"""Bearer-token verification for ``/mcp``, and access to the caller inside a tool.

Two kinds of bearer token are accepted:

* a gateway access token (``fmg_at_…``), issued by the OAuth server;
* a Forgejo access token, when ``ALLOW_FORGEJO_TOKENS`` is on. It is checked
  against Forgejo's ``/user`` and the answer is cached briefly in memory, keyed
  by the token's hash, so a burst of tool calls costs one lookup.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import TYPE_CHECKING

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from pydantic import ConfigDict, Field

from .crypto import fingerprint
from .forgejo import ForgejoClient, ForgejoError, ForgejoUnauthorized
from .oauth import Principal, is_gateway_token

if TYPE_CHECKING:
    from .oauth import OAuthServer

log = logging.getLogger(__name__)

FORGEJO_TOKEN_CLIENT_ID = "forgejo-token"  # noqa: S105 - a public prefix/label, not a secret
_CACHE_ENTRIES = 4096


class GatewayAccessToken(AccessToken):
    """The SDK's verified token, carrying who it acts as. Never serialised to clients."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    principal: Principal = Field(exclude=True, repr=False)


class _TTLCache:
    """A small LRU of verified Forgejo tokens. Holds hashes as keys, never the tokens."""

    def __init__(self, ttl_seconds: float, max_entries: int) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._entries: OrderedDict[str, tuple[float, Principal]] = OrderedDict()

    def get(self, key: str) -> Principal | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry[0] <= time.monotonic():
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return entry[1]

    def put(self, key: str, principal: Principal) -> None:
        if self._ttl <= 0:
            return
        self._entries[key] = (time.monotonic() + self._ttl, principal)
        self._entries.move_to_end(key)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def discard(self, key: str) -> None:
        self._entries.pop(key, None)


class GatewayTokenVerifier:
    """Implements the MCP SDK's ``TokenVerifier`` protocol."""

    def __init__(
        self,
        *,
        forgejo: ForgejoClient,
        oauth: OAuthServer | None,
        allow_forgejo_tokens: bool,
        cache_seconds: float,
    ) -> None:
        self._forgejo = forgejo
        self._oauth = oauth
        self._allow_forgejo_tokens = allow_forgejo_tokens
        self._cache = _TTLCache(cache_seconds, _CACHE_ENTRIES)
        self._inflight: dict[str, asyncio.Future[Principal | None]] = {}

    async def verify_token(self, token: str) -> AccessToken | None:
        principal = await self.principal_for(token)
        if principal is None:
            return None
        return GatewayAccessToken(
            token=token,
            client_id=principal.client_id,
            scopes=[],
            expires_at=principal.expires_at,
            resource=self._oauth.resource if self._oauth else None,
            subject=str(principal.forgejo_user_id),
            principal=principal,
        )

    async def principal_for(self, token: str) -> Principal | None:
        if is_gateway_token(token):
            return await self._oauth.principal_for_access_token(token) if self._oauth else None
        if not self._allow_forgejo_tokens or not token or len(token) > 512:
            return None
        key = fingerprint(token)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        # Collapse concurrent first-use lookups of one token into a single Forgejo call.
        pending = self._inflight.get(key)
        if pending is not None:
            return await pending
        future: asyncio.Future[Principal | None] = asyncio.get_running_loop().create_future()
        self._inflight[key] = future
        try:
            principal = await self._lookup_forgejo_token(token)
        except Exception as exc:
            future.set_exception(exc)
            future.exception()  # mark retrieved; any waiters re-raise it themselves
            raise
        except BaseException:
            future.cancel()
            raise
        else:
            future.set_result(principal)
        finally:
            del self._inflight[key]
        if principal is not None:
            self._cache.put(key, principal)
        return principal

    async def _lookup_forgejo_token(self, token: str) -> Principal | None:
        try:
            user = await self._forgejo.current_user(token)
        except ForgejoUnauthorized:
            return None
        except ForgejoError as exc:
            if exc.status in (403, 404):
                return None
            raise
        return Principal(
            kind="forgejo_token",
            forgejo_user_id=user.id,
            forgejo_login=user.login,
            forgejo_token=token,
            client_id=FORGEJO_TOKEN_CLIENT_ID,
            expires_at=None,
        )

    async def forget(self, principal: Principal) -> None:
        """Forgejo refused the principal's token mid-call: stop accepting it."""
        if principal.kind == "forgejo_token":
            self._cache.discard(fingerprint(principal.forgejo_token))
        elif principal.connection_id is not None and self._oauth is not None:
            await self._oauth.revoke_connection(principal.connection_id, "forgejo_token_refused")


def current_principal() -> Principal:
    """The caller of the current MCP request. Only valid inside a tool call."""
    token = get_access_token()
    if not isinstance(token, GatewayAccessToken):
        raise RuntimeError("no authenticated caller in this context")
    return token.principal

"""The gateway's OAuth authorization server.

A fixed subset of OAuth 2.1: authorization code with PKCE S256, resource
indicators (RFC 8707), ``iss`` on authorization responses (RFC 9207), refresh
with rotation, revocation (RFC 7009) and discovery (RFC 8414; RFC 9728 is served
by the MCP SDK). Clients are a pinned allowlist matched exactly. A hosted
assistant's client id is its Client ID Metadata Document URL, which is never
fetched: there is no registration endpoint and no outbound call. Client
authentication is ``none``.

A **connection** is one person's grant to one client. The person proves who
they are by pasting a Forgejo access token on the consent page; the gateway
checks it against Forgejo, seals it, and from then on acts with it. The token's
own scopes are the only permissions a connection has. Connecting the same
client again replaces the earlier connection.

Access tokens are opaque, one hour, looked up on every call, so revoking takes
effect at once. Refresh tokens are opaque, 30 days, single use; reusing a
refresh token or an authorization code revokes the whole connection. The
consent request is bound to the browser that started it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlencode
from uuid import uuid4

from .config import OAuthClient, Settings
from .crypto import Keyring, new_secret
from .forgejo import ForgejoClient, ForgejoError, ForgejoUnauthorized, ForgejoUser
from .store import ApprovedRequest, Connection, PendingRequest, Store, Transaction

log = logging.getLogger(__name__)

ACCESS_TOKEN_SECONDS = 3600
REFRESH_TOKEN_SECONDS = 30 * 24 * 3600
CONNECTION_SECONDS = 365 * 24 * 3600
REQUEST_SECONDS = 600
CODE_SECONDS = 60

ACCESS_TOKEN_PREFIX = "fmg_at_"  # noqa: S105 - a public prefix/label, not a secret
REFRESH_TOKEN_PREFIX = "fmg_rt_"  # noqa: S105 - a public prefix/label, not a secret

_STATE = re.compile(r"[\x20-\x7e]{0,1024}")
_CHALLENGE = re.compile(r"[A-Za-z0-9\-_]{43}")
_VERIFIER = re.compile(r"[A-Za-z0-9\-._~]{43,128}")
_REQUEST_ID = re.compile(r"[A-Za-z0-9\-_]{20,128}")
# Scopes clients commonly request. Accepted and ignored: what a connection may do
# is set by the Forgejo token behind it, and refresh tokens are always issued.
_IGNORED_SCOPES = frozenset({"offline_access", "mcp"})


class OAuthError(Exception):
    """An RFC 6749 error for the token and revocation endpoints."""

    def __init__(self, error: str, status_code: int = 400, description: str | None = None) -> None:
        super().__init__(error)
        self.error = error
        self.status_code = status_code
        self.description = description


class ConsentGone(Exception):
    """The consent request is unknown, expired, already decided, or from another browser."""


class TokenRejected(Exception):
    """The pasted Forgejo token did not work."""


@dataclass(frozen=True, slots=True)
class AuthorizeOutcome:
    """Either a consent page (with the browser secret to set), or a redirect back to the client."""

    consent_path: str | None = None
    browser_secret: str | None = None
    client_redirect: str | None = None


@dataclass(frozen=True, slots=True)
class ConsentView:
    client_name: str


@dataclass(frozen=True, slots=True)
class Principal:
    """Who a verified bearer token acts as."""

    kind: Literal["connection", "forgejo_token"]
    forgejo_user_id: int
    forgejo_login: str
    forgejo_token: str
    client_id: str
    expires_at: int | None
    connection_id: str | None = None

    def __repr__(self) -> str:  # never print the Forgejo token
        return f"Principal(kind={self.kind!r}, login={self.forgejo_login!r}, connection_id={self.connection_id!r})"


def _now() -> int:
    return int(time.time())


def _one(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name)
    return values[0] if values else None


def pkce_matches(verifier: str, challenge: str) -> bool:
    if not _VERIFIER.fullmatch(verifier):
        return False
    digest = hashlib.sha256(verifier.encode()).digest()
    return hmac.compare_digest(base64.urlsafe_b64encode(digest).rstrip(b"=").decode(), challenge)


def is_gateway_token(token: str) -> bool:
    return token.startswith((ACCESS_TOKEN_PREFIX, REFRESH_TOKEN_PREFIX))


class OAuthServer:
    def __init__(self, settings: Settings, store: Store, keyring: Keyring, forgejo: ForgejoClient) -> None:
        if settings.public_url is None or settings.resource is None:
            raise ValueError("OAuth needs PUBLIC_URL")
        self._settings = settings
        self._store = store
        self._keys = keyring
        self._forgejo = forgejo
        self.issuer: str = settings.public_url
        self.resource: str = settings.resource

    # ── Discovery ─────────────────────────────────────────────────────────────

    def authorization_server_metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/oauth/authorize",
            "token_endpoint": f"{self.issuer}/oauth/token",
            "revocation_endpoint": f"{self.issuer}/oauth/revoke",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": sorted(_IGNORED_SCOPES),
            "client_id_metadata_document_supported": True,
            "authorization_response_iss_parameter_supported": True,
        }

    def client_redirect(self, redirect_uri: str, state: str | None, **params: str) -> str:
        query = {**params, "iss": self.issuer}
        if state is not None:
            query["state"] = state
        separator = "&" if "?" in redirect_uri else "?"
        return f"{redirect_uri}{separator}{urlencode(query)}"

    # ── Authorization request ─────────────────────────────────────────────────

    def validate_client(self, query: dict[str, list[str]]) -> tuple[OAuthClient, str] | None:
        """The client and redirect URI, when both match exactly and no parameter repeats.

        Until this passes, errors must stay on the gateway's page: redirecting
        to an unverified URI would make the endpoint an open redirect.
        """
        if any(len(values) > 1 for values in query.values()):
            return None
        client = self._settings.clients_by_id.get(_one(query, "client_id") or "")
        redirect_uri = _one(query, "redirect_uri")
        if client is None or redirect_uri not in client.redirect_uris:
            return None
        state = _one(query, "state")
        if state is not None and not _STATE.fullmatch(state):
            return None
        return client, redirect_uri

    async def start_authorization(
        self, client: OAuthClient, redirect_uri: str, query: dict[str, list[str]]
    ) -> AuthorizeOutcome:
        state = _one(query, "state")

        def refuse(error: str) -> AuthorizeOutcome:
            return AuthorizeOutcome(client_redirect=self.client_redirect(redirect_uri, state, error=error))

        if _one(query, "response_type") != "code":
            return refuse("unsupported_response_type")
        challenge = _one(query, "code_challenge") or ""
        if _one(query, "code_challenge_method") != "S256" or not _CHALLENGE.fullmatch(challenge):
            return refuse("invalid_request")
        resource = _one(query, "resource")
        if resource is not None and resource.rstrip("/") != self.resource:
            return refuse("invalid_target")
        if not set((_one(query, "scope") or "").split()) <= _IGNORED_SCOPES:
            return refuse("invalid_scope")

        request_id, browser_secret = new_secret(), new_secret()
        now = _now()
        pending = PendingRequest(
            id_hash=self._keys.digest(request_id),
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=challenge,
            resource=self.resource,
            expires_at=now + REQUEST_SECONDS,
        )

        def work(tx: Transaction) -> None:
            tx.sweep_expired(now)
            tx.insert_request(pending, self._keys.digest(browser_secret))

        await self._store.run(work)
        return AuthorizeOutcome(consent_path=f"/oauth/consent/{request_id}", browser_secret=browser_secret)

    # ── Consent ───────────────────────────────────────────────────────────────

    async def _open_request(self, request_id: str, browser_secret: str) -> PendingRequest:
        if not _REQUEST_ID.fullmatch(request_id) or not browser_secret:
            raise ConsentGone
        id_hash, browser_hash, now = self._keys.digest(request_id), self._keys.digest(browser_secret), _now()
        pending = await self._store.run(lambda tx: tx.open_request(id_hash, browser_hash, now))
        if pending is None:
            raise ConsentGone
        return pending

    async def consent_view(self, request_id: str, browser_secret: str) -> ConsentView:
        pending = await self._open_request(request_id, browser_secret)
        return ConsentView(client_name=self._settings.clients_by_id[pending.client_id].name)

    async def deny(self, request_id: str, browser_secret: str) -> str:
        pending = await self._open_request(request_id, browser_secret)
        browser_hash, now = self._keys.digest(browser_secret), _now()

        def work(tx: Transaction) -> bool:
            if tx.open_request(pending.id_hash, browser_hash, now) is None:
                return False
            tx.deny_request(pending.id_hash, now)
            return True

        if not await self._store.run(work):
            raise ConsentGone
        return self.client_redirect(pending.redirect_uri, pending.state, error="access_denied")

    async def approve(self, request_id: str, browser_secret: str, forgejo_token: str) -> tuple[str, ForgejoUser]:
        """Check the pasted token with Forgejo, then issue a code. Returns the client redirect and the user."""
        pending = await self._open_request(request_id, browser_secret)
        token = forgejo_token.strip()
        if not token or len(token) > 512 or any(ch.isspace() for ch in token):
            raise TokenRejected("That doesn't look like a Forgejo access token.")
        try:
            user = await self._forgejo.current_user(token)
        except ForgejoUnauthorized:
            raise TokenRejected("Forgejo didn't accept that token. Check it and try again.") from None
        except ForgejoError as exc:
            if exc.status == 403:
                raise TokenRejected(
                    "That token can't read your account. Give it at least the read:user scope."
                ) from None
            raise

        code = new_secret()
        browser_hash, now = self._keys.digest(browser_secret), _now()
        sealed = self._keys.seal(token, bound_to=pending.id_hash)

        def work(tx: Transaction) -> bool:
            if tx.open_request(pending.id_hash, browser_hash, now) is None:
                return False
            tx.approve_request(
                pending.id_hash,
                code_hash=self._keys.digest(code),
                code_expires_at=now + CODE_SECONDS,
                forgejo_user_id=user.id,
                forgejo_login=user.login,
                sealed_token=sealed,
            )
            return True

        if not await self._store.run(work):
            raise ConsentGone
        log.info("oauth.consent_approved", extra={"client_id": pending.client_id, "forgejo_login": user.login})
        return self.client_redirect(pending.redirect_uri, pending.state, code=code), user

    # ── Token endpoint ────────────────────────────────────────────────────────

    async def exchange(self, form: dict[str, str]) -> dict[str, Any]:
        client_id = form.get("client_id", "")
        if client_id not in self._settings.clients_by_id:
            raise OAuthError("invalid_client", 401)
        grant_type = form.get("grant_type")
        if grant_type == "authorization_code":
            return await self._exchange_code(client_id, form)
        if grant_type == "refresh_token":
            return await self._refresh(client_id, form)
        raise OAuthError("unsupported_grant_type")

    async def _exchange_code(self, client_id: str, form: dict[str, str]) -> dict[str, Any]:
        code_hash, now = self._keys.digest(form.get("code", "")), _now()
        access, refresh = new_secret(ACCESS_TOKEN_PREFIX), new_secret(REFRESH_TOKEN_PREFIX)

        def valid(row: ApprovedRequest) -> bool:
            requested_resource = form.get("resource")
            return (
                row.code_expires_at > now
                and row.client_id == client_id
                and row.redirect_uri == form.get("redirect_uri")
                and (requested_resource is None or requested_resource.rstrip("/") == row.resource)
                and pkce_matches(form.get("code_verifier", ""), row.code_challenge)
            )

        def work(tx: Transaction) -> Literal["ok", "invalid", "replayed"]:
            row = tx.request_by_code(code_hash)
            if row is None:
                return "invalid"
            if row.consumed_at is not None:
                # A code seen twice may have been stolen: what it issued can't be trusted.
                if row.connection_id is not None:
                    tx.revoke_connection(row.connection_id, now, "code_replayed")
                return "replayed"
            if not valid(row):
                return "invalid"
            token = self._keys.open(row.sealed_token, bound_to=row.id_hash)
            connection_id = str(uuid4())
            for old in tx.active_connection_ids(row.forgejo_user_id, client_id):
                tx.revoke_connection(old, now, "reconnected")
            tx.insert_connection(
                Connection(
                    id=connection_id,
                    client_id=client_id,
                    forgejo_user_id=row.forgejo_user_id,
                    forgejo_login=row.forgejo_login,
                    sealed_token=self._keys.seal(token, bound_to=connection_id),
                    expires_at=now + CONNECTION_SECONDS,
                    revoked_at=None,
                ),
                now,
            )
            tx.consume_request(row.id_hash, now, connection_id)
            self._issue(tx, connection_id, access, refresh, now)
            log.info(
                "oauth.connection_created",
                extra={"connection_id": connection_id, "client_id": client_id, "forgejo_login": row.forgejo_login},
            )
            return "ok"

        outcome = await self._store.run(work)
        if outcome == "replayed":
            log.warning("oauth.code_replayed")
        if outcome != "ok":
            raise OAuthError("invalid_grant")
        return self._token_body(access, refresh)

    async def _refresh(self, client_id: str, form: dict[str, str]) -> dict[str, Any]:
        token_hash, now = self._keys.digest(form.get("refresh_token", "")), _now()
        access, refresh = new_secret(ACCESS_TOKEN_PREFIX), new_secret(REFRESH_TOKEN_PREFIX)
        requested_resource = form.get("resource")

        def work(tx: Transaction) -> Literal["ok", "invalid", "reused"]:
            record = tx.refresh_record(token_hash)
            if record is None:
                return "invalid"
            connection = record.connection
            if record.consumed_at is not None:
                tx.revoke_connection(connection.id, now, "refresh_reused")
                return "reused"
            if (
                record.expires_at <= now
                or connection.revoked_at is not None
                or connection.expires_at <= now
                or connection.client_id != client_id
                or (requested_resource is not None and requested_resource.rstrip("/") != self.resource)
            ):
                return "invalid"
            tx.consume_refresh_token(token_hash, now)
            self._issue(tx, connection.id, access, refresh, now)
            return "ok"

        outcome = await self._store.run(work)
        if outcome == "reused":
            log.warning("oauth.refresh_reused")
        if outcome != "ok":
            raise OAuthError("invalid_grant")
        return self._token_body(access, refresh)

    def _issue(self, tx: Transaction, connection_id: str, access: str, refresh: str, now: int) -> None:
        tx.sweep_expired(now)
        tx.insert_access_token(self._keys.digest(access), connection_id, now + ACCESS_TOKEN_SECONDS)
        tx.insert_refresh_token(self._keys.digest(refresh), connection_id, now + REFRESH_TOKEN_SECONDS)

    @staticmethod
    def _token_body(access: str, refresh: str) -> dict[str, Any]:
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_SECONDS,
            "refresh_token": refresh,
        }

    async def revoke(self, form: dict[str, str]) -> None:
        """RFC 7009: disconnect the connection a token belongs to. Unknown tokens are not an error."""
        if form.get("client_id", "") not in self._settings.clients_by_id:
            raise OAuthError("invalid_client", 401)
        token = form.get("token", "")
        if not token:
            raise OAuthError("invalid_request")
        token_hash, now = self._keys.digest(token), _now()

        def work(tx: Transaction) -> None:
            connection_id = tx.connection_id_for_token(token_hash)
            if connection_id is not None:
                tx.revoke_connection(connection_id, now, "client_revoked")

        await self._store.run(work)

    # ── Resource server side ──────────────────────────────────────────────────

    async def principal_for_access_token(self, token: str) -> Principal | None:
        if not token.startswith(ACCESS_TOKEN_PREFIX):
            return None
        token_hash, now = self._keys.digest(token), _now()
        found = await self._store.run(lambda tx: tx.connection_for_access_token(token_hash, now))
        if found is None:
            return None
        connection, expires_at = found
        return Principal(
            kind="connection",
            forgejo_user_id=connection.forgejo_user_id,
            forgejo_login=connection.forgejo_login,
            forgejo_token=self._keys.open(connection.sealed_token, bound_to=connection.id),
            client_id=connection.client_id,
            expires_at=expires_at,
            connection_id=connection.id,
        )

    async def revoke_connection(self, connection_id: str, reason: str) -> None:
        now = _now()
        if await self._store.run(lambda tx: tx.revoke_connection(connection_id, now, reason)):
            log.warning("oauth.connection_revoked", extra={"connection_id": connection_id, "reason": reason})

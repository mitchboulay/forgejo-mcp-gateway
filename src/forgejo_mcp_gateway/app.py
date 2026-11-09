"""Assemble the ASGI application."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import __version__
from .auth import GatewayTokenVerifier
from .config import Settings
from .crypto import Keyring, decode_secret_key
from .forgejo import ForgejoClient
from .oauth import OAuthServer
from .ratelimit import McpRateLimitMiddleware, RateLimiter
from .store import Store
from .tools import register_tools
from .web import Routes

log = logging.getLogger(__name__)

INSTRUCTIONS = """\
Tools for a Forgejo server, acting as the connected Forgejo user with that user's permissions.
Start with get_me to see who you are, then search_repositories or list_owner_repositories.
Read files with get_file; to change one, pass the sha get_file returned to write_file.
Prefer opening a branch and a pull request over committing to the default branch.
List tools are paginated: follow has_more with the next page."""


def create_app(settings: Settings) -> Starlette:
    store = Store(settings.database_path)
    store.open()
    forgejo = ForgejoClient(
        settings.forgejo_url,
        timeout_seconds=settings.forgejo_timeout_seconds,
        max_attempts=settings.forgejo_max_attempts,
    )

    oauth: OAuthServer | None = None
    if settings.oauth_enabled:
        assert settings.secret_key is not None
        keyring = Keyring(decode_secret_key(settings.secret_key.get_secret_value()))
        oauth = OAuthServer(settings, store, keyring, forgejo)

    verifier = GatewayTokenVerifier(
        forgejo=forgejo,
        oauth=oauth,
        allow_forgejo_tokens=settings.allow_forgejo_tokens,
        cache_seconds=settings.token_cache_seconds,
    )
    auth = AuthSettings(
        issuer_url=settings.public_url or settings.forgejo_browser_url,  # type: ignore[arg-type]
        resource_server_url=settings.resource,  # type: ignore[arg-type]
        validate_token_resource=oauth is not None,
    )
    server: MCPServer = MCPServer(
        name="forgejo",
        title="Forgejo",
        instructions=INSTRUCTIONS,
        version=__version__,
        website_url=settings.forgejo_browser_url,
        token_verifier=verifier,
        auth=auth,
    )
    register_tools(server, forgejo, verifier)

    for route in Routes(settings, store, oauth).routes():
        server.custom_route(route.path, methods=sorted(route.methods or {"GET"}), include_in_schema=False)(
            route.endpoint
        )

    if oauth is not None:
        protected_resource = {
            "resource": oauth.resource,
            "authorization_servers": [oauth.issuer],
            "bearer_methods_supported": ["header"],
            "resource_name": "Forgejo",
        }

        async def root_protected_resource(request: Request) -> Response:
            # Some clients look at the root form before the path-suffixed one the SDK serves.
            return JSONResponse(protected_resource)

        server.custom_route("/.well-known/oauth-protected-resource", methods=["GET"], include_in_schema=False)(
            root_protected_resource
        )

    app = server.streamable_http_app(
        streamable_http_path=settings.mcp_path,
        stateless_http=True,
        json_response=True,
        host=settings.host,
    )
    app.add_middleware(
        McpRateLimitMiddleware,
        mcp_path=settings.mcp_path,
        per_token=RateLimiter(settings.rate_limit_per_minute, settings.rate_limit_burst),
        per_address=RateLimiter(settings.rate_limit_per_minute * 4, settings.rate_limit_burst * 4),
        trusted_ip_header=settings.trusted_client_ip_header,
    )

    inner_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(asgi_app: Starlette) -> AsyncIterator[None]:
        try:
            async with inner_lifespan(asgi_app):
                log.info(
                    "gateway.started",
                    extra={
                        "version": __version__,
                        "forgejo_url": settings.forgejo_url,
                        "oauth": oauth is not None,
                        "forgejo_tokens": settings.allow_forgejo_tokens,
                    },
                )
                yield
        finally:
            await forgejo.aclose()
            store.close()

    app.router.lifespan_context = lifespan
    return app

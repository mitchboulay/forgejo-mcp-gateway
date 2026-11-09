"""HTTP routes for the OAuth authorization server, the consent page and health.

``/mcp`` and the protected-resource metadata are served by the MCP SDK; these
are the routes it doesn't provide.
"""

from __future__ import annotations

import html
import logging
from importlib.resources import files
from string import Template
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlsplit

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .config import Settings
from .forgejo import ForgejoError
from .oauth import REQUEST_SECONDS, ConsentGone, OAuthError, OAuthServer, TokenRejected
from .ratelimit import RateLimiter, client_address
from .store import Store

log = logging.getLogger(__name__)

BROWSER_COOKIE = "__Host-fmg_oauth"
MAX_FORM_BYTES = 16 * 1024
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_TEMPLATES = files("forgejo_mcp_gateway") / "templates"
_PAGE = Template((_TEMPLATES / "page.html").read_text(encoding="utf-8"))
_CONSENT = Template((_TEMPLATES / "consent.html").read_text(encoding="utf-8"))


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


class Routes:
    def __init__(self, settings: Settings, store: Store, oauth: OAuthServer | None) -> None:
        self._settings = settings
        self._store = store
        self._oauth = oauth
        # Browser pages and the token endpoint are limited separately: the token endpoint is
        # called by the client's servers, the pages by the person's browser.
        per_minute = settings.oauth_rate_limit_per_minute
        self._page_limiter = RateLimiter(per_minute, per_minute)
        self._token_limiter = RateLimiter(per_minute, per_minute)
        redirect_origins = sorted({_origin(uri) for c in settings.oauth_clients for uri in c.redirect_uris})
        # form-action also governs where a form's response may redirect, so the
        # clients' redirect origins must be allowed for the post-consent redirect.
        self._html_headers = {
            **_NO_STORE,
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
            f"form-action 'self' {' '.join(redirect_origins)}; frame-ancestors 'none'; base-uri 'none'",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }

    def routes(self) -> list[Route]:
        routes = [Route("/healthz", self.health, methods=["GET"])]
        if self._oauth is not None:
            routes += [
                Route("/.well-known/oauth-authorization-server", self.authorization_server_metadata, methods=["GET"]),
                Route(
                    "/.well-known/oauth-authorization-server/mcp", self.authorization_server_metadata, methods=["GET"]
                ),
                Route("/oauth/authorize", self.authorize, methods=["GET"]),
                Route("/oauth/consent/{request_id}", self.consent, methods=["GET", "POST"]),
                Route("/oauth/token", self.token, methods=["POST"]),
                Route("/oauth/revoke", self.revoke, methods=["POST"]),
            ]
        return routes

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _limited(self, request: Request, limiter: RateLimiter) -> Response | None:
        allowed, retry_after = limiter.allow(client_address(request.scope, self._settings.trusted_client_ip_header))
        if allowed:
            return None
        return JSONResponse(
            {"error": "rate_limited"}, 429, headers={**_NO_STORE, "Retry-After": str(max(1, round(retry_after)))}
        )

    def _page(self, title: str, body: str, status_code: int = 200) -> HTMLResponse:
        document = _PAGE.substitute(title=html.escape(title), body=body)
        return HTMLResponse(document, status_code, headers=self._html_headers)

    def _message(self, title: str, text: str, status_code: int) -> HTMLResponse:
        return self._page(title, f"<h1>{html.escape(title)}</h1><p>{html.escape(text)}</p>", status_code)

    def _expired(self) -> HTMLResponse:
        return self._message("This request has expired", "Go back to your assistant and connect again.", 404)

    def _consent_form(self, request_id: str, client_name: str, error: str | None = None) -> HTMLResponse:
        body = _CONSENT.substitute(
            client=html.escape(client_name),
            forgejo=html.escape(self._settings.forgejo_browser_url),
            request_id=html.escape(request_id),
            error=f'<p class="error" role="alert">{html.escape(error)}</p>' if error else "",
        )
        return self._page(f"Connect {client_name} to Forgejo", body, 400 if error else 200)

    async def _read_form(self, request: Request) -> dict[str, str]:
        """The urlencoded body. A repeated parameter is refused."""
        if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            raise OAuthError("invalid_request")
        body = await request.body()
        if len(body) > MAX_FORM_BYTES:
            raise OAuthError("invalid_request")
        try:
            pairs = parse_qsl(body.decode("utf-8", "strict"), keep_blank_values=True)
        except UnicodeDecodeError:
            raise OAuthError("invalid_request") from None
        form = dict(pairs)
        if len(form) != len(pairs):
            raise OAuthError("invalid_request")
        return form

    @staticmethod
    def _oauth_error(exc: OAuthError) -> JSONResponse:
        body: dict[str, Any] = {"error": exc.error}
        if exc.description:
            body["error_description"] = exc.description
        return JSONResponse(body, exc.status_code, headers=_NO_STORE)

    # ── Endpoints ─────────────────────────────────────────────────────────────

    async def health(self, request: Request) -> Response:
        try:
            self._store.ping()
        except Exception:
            log.exception("health.store_failed")
            return JSONResponse({"status": "error", "store": "unavailable"}, 503, headers=_NO_STORE)
        return JSONResponse({"status": "ok", "oauth": self._oauth is not None}, headers=_NO_STORE)

    async def authorization_server_metadata(self, request: Request) -> Response:
        assert self._oauth is not None
        return JSONResponse(self._oauth.authorization_server_metadata())

    async def authorize(self, request: Request) -> Response:
        assert self._oauth is not None
        if (limited := self._limited(request, self._page_limiter)) is not None:
            return limited
        query = parse_qs(request.url.query, keep_blank_values=True)
        validated = self._oauth.validate_client(query)
        if validated is None:
            return self._message("This connection request isn't valid", "Go back to your assistant and try again.", 400)
        client, redirect_uri = validated
        outcome = await self._oauth.start_authorization(client, redirect_uri, query)
        if outcome.client_redirect is not None:
            return RedirectResponse(outcome.client_redirect, 303)
        response = RedirectResponse(outcome.consent_path or "/", 303, headers=_NO_STORE)
        response.set_cookie(
            BROWSER_COOKIE,
            outcome.browser_secret or "",
            max_age=REQUEST_SECONDS,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response

    async def consent(self, request: Request) -> Response:
        assert self._oauth is not None
        if (limited := self._limited(request, self._page_limiter)) is not None:
            return limited
        request_id = request.path_params["request_id"]
        browser_secret = request.cookies.get(BROWSER_COOKIE, "")

        if request.method == "GET":
            try:
                view = await self._oauth.consent_view(request_id, browser_secret)
            except ConsentGone:
                return self._expired()
            return self._consent_form(request_id, view.client_name)

        origin = request.headers.get("origin")
        if origin is not None and origin != self._oauth.issuer:
            return self._message("This request can't be accepted", "Open the connect page again.", 403)
        try:
            form = await self._read_form(request)
        except OAuthError:
            return self._message("This request can't be accepted", "Open the connect page again.", 400)

        try:
            view = await self._oauth.consent_view(request_id, browser_secret)
            if form.get("decision") != "allow":
                redirect = await self._oauth.deny(request_id, browser_secret)
            else:
                redirect, _user = await self._oauth.approve(request_id, browser_secret, form.get("token", ""))
        except ConsentGone:
            return self._expired()
        except TokenRejected as exc:
            return self._consent_form(request_id, view.client_name, str(exc))
        except ForgejoError:
            log.exception("oauth.consent_forgejo_unavailable")
            return self._consent_form(
                request_id, view.client_name, "Forgejo couldn't be reached to check the token. Try again shortly."
            )
        response = RedirectResponse(redirect, 303, headers=_NO_STORE)
        response.delete_cookie(BROWSER_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        return response

    async def token(self, request: Request) -> Response:
        assert self._oauth is not None
        if (limited := self._limited(request, self._token_limiter)) is not None:
            return limited
        try:
            form = await self._read_form(request)
            body = await self._oauth.exchange(form)
        except OAuthError as exc:
            return self._oauth_error(exc)
        return JSONResponse(body, headers=_NO_STORE)

    async def revoke(self, request: Request) -> Response:
        assert self._oauth is not None
        if (limited := self._limited(request, self._token_limiter)) is not None:
            return limited
        try:
            form = await self._read_form(request)
            await self._oauth.revoke(form)
        except OAuthError as exc:
            return self._oauth_error(exc)
        return Response(status_code=200, headers=_NO_STORE)

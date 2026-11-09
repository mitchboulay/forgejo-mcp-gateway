"""Offline fixtures: the real app in-process, with only Forgejo's HTTP API faked.

These tests cover the OAuth protocol's refusal paths and the settings and
crypto contracts. Everything that needs Forgejo's real behaviour is in
``tests/live``.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
import respx

from forgejo_mcp_gateway.app import create_app
from forgejo_mcp_gateway.config import Settings

FORGEJO = "http://forgejo.test"
GATEWAY = "https://gateway.test"
CHATGPT = "https://chatgpt.com/oauth/client.json"
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
GOOD_TOKEN = "a" * 40
COOKIE = "__Host-fmg_oauth"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        forgejo_url=FORGEJO,
        public_url=GATEWAY,
        secret_key=secrets.token_hex(32),
        database_path=tmp_path / "gateway.sqlite3",
        oauth_rate_limit_per_minute=1000,
    )


@pytest.fixture
def forgejo() -> respx.MockRouter:
    with respx.mock(base_url=f"{FORGEJO}/api/v1", assert_all_called=False) as router:

        def user(request: httpx.Request) -> httpx.Response:
            if request.headers.get("authorization") == f"token {GOOD_TOKEN}":
                return httpx.Response(200, json={"id": 7, "login": "alice", "full_name": "Alice", "is_admin": False})
            return httpx.Response(401, json={"message": "token is required"})

        router.get("/user").mock(side_effect=user)
        yield router


@pytest.fixture
async def client(settings: Settings, forgejo: respx.MockRouter) -> AsyncIterator[httpx.AsyncClient]:
    # The lifespan is not entered: these tests stop at the OAuth routes and the bearer check,
    # in front of the MCP session manager, and anyio cancel scopes cannot span fixture tasks.
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=GATEWAY) as http:
        yield http


class Flow:
    """Drives the browser and token-endpoint halves the way ChatGPT does."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self.http = http

    async def authorize(self, **overrides: str) -> httpx.Response:
        verifier, challenge = pkce()
        self.verifier = verifier
        query = {
            "response_type": "code",
            "client_id": CHATGPT,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": f"{GATEWAY}/mcp",
            "state": "xyz",
            **overrides,
        }
        return await self.http.get(f"/oauth/authorize?{urlencode(query)}")

    async def consent(self, token: str = GOOD_TOKEN, decision: str = "allow") -> httpx.Response:
        started = await self.authorize()
        assert started.status_code == 303
        self.consent_path = started.headers["location"]
        self.cookie = started.cookies[COOKIE]
        return await self.http.post(
            self.consent_path,
            data={"decision": decision, "token": token},
            headers={"Cookie": f"{COOKIE}={self.cookie}", "Origin": GATEWAY},
        )

    async def code(self) -> str:
        approved = await self.consent()
        assert approved.status_code == 303, approved.text
        return parse_qs(urlsplit(approved.headers["location"]).query)["code"][0]

    async def exchange(self, code: str, /, **overrides: str) -> httpx.Response:
        form = {
            "grant_type": "authorization_code",
            "client_id": CHATGPT,
            "redirect_uri": REDIRECT,
            "code": code,
            "code_verifier": self.verifier,
            **overrides,
        }
        return await self.http.post("/oauth/token", data=form)


@pytest.fixture
def flow(client: httpx.AsyncClient) -> Flow:
    return Flow(client)

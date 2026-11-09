"""The ChatGPT connection flow, end to end, against a real Forgejo.

Plays ChatGPT's part exactly: discovery, an authorization request with PKCE,
the consent page in a browser (cookie and form post), the code exchange, MCP
calls with the access token, refresh with rotation, reuse detection, and
revocation.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2
import pytest

from .conftest import LiveTarget, mcp_session

pytestmark = pytest.mark.live

CHATGPT_CLIENT_ID = "https://chatgpt.com/oauth/client.json"
CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
COOKIE = "__Host-fmg_oauth"


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


async def _discover(http: httpx2.AsyncClient, gateway: str) -> tuple[dict[str, object], dict[str, object]]:
    challenge = await http.post(f"{gateway}/mcp", json={})
    assert challenge.status_code == 401
    match = re.search(r'resource_metadata="([^"]+)"', challenge.headers.get("www-authenticate", ""))
    if match is None:
        pytest.skip("the gateway has OAuth off")
    resource = (await http.get(match.group(1))).json()
    issuer = resource["authorization_servers"][0]
    server = (await http.get(f"{issuer}/.well-known/oauth-authorization-server")).json()
    return resource, server


async def _connect(http: httpx2.AsyncClient, live: LiveTarget, *, forgejo_token: str) -> tuple[httpx2.Response, str]:
    """Run the browser half. Returns the final response from the consent post and the PKCE verifier."""
    resource, server = await _discover(http, live.gateway_url)
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(16)
    query = {
        "response_type": "code",
        "client_id": CHATGPT_CLIENT_ID,
        "redirect_uri": CHATGPT_REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": resource["resource"],
        "scope": "offline_access",
        "state": state,
    }
    started = await http.get(f"{server['authorization_endpoint']}?{urlencode(query)}")
    assert started.status_code == 303, started.text
    consent_url = started.headers["location"]
    if consent_url.startswith("/"):
        consent_url = f"{live.gateway_url}{consent_url}"
    cookie = started.cookies.get(COOKIE)
    assert cookie, "authorize must bind the request to the browser"
    headers = {"Cookie": f"{COOKIE}={cookie}"}

    page = await http.get(consent_url, headers=headers)
    assert page.status_code == 200
    assert "Connect ChatGPT to Forgejo" in page.text
    assert (await http.get(consent_url)).status_code == 404, "another browser must not see the request"

    posted = await http.post(
        consent_url,
        headers={**headers, "Origin": str(server["issuer"])},
        data={"decision": "allow", "token": forgejo_token},
    )
    if posted.status_code == 303:
        redirect = urlsplit(posted.headers["location"])
        params = parse_qs(redirect.query)
        assert f"{redirect.scheme}://{redirect.netloc}{redirect.path}" == CHATGPT_REDIRECT
        assert params["state"] == [state]
        assert params["iss"] == [server["issuer"]]
    return posted, verifier


async def test_chatgpt_connects_calls_refreshes_and_revokes(live: LiveTarget) -> None:
    async with httpx2.AsyncClient(timeout=60, follow_redirects=False) as http:
        _, server = await _discover(http, live.gateway_url)
        token_url = str(server["token_endpoint"])

        posted, verifier = await _connect(http, live, forgejo_token=live.token)
        assert posted.status_code == 303, posted.text
        code = parse_qs(urlsplit(posted.headers["location"]).query)["code"][0]

        exchange = {
            "grant_type": "authorization_code",
            "client_id": CHATGPT_CLIENT_ID,
            "redirect_uri": CHATGPT_REDIRECT,
            "code": code,
            "code_verifier": verifier,
        }
        issued = await http.post(token_url, data=exchange)
        assert issued.status_code == 200, issued.text
        tokens = issued.json()
        assert tokens["token_type"] == "Bearer"
        assert tokens["access_token"].startswith("fmg_at_")

        async with mcp_session(live.gateway_url, tokens["access_token"]) as session:
            me = await session.call_tool("get_me", {})
            assert not me.is_error
            assert isinstance(me.structured_content, dict)
            assert me.structured_content["login"] == live.owner

        refreshed = await http.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "client_id": CHATGPT_CLIENT_ID,
                "refresh_token": tokens["refresh_token"],
            },
        )
        assert refreshed.status_code == 200, refreshed.text
        rotated = refreshed.json()
        assert rotated["refresh_token"] != tokens["refresh_token"]

        async with mcp_session(live.gateway_url, rotated["access_token"]) as session:
            assert not (await session.call_tool("get_me", {})).is_error

        revoked = await http.post(
            str(server["revocation_endpoint"]),
            data={"client_id": CHATGPT_CLIENT_ID, "token": rotated["refresh_token"]},
        )
        assert revoked.status_code == 200
        after = await http.post(
            f"{live.gateway_url}/mcp",
            json={},
            headers={"Authorization": f"Bearer {rotated['access_token']}"},
        )
        assert after.status_code == 401, "revoking must cut off the connection's access tokens at once"


async def test_code_replay_and_refresh_reuse_revoke_the_connection(live: LiveTarget) -> None:
    async with httpx2.AsyncClient(timeout=60, follow_redirects=False) as http:
        _, server = await _discover(http, live.gateway_url)
        token_url = str(server["token_endpoint"])
        posted, verifier = await _connect(http, live, forgejo_token=live.token)
        code = parse_qs(urlsplit(posted.headers["location"]).query)["code"][0]
        exchange = {
            "grant_type": "authorization_code",
            "client_id": CHATGPT_CLIENT_ID,
            "redirect_uri": CHATGPT_REDIRECT,
            "code": code,
            "code_verifier": verifier,
        }
        first = (await http.post(token_url, data=exchange)).json()
        replay = await http.post(token_url, data=exchange)
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"
        dead = await http.post(
            f"{live.gateway_url}/mcp", json={}, headers={"Authorization": f"Bearer {first['access_token']}"}
        )
        assert dead.status_code == 401, "a replayed code must revoke what it issued"

        posted, verifier = await _connect(http, live, forgejo_token=live.token)
        code = parse_qs(urlsplit(posted.headers["location"]).query)["code"][0]
        second = (await http.post(token_url, data={**exchange, "code": code, "code_verifier": verifier})).json()
        refresh = {
            "grant_type": "refresh_token",
            "client_id": CHATGPT_CLIENT_ID,
            "refresh_token": second["refresh_token"],
        }
        rotated = await http.post(token_url, data=refresh)
        assert rotated.status_code == 200
        reused = await http.post(token_url, data=refresh)
        assert reused.json()["error"] == "invalid_grant"
        newest = await http.post(token_url, data={**refresh, "refresh_token": rotated.json()["refresh_token"]})
        assert newest.status_code == 400, "reusing a refresh token must revoke the whole connection"


async def test_bad_forgejo_token_stays_on_the_consent_page(live: LiveTarget) -> None:
    async with httpx2.AsyncClient(timeout=60, follow_redirects=False) as http:
        posted, _ = await _connect(http, live, forgejo_token="0" * 40)
    assert posted.status_code == 400
    assert "accept that token" in posted.text


async def test_wrong_redirect_uri_is_not_followed(live: LiveTarget) -> None:
    async with httpx2.AsyncClient(timeout=60, follow_redirects=False) as http:
        _, server = await _discover(http, live.gateway_url)
        _, challenge = _pkce()
        query = {
            "response_type": "code",
            "client_id": CHATGPT_CLIENT_ID,
            "redirect_uri": "https://attacker.example/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        response = await http.get(f"{server['authorization_endpoint']}?{urlencode(query)}")
    assert response.status_code == 400
    assert "location" not in response.headers

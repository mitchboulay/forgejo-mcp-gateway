"""The OAuth server's refusal paths. The happy path runs live in tests/live/test_live_oauth.py."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from .conftest import CHATGPT, COOKIE, GATEWAY, GOOD_TOKEN, REDIRECT, Flow


def _redirect_params(response: httpx.Response) -> dict[str, list[str]]:
    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    return parse_qs(location.query)


async def test_metadata_advertises_only_what_is_supported(client: httpx.AsyncClient) -> None:
    metadata = (await client.get("/.well-known/oauth-authorization-server")).json()
    assert metadata["issuer"] == GATEWAY
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert metadata["token_endpoint_auth_methods_supported"] == ["none"]
    assert "registration_endpoint" not in metadata
    resource = (await client.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert resource["resource"] == f"{GATEWAY}/mcp"
    assert (await client.get("/.well-known/oauth-protected-resource")).json()["resource"] == f"{GATEWAY}/mcp"


@pytest.mark.parametrize(
    "overrides",
    [
        {"client_id": "https://evil.example/client.json"},
        {"redirect_uri": "https://evil.example/cb"},
        {"redirect_uri": REDIRECT + "/extra"},
        {"state": "bad\nstate"},
    ],
)
async def test_unverified_client_or_redirect_never_redirects(flow: Flow, overrides: dict[str, str]) -> None:
    response = await flow.authorize(**overrides)
    assert response.status_code == 400
    assert "location" not in response.headers


async def test_repeated_parameter_is_refused_without_redirect(client: httpx.AsyncClient) -> None:
    response = await client.get(
        f"/oauth/authorize?client_id={CHATGPT}&client_id={CHATGPT}&redirect_uri={REDIRECT}&response_type=code"
    )
    assert response.status_code == 400
    assert "location" not in response.headers


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"code_challenge": "short"}, "invalid_request"),
        ({"resource": "https://other.example/mcp"}, "invalid_target"),
        ({"scope": "admin"}, "invalid_scope"),
    ],
)
async def test_bad_request_from_a_verified_client_redirects_with_error(
    flow: Flow, overrides: dict[str, str], error: str
) -> None:
    params = _redirect_params(await flow.authorize(**overrides))
    assert params["error"] == [error]
    assert params["state"] == ["xyz"]
    assert params["iss"] == [GATEWAY]


async def test_consent_is_bound_to_the_browser_that_started_it(flow: Flow) -> None:
    started = await flow.authorize()
    path = started.headers["location"]
    flow.http.cookies.clear()  # another browser: it never received the cookie
    assert (await flow.http.get(path)).status_code == 404
    assert (await flow.http.get(path, headers={"Cookie": f"{COOKIE}=someone-else"})).status_code == 404
    page = await flow.http.get(path, headers={"Cookie": f"{COOKIE}={started.cookies[COOKIE]}"})
    assert page.status_code == 200
    assert page.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["referrer-policy"] == "no-referrer"


async def test_cross_origin_consent_post_is_refused(flow: Flow) -> None:
    started = await flow.authorize()
    response = await flow.http.post(
        started.headers["location"],
        data={"decision": "allow", "token": GOOD_TOKEN},
        headers={"Cookie": f"{COOKIE}={started.cookies[COOKIE]}", "Origin": "https://evil.example"},
    )
    assert response.status_code == 403


async def test_deny_redirects_access_denied_and_closes_the_request(flow: Flow) -> None:
    params = _redirect_params(await flow.consent(decision="deny"))
    assert params["error"] == ["access_denied"]
    again = await flow.http.post(
        flow.consent_path,
        data={"decision": "allow", "token": GOOD_TOKEN},
        headers={"Cookie": f"{COOKIE}={flow.cookie}", "Origin": GATEWAY},
    )
    assert again.status_code == 404


async def test_rejected_token_keeps_the_request_open(flow: Flow) -> None:
    refused = await flow.consent(token="b" * 40)
    assert refused.status_code == 400
    retried = await flow.http.post(
        flow.consent_path,
        data={"decision": "allow", "token": GOOD_TOKEN},
        headers={"Cookie": f"{COOKIE}={flow.cookie}", "Origin": GATEWAY},
    )
    assert retried.status_code == 303


@pytest.mark.parametrize(
    "overrides",
    [
        {"code_verifier": "x" * 64},
        {"redirect_uri": REDIRECT + "?x=1"},
        {"resource": "https://other.example/mcp"},
        {"code": "not-a-code"},
    ],
)
async def test_code_exchange_refusals(flow: Flow, overrides: dict[str, str]) -> None:
    code = await flow.code()
    response = await flow.exchange(code, **overrides)
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}
    assert response.headers["cache-control"] == "no-store"
    assert (await flow.exchange(code)).status_code == 200, "a refused attempt must not burn the code"


async def test_unknown_client_and_grant(flow: Flow) -> None:
    code = await flow.code()
    unknown = await flow.exchange(code, client_id="https://evil.example/client.json")
    assert (unknown.status_code, unknown.json()) == (401, {"error": "invalid_client"})
    grant = await flow.exchange(code, grant_type="password")
    assert grant.json() == {"error": "unsupported_grant_type"}


async def test_token_endpoint_requires_a_form_body(client: httpx.AsyncClient) -> None:
    response = await client.post("/oauth/token", json={"grant_type": "authorization_code"})
    assert response.json() == {"error": "invalid_request"}


async def test_reconnecting_replaces_the_earlier_connection(flow: Flow) -> None:
    first = (await flow.exchange(await flow.code())).json()
    second = (await flow.exchange(await flow.code())).json()
    old = await flow.http.post("/mcp", json={}, headers={"Authorization": f"Bearer {first['access_token']}"})
    assert old.status_code == 401
    refresh = await flow.http.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "client_id": CHATGPT, "refresh_token": first["refresh_token"]},
    )
    assert refresh.json() == {"error": "invalid_grant"}
    assert second["access_token"] != first["access_token"]


async def test_forgejo_tokens_can_be_turned_off(tmp_path, forgejo) -> None:  # type: ignore[no-untyped-def]
    import secrets as _secrets

    from forgejo_mcp_gateway.app import create_app
    from forgejo_mcp_gateway.config import Settings

    from .conftest import FORGEJO

    app = create_app(
        Settings(
            forgejo_url=FORGEJO,
            public_url=GATEWAY,
            secret_key=_secrets.token_hex(32),
            database_path=tmp_path / "db.sqlite3",
            allow_forgejo_tokens=False,
        )
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=GATEWAY) as http:
        response = await http.post("/mcp", json={}, headers={"Authorization": f"Bearer {GOOD_TOKEN}"})
    assert response.status_code == 401

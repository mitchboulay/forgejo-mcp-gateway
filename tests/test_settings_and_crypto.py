"""Settings validation and the crypto contract."""

from __future__ import annotations

import base64
import secrets
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from pydantic import ValidationError

from forgejo_mcp_gateway.config import Settings
from forgejo_mcp_gateway.crypto import InvalidSecretKey, Keyring, decode_secret_key
from forgejo_mcp_gateway.ratelimit import RateLimiter


def test_token_only_mode_needs_no_secret() -> None:
    settings = Settings(forgejo_url="http://forgejo:3000/")
    assert settings.oauth_enabled is False
    assert settings.forgejo_url == "http://forgejo:3000"
    assert settings.resource is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"public_url": "https://gw.example"},  # OAuth half-configured
        {"secret_key": secrets.token_hex(32)},
        {"public_url": "http://gw.example", "secret_key": secrets.token_hex(32)},  # http outside localhost
        {"allow_forgejo_tokens": False},  # nothing could authenticate
        {
            "oauth_clients": '[{"client_id": "a", "name": "A", "redirect_uris": []},'
            ' {"client_id": "a", "name": "B", "redirect_uris": []}]'
        },
    ],
)
def test_invalid_settings_are_refused(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Settings(forgejo_url="http://forgejo:3000", **kwargs)  # type: ignore[arg-type]


def test_oauth_clients_from_json() -> None:
    settings = Settings(
        forgejo_url="http://forgejo:3000",
        oauth_clients='[{"client_id": "https://c.example/client.json", "name": "C", "redirect_uris": ["https://c.example/cb"]}]',
    )
    assert settings.clients_by_id["https://c.example/client.json"].redirect_uris == ("https://c.example/cb",)


def test_secret_key_accepts_hex_and_base64_and_rejects_short() -> None:
    raw = secrets.token_bytes(32)
    assert decode_secret_key(raw.hex()) == raw
    assert decode_secret_key(base64.b64encode(raw).decode()) == raw
    assert decode_secret_key(base64.urlsafe_b64encode(raw).decode().rstrip("=")) == raw
    with pytest.raises(InvalidSecretKey):
        decode_secret_key(secrets.token_hex(16))


def test_sealed_values_are_bound_to_their_row_and_key() -> None:
    keys = Keyring(secrets.token_bytes(32))
    sealed = keys.seal("forgejo-token", bound_to="row-1")
    assert keys.open(sealed, bound_to="row-1") == "forgejo-token"
    assert b"forgejo-token" not in sealed
    with pytest.raises(InvalidTag):
        keys.open(sealed, bound_to="row-2")
    with pytest.raises(InvalidTag):
        Keyring(secrets.token_bytes(32)).open(sealed, bound_to="row-1")


def test_digest_is_keyed() -> None:
    master = secrets.token_bytes(32)
    assert Keyring(master).digest("x") == Keyring(master).digest("x")
    assert Keyring(master).digest("x") != Keyring(secrets.token_bytes(32)).digest("x")


def test_rate_limiter_allows_burst_then_refuses() -> None:
    limiter = RateLimiter(per_minute=60, burst=3)
    assert [limiter.allow("k")[0] for _ in range(4)] == [True, True, True, False]
    allowed, retry_after = limiter.allow("k")
    assert not allowed
    assert 0 < retry_after <= 1
    assert limiter.allow("other")[0]


def test_database_path_parent_is_created(tmp_path: Path) -> None:
    from forgejo_mcp_gateway.store import Store

    store = Store(tmp_path / "nested" / "dir" / "db.sqlite3")
    store.open()
    store.ping()
    store.close()
    assert (tmp_path / "nested" / "dir" / "db.sqlite3").exists()

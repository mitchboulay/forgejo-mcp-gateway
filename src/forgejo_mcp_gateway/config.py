"""Settings, read once from the environment at startup.

Two modes, chosen by configuration:

* Token mode (always on unless ``ALLOW_FORGEJO_TOKENS=false``): a client sends a
  Forgejo access token as its bearer token and the gateway acts with it.
* OAuth mode (on when ``PUBLIC_URL`` and ``SECRET_KEY`` are both set): hosted
  assistants such as ChatGPT connect through the gateway's own authorization
  server. The person connecting pastes a Forgejo access token on the consent
  page; the gateway stores it encrypted and acts with it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


@dataclass(frozen=True, slots=True)
class OAuthClient:
    """An OAuth client the gateway accepts. Matched exactly; never fetched or registered."""

    client_id: str
    name: str
    redirect_uris: tuple[str, ...]


CHATGPT = OAuthClient(
    client_id="https://chatgpt.com/oauth/client.json",
    name="ChatGPT",
    redirect_uris=("https://chatgpt.com/connector_platform_oauth_redirect",),
)

DEFAULT_CLIENTS: tuple[OAuthClient, ...] = (CHATGPT,)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", frozen=True)

    forgejo_url: str = Field(
        description="Base URL the gateway uses to reach Forgejo, e.g. http://forgejo:3000.",
    )
    forgejo_public_url: str | None = Field(
        default=None,
        description="Forgejo URL people open in a browser (for links on the consent page). Defaults to FORGEJO_URL.",
    )
    public_url: str | None = Field(
        default=None,
        description="Public HTTPS URL of this gateway. Required for OAuth; it is the issuer.",
    )
    secret_key: SecretStr | None = Field(
        default=None,
        description="At least 32 random bytes, base64 or hex. Encrypts stored Forgejo tokens "
        "and keys every stored hash. Required for OAuth.",
    )
    allow_forgejo_tokens: bool = Field(
        default=True,
        description="Accept a Forgejo access token directly as the bearer token.",
    )
    oauth_clients: Annotated[tuple[OAuthClient, ...], NoDecode] = Field(
        default=DEFAULT_CLIENTS,
        description="JSON list of {client_id, name, redirect_uris}. Defaults to ChatGPT.",
    )
    database_path: Path = Field(default=Path("data/gateway.sqlite3"))
    host: str = "0.0.0.0"  # noqa: S104 - the gateway runs in a container behind a proxy
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    trusted_client_ip_header: str | None = Field(
        default=None,
        description="Header a trusted proxy sets to the caller's address, e.g. CF-Connecting-IP. "
        "Unset means the TCP peer is the caller.",
    )

    forgejo_timeout_seconds: float = Field(default=20.0, gt=0, le=300)
    forgejo_max_attempts: int = Field(default=3, ge=1, le=10)
    token_cache_seconds: float = Field(default=60.0, ge=0, le=3600)

    rate_limit_per_minute: int = Field(default=120, ge=1)
    rate_limit_burst: int = Field(default=60, ge=1)
    oauth_rate_limit_per_minute: int = Field(default=30, ge=1)

    @field_validator("forgejo_url", "forgejo_public_url", "public_url")
    @classmethod
    def _http_url(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.query or parts.fragment:
            raise ValueError("must be an http(s) URL with no query or fragment")
        return value.rstrip("/")

    @field_validator("oauth_clients", mode="before")
    @classmethod
    def _parse_clients(cls, value: object) -> object:
        if isinstance(value, str):
            raw = json.loads(value)
            if not isinstance(raw, list) or not raw:
                raise ValueError("OAUTH_CLIENTS must be a non-empty JSON list")
            return tuple(
                OAuthClient(
                    client_id=str(entry["client_id"]),
                    name=str(entry["name"]),
                    redirect_uris=tuple(str(uri) for uri in entry["redirect_uris"]),
                )
                for entry in raw
            )
        return value

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if self.public_url is not None and not self.public_url.startswith("https://"):
            host = urlsplit(self.public_url).hostname
            if host not in ("localhost", "127.0.0.1", "::1"):
                raise ValueError("PUBLIC_URL must use https outside localhost")
        if (self.public_url is None) != (self.secret_key is None):
            raise ValueError("set PUBLIC_URL and SECRET_KEY together to turn OAuth on, or neither")
        if self.public_url is None and not self.allow_forgejo_tokens:
            raise ValueError("nothing can authenticate: turn on OAuth or ALLOW_FORGEJO_TOKENS")
        ids = [client.client_id for client in self.oauth_clients]
        if len(set(ids)) != len(ids):
            raise ValueError("OAUTH_CLIENTS has duplicate client_id values")
        return self

    @property
    def oauth_enabled(self) -> bool:
        return self.public_url is not None and self.secret_key is not None

    @property
    def forgejo_browser_url(self) -> str:
        return self.forgejo_public_url or self.forgejo_url

    @property
    def mcp_path(self) -> str:
        return "/mcp"

    @property
    def resource(self) -> str | None:
        """The RFC 8707 resource identifier: the public MCP endpoint."""
        return f"{self.public_url}{self.mcp_path}" if self.public_url else None

    @property
    def clients_by_id(self) -> dict[str, OAuthClient]:
        return {client.client_id: client for client in self.oauth_clients}

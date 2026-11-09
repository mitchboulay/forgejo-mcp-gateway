"""Live tests: a running gateway in front of a real Forgejo.

    GATEWAY_URL=https://mcp.example.com \
    FORGEJO_TEST_TOKEN=... FORGEJO_TEST_REPO=someone/sandbox \
    uv run pytest -m live

The token's user must own FORGEJO_TEST_REPO, a scratch repository the suite
writes to (branches, files, issues, pull requests, merges) and never cleans up
beyond merging what it opens. The OAuth tests run when the gateway has OAuth on
and accepts ChatGPT as a client; they call the consent page and the token
endpoint exactly as ChatGPT does.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx2
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


class Secret(str):
    """A string that never shows itself in a traceback or assertion message."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "'***'"


@dataclass(frozen=True)
class LiveTarget:
    gateway_url: str
    token: str = field(repr=False)
    owner: str
    repo: str


@pytest.fixture(scope="session")
def live() -> LiveTarget:
    missing = [k for k in ("GATEWAY_URL", "FORGEJO_TEST_TOKEN", "FORGEJO_TEST_REPO") if not os.environ.get(k)]
    if missing:
        pytest.skip(f"live tests need {', '.join(missing)}")
    owner, _, repo = os.environ["FORGEJO_TEST_REPO"].partition("/")
    return LiveTarget(
        gateway_url=os.environ["GATEWAY_URL"].rstrip("/"),
        token=Secret(os.environ["FORGEJO_TEST_TOKEN"]),
        owner=owner,
        repo=repo,
    )


@asynccontextmanager
async def mcp_session(gateway_url: str, bearer: str) -> AsyncIterator[ClientSession]:
    async with (
        httpx2.AsyncClient(headers={"Authorization": f"Bearer {bearer}"}, timeout=60) as http,
        streamable_http_client(f"{gateway_url}/mcp", http_client=http) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session

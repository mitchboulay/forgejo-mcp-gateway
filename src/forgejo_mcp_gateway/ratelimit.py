"""In-process token-bucket rate limiting.

Buckets live in this process, which is right for the single-replica deployment
the SQLite store implies. ``/mcp`` is limited per bearer token (by hash) and per
client address, so a flood of made-up tokens cannot turn into a flood of
Forgejo lookups. The OAuth endpoints are limited per client address.
"""

from __future__ import annotations

import json
import time
from collections import OrderedDict
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send

from .crypto import fingerprint

_MAX_BUCKETS = 50_000


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, per_minute: int, burst: int) -> None:
        self._rate = per_minute / 60.0
        self._capacity = float(burst)
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()

    def allow(self, key: str) -> tuple[bool, float]:
        """Take one token for ``key``. Returns (allowed, seconds until a token is available)."""
        now = time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=self._capacity, updated=now)
            self._buckets[key] = bucket
            while len(self._buckets) > _MAX_BUCKETS:
                self._buckets.popitem(last=False)
        else:
            bucket.tokens = min(self._capacity, bucket.tokens + (now - bucket.updated) * self._rate)
            bucket.updated = now
            self._buckets.move_to_end(key)
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return True, 0.0
        return False, (1 - bucket.tokens) / self._rate


def client_address(scope: Scope, trusted_header: str | None) -> str:
    if trusted_header:
        wanted = trusted_header.lower().encode()
        for name, value in scope.get("headers", []):
            if name == wanted:
                # The rightmost entry is the one the trusted proxy added; earlier ones are client-supplied.
                return str(value.decode("latin-1")).split(",")[-1].strip()
    client = scope.get("client")
    return str(client[0]) if client else "unknown"


class McpRateLimitMiddleware:
    """Limits ``/mcp`` requests per bearer token and per client address."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        mcp_path: str,
        per_token: RateLimiter,
        per_address: RateLimiter,
        trusted_ip_header: str | None,
    ) -> None:
        self._app = app
        self._mcp_path = mcp_path
        self._per_token = per_token
        self._per_address = per_address
        self._trusted_ip_header = trusted_ip_header

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != self._mcp_path:
            await self._app(scope, receive, send)
            return
        allowed, retry_after = self._per_address.allow(client_address(scope, self._trusted_ip_header))
        if allowed:
            authorization = next((v for k, v in scope.get("headers", []) if k == b"authorization"), None)
            if authorization:
                allowed, retry_after = self._per_token.allow(fingerprint(authorization.decode("latin-1")))
        if allowed:
            await self._app(scope, receive, send)
            return
        body = json.dumps({"error": "rate_limited", "error_description": "Too many requests"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(max(1, round(retry_after))).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

"""A typed client for the Forgejo REST API (``/api/v1``), acting as one person.

One ``httpx.AsyncClient`` is shared by every request; the person is chosen per
call by passing their token. Reads (GET) are retried with exponential backoff
and jitter on connection errors, timeouts, 429, 502, 503 and 504. Writes are
never retried: a retry after a timeout could create a second issue or comment,
or report a conflict for a file update that already landed.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

import httpx

from . import __version__

log = logging.getLogger(__name__)

Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
QueryValue = str | int | bool | Sequence[str] | None

_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
_RETRIED_METHODS: frozenset[Method] = frozenset({"GET"})
_BACKOFF_BASE_SECONDS = 0.25
_BACKOFF_CAP_SECONDS = 4.0


class ForgejoError(Exception):
    """Forgejo answered with an error, or could not be reached."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ForgejoUnauthorized(ForgejoError):
    """The token was refused (401). It is expired, revoked or wrong."""


class ForgejoUnavailable(ForgejoError):
    """Forgejo could not be reached, timed out, or kept failing after retries."""


@dataclass(frozen=True, slots=True)
class ForgejoUser:
    id: int
    login: str
    full_name: str
    is_admin: bool


@dataclass(frozen=True, slots=True)
class Page:
    """One page of a list endpoint. ``total`` is Forgejo's X-Total-Count when it sends one."""

    items: list[Any]
    page: int
    limit: int
    total: int | None

    @property
    def has_more(self) -> bool:
        if self.total is not None:
            return self.page * self.limit < self.total
        return len(self.items) >= self.limit


class InvalidPath(ForgejoError):
    """A path argument would leave the API route it was meant for (an empty, ``.`` or ``..`` segment)."""


def _segment(value: str) -> str:
    if value in ("", ".", ".."):
        raise InvalidPath(f"'{value}' is not a valid path segment", status=400)
    return quote(value, safe="")


def path(*segments: str | int) -> str:
    """Join URL path segments, percent-encoding each one (``/`` included).

    Empty, ``.`` and ``..`` segments are refused: httpx would resolve them and
    the request could reach another Forgejo endpoint.
    """
    return "/" + "/".join(_segment(str(segment)) for segment in segments)


def file_path(value: str) -> str:
    """Encode a repository file path, keeping its ``/`` separators. Refuses ``.`` and ``..`` segments."""
    parts = value.strip("/").split("/")
    if parts == [""]:
        raise InvalidPath("a file path is required", status=400)
    return "/".join(_segment(part) for part in parts)


class ForgejoClient:
    def __init__(self, base_url: str, *, timeout_seconds: float, max_attempts: int) -> None:
        self._max_attempts = max_attempts
        self._http = httpx.AsyncClient(
            base_url=f"{base_url.rstrip('/')}/api/v1",
            timeout=httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 5.0)),
            headers={"User-Agent": f"forgejo-mcp-gateway/{__version__}", "Accept": "application/json"},
            follow_redirects=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def current_user(self, token: str) -> ForgejoUser:
        data = await self.json("GET", "/user", token=token)
        return ForgejoUser(
            id=int(data["id"]),
            login=str(data["login"]),
            full_name=str(data.get("full_name") or ""),
            is_admin=bool(data.get("is_admin", False)),
        )

    async def version(self) -> str:
        data = await self.json("GET", "/version", token=None)
        return str(data.get("version", ""))

    async def json(
        self,
        method: Method,
        url: str,
        *,
        token: str | None,
        params: Mapping[str, QueryValue] | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> Any:
        response = await self._send(method, url, token=token, params=params, body=body)
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    async def text(self, url: str, *, token: str | None, params: Mapping[str, QueryValue] | None = None) -> str:
        response = await self._send("GET", url, token=token, params=params, accept="text/plain")
        return response.text

    async def page(
        self,
        url: str,
        *,
        token: str | None,
        page: int,
        limit: int,
        params: Mapping[str, QueryValue] | None = None,
        items_key: str | None = None,
    ) -> Page:
        query = {**(params or {}), "page": page, "limit": limit}
        response = await self._send("GET", url, token=token, params=query)
        data = response.json()
        items = data.get(items_key, []) if items_key else data
        if not isinstance(items, list):
            raise ForgejoError(f"expected a list from {url}")
        total_header = response.headers.get("x-total-count")
        total = int(total_header) if total_header and total_header.isdigit() else None
        if total is None and items_key and isinstance(data.get("total_count"), int):
            total = int(data["total_count"])
        return Page(items=items, page=page, limit=limit, total=total)

    async def all_pages(
        self,
        url: str,
        *,
        token: str | None,
        params: Mapping[str, QueryValue] | None = None,
        page_size: int = 50,
    ) -> list[Any]:
        """Every item of a list endpoint, fetched page by page."""
        items: list[Any] = []
        page_no = 1
        while True:
            result = await self.page(url, token=token, page=page_no, limit=page_size, params=params)
            items.extend(result.items)
            if not result.items or not result.has_more:
                return items
            page_no += 1

    async def _send(
        self,
        method: Method,
        url: str,
        *,
        token: str | None,
        params: Mapping[str, QueryValue] | None = None,
        body: Mapping[str, Any] | None = None,
        accept: str | None = None,
    ) -> httpx.Response:
        headers: dict[str, str] = {}
        if token is not None:
            headers["Authorization"] = f"token {token}"
        if accept is not None:
            headers["Accept"] = accept
        query = _clean_params(params)
        attempts = self._max_attempts if method in _RETRIED_METHODS else 1
        for attempt in range(1, attempts + 1):
            try:
                response = await self._http.request(method, url, params=query, json=body, headers=headers)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt == attempts:
                    raise ForgejoUnavailable(f"Forgejo did not respond ({type(exc).__name__})") from exc
                await _backoff(attempt, method, url, type(exc).__name__)
                continue
            if response.status_code in _RETRYABLE_STATUS and attempt < attempts:
                await _backoff(attempt, method, url, str(response.status_code), response.headers.get("retry-after"))
                continue
            if response.is_success:
                return response
            raise _error_for(response)
        raise AssertionError("unreachable")  # pragma: no cover


def _clean_params(params: Mapping[str, QueryValue] | None) -> httpx.QueryParams:
    query: list[tuple[str, str | int | float | bool | None]] = []
    for key, value in (params or {}).items():
        if value is None:
            continue
        if isinstance(value, bool):
            query.append((key, "true" if value else "false"))
        elif isinstance(value, str | int):
            query.append((key, str(value)))
        else:
            query.extend((key, str(item)) for item in value)
    return httpx.QueryParams(query)


async def _backoff(attempt: int, method: str, url: str, reason: str, retry_after: str | None = None) -> None:
    delay = min(_BACKOFF_CAP_SECONDS, _BACKOFF_BASE_SECONDS * 2 ** (attempt - 1))
    delay = delay / 2 + random.uniform(0, delay / 2)  # noqa: S311 - jitter, not security
    if retry_after and retry_after.isdigit():
        delay = min(_BACKOFF_CAP_SECONDS, max(delay, float(retry_after)))
    log.warning(
        "forgejo.retry",
        extra={"method": method, "path": url, "attempt": attempt, "reason": reason, "delay_s": round(delay, 3)},
    )
    await asyncio.sleep(delay)


def _error_for(response: httpx.Response) -> ForgejoError:
    status = response.status_code
    message = ""
    try:
        data = response.json()
        if isinstance(data, dict):
            message = str(data.get("message") or "")
            errors = data.get("errors")
            if isinstance(errors, list) and errors:
                message = f"{message} ({'; '.join(str(e) for e in errors)})".strip()
    except ValueError:
        message = ""  # not Forgejo's JSON (a proxy page, say): don't pass the body through
    if status == 401:
        return ForgejoUnauthorized("Forgejo refused the token (it may be expired or revoked)", status=status)
    if status >= 500 or status in _RETRYABLE_STATUS:
        return ForgejoUnavailable(f"Forgejo returned {status}: {message or response.reason_phrase}", status=status)
    hints = {
        403: "the token lacks the permission or scope for this",
        404: "not found, or the token cannot see it",
        409: "conflict",
        422: "Forgejo rejected the request",
    }
    detail = message or hints.get(status, response.reason_phrase)
    return ForgejoError(f"Forgejo returned {status}: {detail}", status=status)

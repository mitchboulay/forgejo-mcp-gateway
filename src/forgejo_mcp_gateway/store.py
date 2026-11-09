"""Durable state for OAuth: pending requests, connections, access and refresh tokens.

SQLite in WAL mode behind one connection and one lock. Every unit of work runs
in a single ``BEGIN IMMEDIATE`` transaction on a worker thread (``Store.run``),
so a read-then-write such as redeeming a code can never interleave with another.
That serialises writes, which is what a single-replica gateway needs; the
``Transaction`` methods are the whole storage contract, so another backend only
has to provide them.

Every secret column holds a keyed hash (``crypto.Keyring.digest``) except the
Forgejo token, which is sealed (``Keyring.seal``) and bound to its row.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

T = TypeVar("T")

SWEEP_BATCH = 200

_MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE auth_requests (
        id_hash          TEXT PRIMARY KEY,
        browser_hash     TEXT NOT NULL,
        client_id        TEXT NOT NULL,
        redirect_uri     TEXT NOT NULL,
        state            TEXT,
        code_challenge   TEXT NOT NULL,
        resource         TEXT NOT NULL,
        expires_at       INTEGER NOT NULL,
        code_hash        TEXT UNIQUE,
        code_expires_at  INTEGER,
        forgejo_user_id  INTEGER,
        forgejo_login    TEXT,
        sealed_token     BLOB,
        consumed_at      INTEGER,
        connection_id    TEXT
    ) STRICT;
    CREATE INDEX auth_requests_expires ON auth_requests (expires_at);

    CREATE TABLE connections (
        id               TEXT PRIMARY KEY,
        client_id        TEXT NOT NULL,
        forgejo_user_id  INTEGER NOT NULL,
        forgejo_login    TEXT NOT NULL,
        sealed_token     BLOB NOT NULL,
        created_at       INTEGER NOT NULL,
        expires_at       INTEGER NOT NULL,
        revoked_at       INTEGER,
        revoked_reason   TEXT
    ) STRICT;
    CREATE INDEX connections_active ON connections (forgejo_user_id, client_id) WHERE revoked_at IS NULL;

    CREATE TABLE access_tokens (
        token_hash       TEXT PRIMARY KEY,
        connection_id    TEXT NOT NULL REFERENCES connections (id) ON DELETE CASCADE,
        expires_at       INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX access_tokens_expires ON access_tokens (expires_at);
    CREATE INDEX access_tokens_connection ON access_tokens (connection_id);

    CREATE TABLE refresh_tokens (
        token_hash       TEXT PRIMARY KEY,
        connection_id    TEXT NOT NULL REFERENCES connections (id) ON DELETE CASCADE,
        expires_at       INTEGER NOT NULL,
        consumed_at      INTEGER
    ) STRICT;
    CREATE INDEX refresh_tokens_expires ON refresh_tokens (expires_at);
    CREATE INDEX refresh_tokens_connection ON refresh_tokens (connection_id);
    """,
    """
    CREATE INDEX connections_expires ON connections (expires_at);
    UPDATE connections SET sealed_token = X'' WHERE revoked_at IS NOT NULL;
    """,
)


@dataclass(frozen=True, slots=True)
class PendingRequest:
    id_hash: str
    client_id: str
    redirect_uri: str
    state: str | None
    code_challenge: str
    resource: str
    expires_at: int


@dataclass(frozen=True, slots=True)
class ApprovedRequest:
    id_hash: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    resource: str
    code_expires_at: int
    forgejo_user_id: int
    forgejo_login: str
    sealed_token: bytes
    consumed_at: int | None
    connection_id: str | None


@dataclass(frozen=True, slots=True)
class Connection:
    id: str
    client_id: str
    forgejo_user_id: int
    forgejo_login: str
    sealed_token: bytes
    expires_at: int
    revoked_at: int | None


@dataclass(frozen=True, slots=True)
class RefreshRecord:
    token_hash: str
    connection: Connection
    expires_at: int
    consumed_at: int | None


class Transaction:
    """The storage contract. Valid only inside ``Store.run``."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db

    # ── Authorization requests ────────────────────────────────────────────────

    def insert_request(self, request: PendingRequest, browser_hash: str) -> None:
        self._db.execute(
            "INSERT INTO auth_requests (id_hash, browser_hash, client_id, redirect_uri, state,"
            " code_challenge, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request.id_hash,
                browser_hash,
                request.client_id,
                request.redirect_uri,
                request.state,
                request.code_challenge,
                request.resource,
                request.expires_at,
            ),
        )

    def open_request(self, id_hash: str, browser_hash: str, now: int) -> PendingRequest | None:
        """A request still awaiting a decision, started by this browser."""
        row = self._db.execute(
            "SELECT id_hash, client_id, redirect_uri, state, code_challenge, resource, expires_at"
            " FROM auth_requests WHERE id_hash = ? AND browser_hash = ? AND code_hash IS NULL"
            " AND consumed_at IS NULL AND expires_at > ?",
            (id_hash, browser_hash, now),
        ).fetchone()
        return PendingRequest(*row) if row else None

    def approve_request(
        self,
        id_hash: str,
        *,
        code_hash: str,
        code_expires_at: int,
        forgejo_user_id: int,
        forgejo_login: str,
        sealed_token: bytes,
    ) -> None:
        self._db.execute(
            # The code can outlive the request: keep the row (and so the code) until both expire.
            "UPDATE auth_requests SET code_hash = ?, code_expires_at = ?, expires_at = MAX(expires_at, ?),"
            " forgejo_user_id = ?, forgejo_login = ?, sealed_token = ? WHERE id_hash = ?",
            (code_hash, code_expires_at, code_expires_at, forgejo_user_id, forgejo_login, sealed_token, id_hash),
        )

    def deny_request(self, id_hash: str, now: int) -> None:
        self._db.execute("UPDATE auth_requests SET consumed_at = ? WHERE id_hash = ?", (now, id_hash))

    def request_by_code(self, code_hash: str) -> ApprovedRequest | None:
        row = self._db.execute(
            "SELECT id_hash, client_id, redirect_uri, code_challenge, resource, code_expires_at,"
            " forgejo_user_id, forgejo_login, sealed_token, consumed_at, connection_id"
            " FROM auth_requests WHERE code_hash = ?",
            (code_hash,),
        ).fetchone()
        return ApprovedRequest(*row) if row else None

    def consume_request(self, id_hash: str, now: int, connection_id: str) -> None:
        """Mark a code redeemed. The sealed token moves to the connection, so it is cleared here."""
        self._db.execute(
            "UPDATE auth_requests SET consumed_at = ?, connection_id = ?, sealed_token = NULL WHERE id_hash = ?",
            (now, connection_id, id_hash),
        )

    # ── Connections ───────────────────────────────────────────────────────────

    def insert_connection(self, connection: Connection, now: int) -> None:
        self._db.execute(
            "INSERT INTO connections (id, client_id, forgejo_user_id, forgejo_login, sealed_token,"
            " created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                connection.id,
                connection.client_id,
                connection.forgejo_user_id,
                connection.forgejo_login,
                connection.sealed_token,
                now,
                connection.expires_at,
            ),
        )

    def active_connection_ids(self, forgejo_user_id: int, client_id: str) -> list[str]:
        rows = self._db.execute(
            "SELECT id FROM connections WHERE forgejo_user_id = ? AND client_id = ? AND revoked_at IS NULL",
            (forgejo_user_id, client_id),
        ).fetchall()
        return [row[0] for row in rows]

    def revoke_connection(self, connection_id: str, now: int, reason: str) -> bool:
        """Revoke a connection: wipe its sealed Forgejo token and delete its tokens.

        False when it was already revoked or unknown.
        """
        changed = self._db.execute(
            "UPDATE connections SET revoked_at = ?, revoked_reason = ?, sealed_token = X''"
            " WHERE id = ? AND revoked_at IS NULL",
            (now, reason, connection_id),
        ).rowcount
        self._db.execute("DELETE FROM access_tokens WHERE connection_id = ?", (connection_id,))
        self._db.execute("DELETE FROM refresh_tokens WHERE connection_id = ? AND consumed_at IS NULL", (connection_id,))
        return changed == 1

    # ── Tokens ────────────────────────────────────────────────────────────────

    def insert_access_token(self, token_hash: str, connection_id: str, expires_at: int) -> None:
        self._db.execute(
            "INSERT INTO access_tokens (token_hash, connection_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, connection_id, expires_at),
        )

    def insert_refresh_token(self, token_hash: str, connection_id: str, expires_at: int) -> None:
        self._db.execute(
            "INSERT INTO refresh_tokens (token_hash, connection_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, connection_id, expires_at),
        )

    def connection_for_access_token(self, token_hash: str, now: int) -> tuple[Connection, int] | None:
        """The live connection an unexpired access token belongs to, with the token's expiry."""
        row = self._db.execute(
            "SELECT c.id, c.client_id, c.forgejo_user_id, c.forgejo_login, c.sealed_token, c.expires_at,"
            " c.revoked_at, a.expires_at FROM access_tokens a JOIN connections c ON c.id = a.connection_id"
            " WHERE a.token_hash = ? AND a.expires_at > ? AND c.revoked_at IS NULL AND c.expires_at > ?",
            (token_hash, now, now),
        ).fetchone()
        return (Connection(*row[:7]), row[7]) if row else None

    def refresh_record(self, token_hash: str) -> RefreshRecord | None:
        row = self._db.execute(
            "SELECT r.token_hash, r.expires_at, r.consumed_at, c.id, c.client_id, c.forgejo_user_id,"
            " c.forgejo_login, c.sealed_token, c.expires_at, c.revoked_at"
            " FROM refresh_tokens r JOIN connections c ON c.id = r.connection_id WHERE r.token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        return RefreshRecord(token_hash=row[0], expires_at=row[1], consumed_at=row[2], connection=Connection(*row[3:]))

    def consume_refresh_token(self, token_hash: str, now: int) -> None:
        self._db.execute("UPDATE refresh_tokens SET consumed_at = ? WHERE token_hash = ?", (now, token_hash))

    def connection_id_for_token(self, token_hash: str) -> str | None:
        """The connection an access or refresh token belongs to, expired or not (for revocation)."""
        for table in ("access_tokens", "refresh_tokens"):
            row = self._db.execute(
                f"SELECT connection_id FROM {table} WHERE token_hash = ?",  # noqa: S608 - fixed table names
                (token_hash,),
            ).fetchone()
            if row:
                return str(row[0])
        return None

    # ── Housekeeping ──────────────────────────────────────────────────────────

    def sweep_expired(self, now: int) -> None:
        """Delete a bounded batch of expired rows from each table.

        Consumed refresh tokens stay until they expire: reuse detection needs them.
        """
        for table, expiry in (
            ("auth_requests", "expires_at"),
            ("access_tokens", "expires_at"),
            ("refresh_tokens", "expires_at"),
            # Expired connections go too (their tokens cascade); revoked ones keep a row, token wiped.
            ("connections", "expires_at"),
        ):
            self._db.execute(
                f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {expiry} <= ? LIMIT ?)",  # noqa: S608
                (now, SWEEP_BATCH),
            )


class Store:
    """The SQLite database. ``open()`` before use, ``close()`` at shutdown."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._db: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def open(self) -> None:
        if str(self._path) != ":memory:":
            self._path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False, timeout=10)
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA synchronous = NORMAL")
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 10000")
        self._migrate(db)
        self._db = db

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        current = int(db.execute("PRAGMA user_version").fetchone()[0])
        if current > len(_MIGRATIONS):
            raise RuntimeError(f"database schema version {current} is newer than this gateway ({len(_MIGRATIONS)})")
        for version, script in enumerate(_MIGRATIONS[current:], start=current + 1):
            db.executescript(f"BEGIN IMMEDIATE;\n{script}\nPRAGMA user_version = {version};\nCOMMIT;")

    def run_sync(self, work: Callable[[Transaction], T]) -> T:
        """Run ``work`` in one transaction on the calling thread. Commits on return, rolls back on raise."""
        with self._lock:
            if self._db is None:
                raise RuntimeError("store is not open")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = work(Transaction(self._db))
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")
            return result

    async def run(self, work: Callable[[Transaction], T]) -> T:
        """Run ``work`` in one transaction on a worker thread."""
        return await asyncio.to_thread(self.run_sync, work)

    def ping(self) -> None:
        with self._lock:
            if self._db is None:
                raise RuntimeError("store is not open")
            self._db.execute("SELECT 1").fetchone()

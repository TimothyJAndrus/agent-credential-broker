"""Grant stores. A grant moves pending -> approved -> issued, or ends denied / revoked.

Credentials are minted at pickup, not at approval, and pickup works exactly
once: every state change is a compare-and-set (``UPDATE ... WHERE state = ?``),
so two broker instances racing on the same grant can't both issue it.

``SqliteStore`` is for one process. ``PostgresStore`` is for several broker
instances behind a load balancer; the same compare-and-set gives the
exactly-once guarantee across them, and it also holds the replay cache for
signed agent logins.
"""

from __future__ import annotations

import contextlib
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

COLUMNS = (
    "id",
    "agent",
    "scope",
    "backend",
    "ttl",
    "justification",
    "state",
    "created_at",
    "approve_by",
    "decided_by",
    "issued_at",
    "expires_at",
)
_STATES = "('pending','approved','issued','denied','revoked')"

SQLITE_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, agent TEXT NOT NULL, scope TEXT NOT NULL, backend TEXT NOT NULL,
  ttl INTEGER NOT NULL, justification TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN {_STATES}),
  created_at REAL NOT NULL, approve_by REAL, decided_by TEXT, issued_at REAL, expires_at REAL
);
CREATE INDEX IF NOT EXISTS grants_state ON grants(state);
CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, expires_at REAL NOT NULL);
"""

PG_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, agent TEXT NOT NULL, scope TEXT NOT NULL, backend TEXT NOT NULL,
  ttl INTEGER NOT NULL, justification TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN {_STATES}),
  created_at DOUBLE PRECISION NOT NULL, approve_by DOUBLE PRECISION, decided_by TEXT,
  issued_at DOUBLE PRECISION, expires_at DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS grants_state ON grants(state);
CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, expires_at DOUBLE PRECISION NOT NULL);
"""


@dataclass
class Grant:
    id: str
    agent: str
    scope: str
    backend: str
    ttl: int
    justification: str
    state: str
    created_at: float
    approve_by: float | None
    decided_by: str | None
    issued_at: float | None
    expires_at: float | None


def new_id() -> str:
    # RoleSessionName allows [\\w+=,.@-], 2..64 chars; this fits and is unguessable.
    return "g-" + secrets.token_hex(12)


class _Base:
    clock = time.time

    def _new(self, agent, scope, backend, ttl, justification, state, approve_window) -> Grant:
        now = self.clock()
        return Grant(
            id=new_id(),
            agent=agent,
            scope=scope,
            backend=backend,
            ttl=ttl,
            justification=justification,
            state=state,
            created_at=now,
            approve_by=now + approve_window if state == "pending" else None,
            decided_by=None,
            issued_at=None,
            expires_at=None,
        )


class SqliteStore(_Base):
    def __init__(self, path: str = ":memory:", clock=time.time):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SQLITE_SCHEMA)
        self.clock = clock
        self._lock = threading.Lock()

    def _q(self, sql, args=()):
        with self._lock:
            return self.db.execute(sql, args)

    def create(self, agent, scope, backend, ttl, justification, state, approve_window) -> Grant:
        g = self._new(agent, scope, backend, ttl, justification, state, approve_window)
        self._q(f"INSERT INTO grants VALUES ({','.join('?' * len(COLUMNS))})", [getattr(g, c) for c in COLUMNS])
        return g

    def get(self, grant_id: str) -> Grant | None:
        r = self._q("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
        return Grant(**dict(r)) if r else None

    def transition(self, grant_id: str, frm: str, to: str, **fields) -> bool:
        sets = ", ".join(["state=?"] + [f"{k}=?" for k in fields])
        cur = self._q(f"UPDATE grants SET {sets} WHERE id=? AND state=?", [to, *fields.values(), grant_id, frm])
        return cur.rowcount == 1

    def pending(self) -> list[Grant]:
        rows = self._q("SELECT * FROM grants WHERE state='pending' ORDER BY created_at").fetchall()
        return [Grant(**dict(r)) for r in rows]

    def revoked_unexpired(self, backend: str) -> list[str]:
        rows = self._q(
            "SELECT id FROM grants WHERE state='revoked' AND backend=? AND expires_at > ?", (backend, self.clock())
        ).fetchall()
        return [r["id"] for r in rows]

    @contextlib.contextmanager
    def lock(self, name: str):
        """Serialize a read-modify-write (e.g. the STS revocation list) across callers."""
        with self._named_lock:
            yield

    _named_lock = threading.Lock()

    def use_nonce(self, nonce: str, ttl: float) -> bool:
        """Record a one-time value. False if it was already used (a replay)."""
        now = self.clock()
        self._q("DELETE FROM nonces WHERE expires_at < ?", (now,))
        cur = self._q("INSERT OR IGNORE INTO nonces VALUES (?, ?)", (nonce, now + ttl))
        return cur.rowcount == 1


class PostgresStore(_Base):
    def __init__(self, dsn: str, clock=time.time, min_size: int = 1, max_size: int = 10):
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self.pool = ConnectionPool(
            dsn, min_size=min_size, max_size=max_size, open=True, kwargs={"autocommit": True, "row_factory": dict_row}
        )
        self.clock = clock
        with self.pool.connection() as c:
            c.execute("SELECT pg_advisory_lock(7400001)")
            try:
                c.execute(PG_SCHEMA)
            finally:
                c.execute("SELECT pg_advisory_unlock(7400001)")

    def _q(self, sql, args=()):
        with self.pool.connection() as c:
            cur = c.execute(sql, args)
            rows = cur.fetchall() if cur.description else None
            return rows, cur.rowcount

    def create(self, agent, scope, backend, ttl, justification, state, approve_window) -> Grant:
        g = self._new(agent, scope, backend, ttl, justification, state, approve_window)
        self._q(
            f"INSERT INTO grants ({','.join(COLUMNS)}) VALUES ({','.join(['%s'] * len(COLUMNS))})",
            [getattr(g, c) for c in COLUMNS],
        )
        return g

    def get(self, grant_id: str) -> Grant | None:
        rows, _ = self._q("SELECT * FROM grants WHERE id=%s", (grant_id,))
        return Grant(**rows[0]) if rows else None

    def transition(self, grant_id: str, frm: str, to: str, **fields) -> bool:
        sets = ", ".join(["state=%s"] + [f"{k}=%s" for k in fields])
        _, n = self._q(f"UPDATE grants SET {sets} WHERE id=%s AND state=%s", [to, *fields.values(), grant_id, frm])
        return n == 1

    def pending(self) -> list[Grant]:
        rows, _ = self._q("SELECT * FROM grants WHERE state='pending' ORDER BY created_at")
        return [Grant(**r) for r in rows]

    def revoked_unexpired(self, backend: str) -> list[str]:
        rows, _ = self._q(
            "SELECT id FROM grants WHERE state='revoked' AND backend=%s AND expires_at > %s", (backend, self.clock())
        )
        return [r["id"] for r in rows]

    @contextlib.contextmanager
    def lock(self, name: str):
        """Session-level advisory lock, so every broker instance serializes on it."""
        key = int.from_bytes(name.encode()[:8].ljust(8, b"\0"), "big", signed=True)
        with self.pool.connection() as c:
            c.execute("SELECT pg_advisory_lock(%s)", (key,))
            try:
                yield
            finally:
                c.execute("SELECT pg_advisory_unlock(%s)", (key,))

    def use_nonce(self, nonce: str, ttl: float) -> bool:
        now = self.clock()
        self._q("DELETE FROM nonces WHERE expires_at < %s", (now,))
        _, n = self._q("INSERT INTO nonces VALUES (%s, %s) ON CONFLICT DO NOTHING", (nonce, now + ttl))
        return n == 1


Store = SqliteStore  # backwards-compatible name


def open_store(url: str, clock=time.time):
    if url.startswith(("postgres://", "postgresql://")):
        return PostgresStore(url, clock=clock)
    return SqliteStore(url.removeprefix("sqlite:///") if url.startswith("sqlite:///") else url, clock=clock)

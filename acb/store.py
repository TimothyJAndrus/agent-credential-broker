"""Grant store (SQLite). A grant moves pending -> approved -> issued, or ends denied / revoked.

Credentials are minted at pickup, not at approval, and pickup works exactly
once. A leaked grant id is therefore worth nothing after the agent has
collected its credentials, and the TTL clock starts when the credentials
exist rather than when someone clicked approve.
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  agent TEXT NOT NULL,
  scope TEXT NOT NULL,
  backend TEXT NOT NULL,
  ttl INTEGER NOT NULL,
  justification TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','approved','issued','denied','revoked')),
  created_at REAL NOT NULL,
  approve_by REAL,
  decided_by TEXT,
  issued_at REAL,
  expires_at REAL
);
CREATE INDEX IF NOT EXISTS grants_state ON grants(state);
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
    # RoleSessionName allows [\w+=,.@-], 2..64 chars; this fits and is unguessable.
    return "g-" + secrets.token_hex(12)


class Store:
    def __init__(self, path: str = ":memory:", clock=time.time):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.clock = clock
        self._lock = threading.Lock()

    def _row(self, r) -> Grant | None:
        return Grant(**dict(r)) if r else None

    def create(self, agent, scope, backend, ttl, justification, state, approve_window) -> Grant:
        g = Grant(
            id=new_id(),
            agent=agent,
            scope=scope,
            backend=backend,
            ttl=ttl,
            justification=justification,
            state=state,
            created_at=self.clock(),
            approve_by=self.clock() + approve_window if state == "pending" else None,
            decided_by=None,
            issued_at=None,
            expires_at=None,
        )
        with self._lock:
            self.db.execute(
                "INSERT INTO grants VALUES (:id,:agent,:scope,:backend,:ttl,:justification,:state,"
                ":created_at,:approve_by,:decided_by,:issued_at,:expires_at)",
                g.__dict__,
            )
        return g

    def get(self, grant_id: str) -> Grant | None:
        return self._row(self.db.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone())

    def transition(self, grant_id: str, frm: str, to: str, **fields) -> bool:
        """Atomic compare-and-set on state. Returns False if the grant was not in ``frm``."""
        sets = ", ".join(["state=?"] + [f"{k}=?" for k in fields])
        with self._lock:
            cur = self.db.execute(
                f"UPDATE grants SET {sets} WHERE id=? AND state=?",
                [to, *fields.values(), grant_id, frm],
            )
        return cur.rowcount == 1

    def pending(self) -> list[Grant]:
        rows = self.db.execute("SELECT * FROM grants WHERE state='pending' ORDER BY created_at").fetchall()
        return [self._row(r) for r in rows]

    def revoked_unexpired(self, backend: str) -> list[str]:
        rows = self.db.execute(
            "SELECT id FROM grants WHERE state='revoked' AND backend=? AND expires_at > ?",
            (backend, self.clock()),
        ).fetchall()
        return [r["id"] for r in rows]

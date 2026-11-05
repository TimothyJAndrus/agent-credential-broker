"""Tamper-evident audit log: every record is chained to the previous one by SHA-256.

Editing, deleting or reordering any record breaks the chain from that point
on, and ``verify`` reports the first bad record. Someone with write access
could still rewrite the whole chain; ship the head hash somewhere else
(CloudWatch, S3 Object Lock) for that.

``AuditLog`` writes JSON lines to a file (one process). ``PostgresAuditLog``
keeps the chain in a table and serializes writers with a transaction-level
advisory lock, so several broker instances extend one chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + canon).encode()).hexdigest()


def _verify_records(records) -> tuple[bool, int, str]:
    prev, n = GENESIS, 0
    for n, rec in enumerate(records, start=1):
        if rec is None:
            return False, n, f"record {n}: not valid JSON"
        rec = dict(rec)
        claimed_prev, claimed = rec.pop("prev", None), rec.pop("hash", None)
        if claimed_prev != prev:
            return False, n, f"record {n}: chain broken (a record before it was removed or reordered)"
        if _digest(prev, rec) != claimed:
            return False, n, f"record {n}: contents changed after it was written"
        prev = claimed
    return True, n, "ok" if n else "empty"


class AuditLog:
    def __init__(self, path: str | Path, clock=time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self._lock = threading.Lock()
        self._head = self._read_head()

    def _read_head(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        with self.path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            pos, buf = f.tell(), b""
            while pos > 0 and buf.count(b"\n") < 2:
                step = min(4096, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
        last = [line for line in buf.splitlines() if line.strip()][-1]
        return json.loads(last)["hash"]

    def write(self, event: str, **fields) -> str:
        with self._lock:
            body = {"ts": round(self.clock(), 3), "event": event, **fields}
            h = _digest(self._head, body)
            with self.path.open("a") as f:
                f.write(json.dumps({**body, "prev": self._head, "hash": h}, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._head = h
            return h

    @property
    def head(self) -> str:
        return self._head

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for raw in self.path.read_text().splitlines():
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                out.append(None)
        return out

    def verify(self) -> tuple[bool, int, str]:
        return _verify_records(self.records())


PG_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
  seq BIGSERIAL PRIMARY KEY,
  body JSONB NOT NULL,
  prev TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE
);
"""


class PostgresAuditLog:
    LOCK_KEY = 7400002

    def __init__(self, pool, clock=time.time):
        self.pool = pool
        self.clock = clock
        with pool.connection() as c:
            c.execute("SELECT pg_advisory_lock(%s)", (self.LOCK_KEY,))
            try:
                c.execute(PG_AUDIT_SCHEMA)
            finally:
                c.execute("SELECT pg_advisory_unlock(%s)", (self.LOCK_KEY,))

    def write(self, event: str, **fields) -> str:
        body = {"ts": round(self.clock(), 3), "event": event, **fields}
        with self.pool.connection() as c, c.transaction():
            c.execute("SELECT pg_advisory_xact_lock(%s)", (self.LOCK_KEY,))
            row = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            # Hash the body as it will read back from JSONB (key order is normalized by sort_keys).
            h = _digest(prev, body)
            c.execute("INSERT INTO audit (body, prev, hash) VALUES (%s::jsonb, %s, %s)", (json.dumps(body), prev, h))
        return h

    @property
    def head(self) -> str:
        with self.pool.connection() as c:
            row = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else GENESIS

    def records(self) -> list[dict]:
        with self.pool.connection() as c:
            rows = c.execute("SELECT body, prev, hash FROM audit ORDER BY seq").fetchall()
        return [{**r["body"], "prev": r["prev"], "hash": r["hash"]} for r in rows]

    def verify(self) -> tuple[bool, int, str]:
        return _verify_records(self.records())

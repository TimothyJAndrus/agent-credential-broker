"""Tamper-evident audit log: append-only JSON lines, each chained to the previous by SHA-256.

Editing, deleting or reordering any line breaks the chain from that point on,
and ``verify`` reports the first bad line. This does not stop someone with
write access from rewriting the whole file; ship the head hash somewhere
else (CloudWatch, S3 Object Lock) for that. It does make quiet edits visible.
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
            pos = f.tell()
            buf = b""
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
            line = json.dumps({**body, "prev": self._head, "hash": h}, sort_keys=True)
            with self.path.open("a") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._head = h
            return h

    @property
    def head(self) -> str:
        return self._head

    def verify(self) -> tuple[bool, int, str]:
        """Return (ok, lines_checked, message)."""
        prev = GENESIS
        n = 0
        if not self.path.exists():
            return True, 0, "empty"
        with self.path.open() as f:
            for n, raw in enumerate(f, start=1):
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    return False, n, f"line {n}: not valid JSON"
                claimed_prev, claimed = rec.pop("prev", None), rec.pop("hash", None)
                if claimed_prev != prev:
                    return False, n, f"line {n}: chain broken (a line before it was removed or reordered)"
                if _digest(prev, rec) != claimed:
                    return False, n, f"line {n}: contents changed after it was written"
                prev = claimed
        return True, n, "ok"

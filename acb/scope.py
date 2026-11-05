"""Scope grammar: one action on one S3 resource, with an optional trailing wildcard.

A scope is the unit of permission an agent asks for, e.g. ``read`` on
``s3://acme-data/reports/*``. The grammar is deliberately narrow so that
containment ("is this request inside what the policy allows?") is a prefix
check that can be proven correct, and so that a resource string can never
smuggle IAM syntax (``${aws:username}``, ``?``, mid-string ``*``) into a
session policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ACTIONS = ("read", "write", "list")

_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
# S3 "safe characters" only. No '$', '{', '?', '[', '*' except one at the end.
_KEY = re.compile(r"^[A-Za-z0-9!_.'()/-]*$")


class ScopeError(ValueError):
    """The requested scope is malformed. The message is safe to return to the caller."""


@dataclass(frozen=True)
class Scope:
    action: str
    bucket: str
    prefix: str  # object key, or key prefix when wildcard is True
    wildcard: bool

    @property
    def resource(self) -> str:
        return f"s3://{self.bucket}/{self.prefix}{'*' if self.wildcard else ''}"

    def __str__(self) -> str:
        return f"{self.action}:{self.resource}"

    def within(self, allowed: Scope) -> bool:
        """True if every object this scope can touch is also covered by ``allowed``."""
        if self.action != allowed.action or self.bucket != allowed.bucket:
            return False
        if allowed.wildcard:
            return self.prefix.startswith(allowed.prefix)
        return not self.wildcard and self.prefix == allowed.prefix

    def overlaps(self, other: Scope) -> bool:
        """True if some object is reachable through both scopes (same action and bucket)."""
        if self.action != other.action or self.bucket != other.bucket:
            return False
        if self.wildcard and other.wildcard:
            return self.prefix.startswith(other.prefix) or other.prefix.startswith(self.prefix)
        if self.wildcard:
            return other.prefix.startswith(self.prefix)
        if other.wildcard:
            return self.prefix.startswith(other.prefix)
        return self.prefix == other.prefix


def parse(action: str, resource: str) -> Scope:
    if action not in ACTIONS:
        raise ScopeError(f"unknown action {action!r}; expected one of {', '.join(ACTIONS)}")
    if not isinstance(resource, str) or not resource.startswith("s3://"):
        raise ScopeError("resource must look like s3://bucket/key or s3://bucket/prefix*")
    rest = resource[len("s3://") :]
    bucket, sep, key = rest.partition("/")
    if not sep:
        raise ScopeError("resource needs a key or prefix after the bucket, e.g. s3://bucket/*")
    if not _BUCKET.match(bucket) or ".." in bucket:
        raise ScopeError("invalid bucket name")
    wildcard = key.endswith("*")
    if wildcard:
        key = key[:-1]
    if not _KEY.match(key):
        raise ScopeError("key may only use S3 safe characters, with '*' allowed only at the end")
    if key.startswith("/") or "//" in key:
        raise ScopeError("key may not start with '/' or contain empty segments")
    if any(seg in (".", "..") for seg in key.split("/")):
        raise ScopeError("key may not contain '.' or '..' segments")
    if not wildcard and (key == "" or key.endswith("/")):
        raise ScopeError("an exact key cannot be empty or end in '/'; use a trailing '*' for a prefix")
    if action == "list" and not wildcard:
        raise ScopeError("list needs a prefix, e.g. s3://bucket/reports/*")
    if len(resource) > 512:
        raise ScopeError("resource too long")
    return Scope(action=action, bucket=bucket, prefix=key, wildcard=wildcard)

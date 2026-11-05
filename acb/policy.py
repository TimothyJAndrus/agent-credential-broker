"""Policy: who may ask for what, for how long, and whether a human must approve.

Default deny. A request is granted only if some allow/approve rule for the
calling agent contains it entirely. Deny rules apply if they merely overlap
the request: asking for ``reports/board/*`` is refused when one file under it
is denied, because the credentials would reach that file. Among containing
rules the strictest decision wins (approve > allow), and the TTL is the smallest of the request, the
matching rules, and the global ceiling. The justification text an agent
sends is recorded but never read by the policy, so persuasive wording cannot
change a decision.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .scope import Scope, ScopeError, parse

DECISIONS = ("allow", "approve", "deny")
_RANK = {"allow": 0, "approve": 1, "deny": 2}
BACKENDS = ("jwt", "sts")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    scope: Scope
    decision: str
    max_ttl: int
    backend: str


@dataclass(frozen=True)
class Principal:
    name: str
    key_sha256: str


@dataclass
class Policy:
    max_ttl: int
    agents: dict[str, list[Rule]]
    agent_keys: dict[str, Principal]
    approvers: dict[str, Principal]
    sts_role_arn: str | None = None
    sts_region: str = "us-west-2"
    warnings: list[str] = field(default_factory=list)

    def authenticate(self, api_key: str, kind: str) -> str | None:
        """Return the principal name for a presented API key, or None."""
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        table = self.agent_keys if kind == "agent" else self.approvers
        for p in table.values():
            if hmac.compare_digest(p.key_sha256, digest):
                return p.name
        return None


@dataclass(frozen=True)
class Decision:
    decision: str  # allow | approve | deny
    ttl: int
    backend: str
    reason: str


def evaluate(policy: Policy, agent: str, scope: Scope, requested_ttl: int) -> Decision:
    if requested_ttl <= 0:
        return Decision("deny", 0, "jwt", "ttl must be positive")
    rules = policy.agents.get(agent, [])
    for r in rules:
        if r.decision == "deny" and scope.overlaps(r.scope):
            return Decision("deny", 0, r.backend, f"request overlaps denied resource {r.scope.resource}")
    matches = [r for r in rules if r.decision != "deny" and scope.within(r.scope)]
    if not matches:
        return Decision("deny", 0, "jwt", f"no rule grants {scope} to {agent}")
    strictest = max(matches, key=lambda r: _RANK[r.decision])
    backends = {r.backend for r in matches}
    if len(backends) > 1:
        return Decision("deny", 0, "jwt", "matching rules disagree on backend; fix the policy")
    ttl = min([requested_ttl, policy.max_ttl] + [r.max_ttl for r in matches])
    return Decision(strictest.decision, ttl, backends.pop(), f"matched {len(matches)} rule(s)")


def _principal(name: str, raw: dict, where: str) -> Principal:
    key = (raw or {}).get("key_sha256", "")
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        raise PolicyError(f"{where} {name}: key_sha256 must be 64 lowercase hex chars")
    return Principal(name, key)


def load(path: str | Path) -> Policy:
    doc = yaml.safe_load(Path(path).read_text())
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise PolicyError("policy must be a mapping with version: 1")
    max_ttl = int(doc.get("max_ttl_seconds", 3600))
    if not 60 <= max_ttl <= 43200:
        raise PolicyError("max_ttl_seconds must be between 60 and 43200")
    sts = doc.get("sts") or {}
    policy = Policy(
        max_ttl=max_ttl,
        agents={},
        agent_keys={},
        approvers={},
        sts_role_arn=sts.get("role_arn"),
        sts_region=sts.get("region", "us-west-2"),
    )
    for name, raw in (doc.get("approvers") or {}).items():
        policy.approvers[name] = _principal(name, raw, "approver")
    for name, raw in (doc.get("agents") or {}).items():
        if name in policy.approvers:
            raise PolicyError(f"{name} cannot be both an agent and an approver")
        policy.agent_keys[name] = _principal(name, raw, "agent")
        rules = []
        for i, r in enumerate(raw.get("rules") or []):
            where = f"agents.{name}.rules[{i}]"
            try:
                scope = parse(r["action"], r["resource"])
            except (KeyError, ScopeError) as e:
                raise PolicyError(f"{where}: {e}") from e
            decision = r.get("decision", "allow")
            backend = r.get("backend", "jwt")
            if decision not in DECISIONS:
                raise PolicyError(f"{where}: decision must be one of {DECISIONS}")
            if backend not in BACKENDS:
                raise PolicyError(f"{where}: backend must be one of {BACKENDS}")
            ttl = int(r.get("max_ttl_seconds", max_ttl))
            if backend == "sts" and decision != "deny" and ttl < 900:
                raise PolicyError(f"{where}: STS sessions last at least 900 seconds; set max_ttl_seconds >= 900")
            if backend == "sts" and not policy.sts_role_arn:
                raise PolicyError(f"{where}: backend sts needs sts.role_arn")
            if scope.wildcard and scope.prefix and not scope.prefix.endswith("/"):
                policy.warnings.append(
                    f"{where}: {scope.resource} also matches siblings such as "
                    f"{scope.prefix}-archive/; end the prefix with '/' if you mean a folder"
                )
            rules.append(Rule(scope, decision, ttl, backend))
        policy.agents[name] = rules
    return policy

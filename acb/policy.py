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
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .auth import OidcRule
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
    sts_probe_bucket: str | None = None
    server_id: str = "agent-credential-broker"
    aws_principals: dict[str, str] = field(default_factory=dict)  # normalized IAM ARN -> agent
    oidc_rules: list[tuple[str, OidcRule]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def authenticate(self, api_key: str, kind: str) -> str | None:
        """Return the principal name for a presented API key, or None."""
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        table = self.agent_keys if kind == "agent" else self.approvers
        for p in table.values():
            if p.key_sha256 and hmac.compare_digest(p.key_sha256, digest):
                return p.name
        return None

    def agent_for_arn(self, arn: str) -> str | None:
        return self.aws_principals.get(arn)


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


def _principal(name: str, raw: dict, where: str, required: bool = True) -> Principal:
    key = (raw or {}).get("key_sha256", "")
    if not key and not required:
        return Principal(name, "")
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
        sts_probe_bucket=sts.get("probe_bucket"),
        server_id=str(doc.get("server_id", "agent-credential-broker")),
    )
    for name, raw in (doc.get("approvers") or {}).items():
        policy.approvers[name] = _principal(name, raw, "approver")
    for name, raw in (doc.get("agents") or {}).items():
        if name in policy.approvers:
            raise PolicyError(f"{name} cannot be both an agent and an approver")
        raw = raw or {}
        policy.agent_keys[name] = _principal(name, raw, "agent", required=False)
        methods = 1 if raw.get("key_sha256") else 0
        for arn in raw.get("aws_principals") or []:
            if not re.fullmatch(r"arn:aws:iam::\d{12}:(role|user)/[\w+=,.@-]+", arn):
                raise PolicyError(
                    f"agents.{name}.aws_principals: {arn!r} must be a role or user ARN "
                    "without a path (assumed-role sessions drop the path)"
                )
            if arn in policy.aws_principals:
                raise PolicyError(f"{arn} is mapped to two agents")
            policy.aws_principals[arn] = name
            methods += 1
        for o in raw.get("oidc") or []:
            try:
                rule = OidcRule(issuer=o["issuer"], audience=o["audience"], subject=o["subject"])
            except (KeyError, TypeError) as e:
                raise PolicyError(f"agents.{name}.oidc: needs issuer, audience and subject") from e
            if not rule.issuer.startswith("https://"):
                raise PolicyError(f"agents.{name}.oidc: issuer must be https")
            if "*" in rule.subject:
                raise PolicyError(f"agents.{name}.oidc: subject must be exact, no wildcards")
            policy.oidc_rules.append((name, rule))
            methods += 1
        if methods == 0:
            raise PolicyError(f"agent {name} has no way to authenticate (key_sha256, aws_principals or oidc)")
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

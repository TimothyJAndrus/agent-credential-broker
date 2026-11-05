import hashlib
import textwrap

import pytest
from fastapi.testclient import TestClient

from acb.app import create_app
from acb.audit import AuditLog
from acb.backends.jwt_backend import JwtBackend
from acb.policy import load
from acb.store import Store

KEYS = {"reporter": "agent-key-reporter", "intruder": "agent-key-intruder", "tim": "approver-key-tim"}


def sha(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()


POLICY = f"""
version: 1
max_ttl_seconds: 3600
sts:
  role_arn: arn:aws:iam::123456789012:role/acb-ceiling
approvers:
  tim: {{key_sha256: {sha(KEYS["tim"])}}}
agents:
  reporter:
    key_sha256: {sha(KEYS["reporter"])}
    rules:
      - {{action: read,  resource: "s3://acme-data/reports/*", decision: allow, max_ttl_seconds: 900}}
      - {{action: list,  resource: "s3://acme-data/reports/*", decision: allow}}
      - {{action: read,  resource: "s3://acme-data/reports/board/*", decision: approve}}
      - {{action: write, resource: "s3://acme-data/outbox/*", decision: approve, max_ttl_seconds: 600}}
      - {{action: read,  resource: "s3://acme-data/reports/board/salaries.csv", decision: deny}}
      - {{action: read,  resource: "s3://acme-data/exports/summary.csv", decision: allow}}
      - {{action: read,  resource: "s3://acme-live/feeds/*", decision: allow, backend: sts, max_ttl_seconds: 900}}
  intruder:
    key_sha256: {sha(KEYS["intruder"])}
    rules: []
"""


class Clock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class FakeSts:
    """Records what the broker would send to AWS. Used where real AWS is not needed."""

    def __init__(self):
        self.calls = []
        self.revoked = None

    def issue(self, grant_id, agent, scope, ttl):
        self.calls.append((grant_id, agent, str(scope), ttl))
        return {
            "type": "aws_sts",
            "access_key_id": "ASIAFAKE",
            "secret_access_key": "x",
            "session_token": "y",
            "expires_at": 0,
            "assumed_role_arn": "arn:fake",
        }

    def sync_revocations(self, ids):
        self.revoked = list(ids)


@pytest.fixture
def env(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(POLICY))
    clock = Clock()
    policy = load(p)
    jb = JwtBackend.generate(clock=clock)
    sts = FakeSts()
    audit = AuditLog(tmp_path / "audit.jsonl", clock=clock)
    store = Store(":memory:", clock=clock)
    app = create_app(policy, store, audit, jb, sts, clock=clock, approval_window=900)

    class Env:
        pass

    e = Env()
    e.client, e.clock, e.jwt, e.sts, e.audit, e.store, e.policy, e.policy_path = (
        TestClient(app),
        clock,
        jb,
        sts,
        audit,
        store,
        policy,
        p,
    )
    e.agent = lambda name="reporter": {"X-Agent-Key": KEYS[name]}
    e.approver = {"X-Approver-Key": KEYS["tim"]}

    def ask(action, resource, ttl=900, who="reporter", why="weekly report"):
        return e.client.post(
            "/v1/grants",
            headers=e.agent(who),
            json={"action": action, "resource": resource, "ttl_seconds": ttl, "justification": why},
        )

    e.ask = ask
    return e

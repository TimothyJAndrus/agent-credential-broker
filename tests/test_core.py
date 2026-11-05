"""Unit tests: scope grammar, policy evaluation, session policies, audit chain."""

import json

import pytest

from acb.audit import AuditLog
from acb.backends.sts_backend import revocation_policy, session_policy
from acb.policy import PolicyError, evaluate, load
from acb.scope import ScopeError, parse


@pytest.mark.parametrize(
    "action,resource",
    [
        ("read", "s3://b/k"),  # bucket too short
        ("read", "s3://acme-data"),  # no key
        ("read", "s3://acme-data/a*b"),  # mid-string wildcard
        ("read", "s3://acme-data/${aws:username}/*"),  # IAM policy variable injection
        ("read", "s3://acme-data/reports/../payroll/*"),  # traversal
        ("read", "s3://acme-data/a?c"),  # IAM single-char wildcard
        ("read", "s3://acme-data//x"),
        ("read", "s3://acme-data/"),  # empty exact key
        ("list", "s3://acme-data/reports/x.csv"),  # list needs a prefix
        ("delete", "s3://acme-data/x"),
        ("read", "arn:aws:s3:::acme-data/*"),
    ],
)
def test_bad_scopes_rejected(action, resource):
    with pytest.raises(ScopeError):
        parse(action, resource)


def test_containment():
    allowed = parse("read", "s3://acme-data/reports/*")
    assert parse("read", "s3://acme-data/reports/q3.csv").within(allowed)
    assert parse("read", "s3://acme-data/reports/2026/*").within(allowed)
    assert not parse("read", "s3://acme-data/*").within(allowed)  # broader
    assert not parse("write", "s3://acme-data/reports/q3.csv").within(allowed)  # other action
    assert not parse("read", "s3://acme-datax/reports/q3.csv").within(allowed)  # other bucket
    exact = parse("read", "s3://acme-data/exports/summary.csv")
    assert parse("read", "s3://acme-data/exports/summary.csv").within(exact)
    assert not parse("read", "s3://acme-data/exports/summary.csv*").within(exact)  # wildcard widens exact


def test_strictest_rule_wins_and_ttl_is_clamped(env):
    p = env.policy
    assert evaluate(p, "reporter", parse("read", "s3://acme-data/reports/q3.csv"), 3600).decision == "allow"
    assert evaluate(p, "reporter", parse("read", "s3://acme-data/reports/q3.csv"), 3600).ttl == 900
    assert evaluate(p, "reporter", parse("read", "s3://acme-data/reports/board/q3.pdf"), 60).decision == "approve"
    assert evaluate(p, "reporter", parse("read", "s3://acme-data/reports/board/salaries.csv"), 60).decision == "deny"
    # A wildcard that would reach a denied object is refused outright, even though a human could approve it:
    d = evaluate(p, "reporter", parse("read", "s3://acme-data/reports/board/*"), 60)
    assert d.decision == "deny" and "overlaps denied" in d.reason
    d = evaluate(p, "reporter", parse("read", "s3://acme-data/reports/*"), 60)
    assert d.decision == "deny"  # the broad allow rule can't hand out salaries.csv either
    assert evaluate(p, "intruder", parse("read", "s3://acme-data/reports/q3.csv"), 60).decision == "deny"
    assert evaluate(p, "nobody", parse("read", "s3://acme-data/reports/q3.csv"), 60).decision == "deny"


def test_policy_validation(tmp_path):
    bad = tmp_path / "p.yaml"
    bad.write_text(
        "version: 1\nagents:\n  a:\n    key_sha256: "
        + "a" * 64
        + "\n    rules:\n      - {action: read, resource: 's3://acme-data/*', backend: sts}\n"
    )
    with pytest.raises(PolicyError, match="sts.role_arn"):
        load(bad)
    bad.write_text(
        "version: 1\nsts: {role_arn: arn:aws:iam::1:role/r}\nagents:\n  a:\n    key_sha256: "
        + "a" * 64
        + "\n    rules:\n      - {action: read, resource: 's3://acme-data/*', backend: sts, max_ttl_seconds: 60}\n"
    )
    with pytest.raises(PolicyError, match="900"):
        load(bad)
    bad.write_text(
        "version: 1\napprovers:\n  a: {key_sha256: " + "b" * 64 + "}\nagents:\n  a:\n    key_sha256: " + "a" * 64 + "\n"
    )
    with pytest.raises(PolicyError, match="both"):
        load(bad)


def test_sibling_prefix_warning(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text(
        "version: 1\nagents:\n  a:\n    key_sha256: "
        + "a" * 64
        + "\n    rules:\n      - {action: read, resource: 's3://acme-data/reports*'}\n"
    )
    assert any("reports-archive" in w for w in load(p).warnings)


def test_session_policies_are_exactly_scoped():
    r = session_policy(parse("read", "s3://acme-data/reports/*"))["Statement"][0]
    assert r["Action"] == ["s3:GetObject"] and r["Resource"] == "arn:aws:s3:::acme-data/reports/*"
    w = session_policy(parse("write", "s3://acme-data/outbox/a.json"))["Statement"][0]
    assert w["Action"] == ["s3:PutObject"] and w["Resource"] == "arn:aws:s3:::acme-data/outbox/a.json"
    lst = session_policy(parse("list", "s3://acme-data/reports/*"))["Statement"][0]
    assert lst["Resource"] == "arn:aws:s3:::acme-data"
    assert lst["Condition"] == {"StringLike": {"s3:prefix": ["reports/*"]}}
    for s in (r, w, lst):
        assert s["Effect"] == "Allow" and "*" not in s["Action"]


def test_revocation_policy_denies_tagged_sessions():
    doc = revocation_policy(["g-2", "g-1"])
    st = doc["Statement"][0]
    assert st["Effect"] == "Deny" and st["Action"] == "*"
    assert st["Condition"]["StringEquals"]["aws:PrincipalTag/acb_grant"] == ["g-1", "g-2"]


def test_audit_chain_detects_edit_delete_reorder(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.write("e", i=i)
    assert log.verify() == (True, 5, "ok")
    assert AuditLog(path).head == log.head  # head survives restart

    lines = path.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["i"] = 99
    path.write_text("\n".join(lines[:2] + [json.dumps(rec)] + lines[3:]) + "\n")
    ok, n, msg = AuditLog(path).verify()
    assert not ok and n == 3 and "changed" in msg

    path.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    ok, n, msg = AuditLog(path).verify()
    assert not ok and n == 3 and "removed or reordered" in msg

    path.write_text("\n".join([lines[1], lines[0]] + lines[2:]) + "\n")
    assert not AuditLog(path).verify()[0]


def test_revocation_list_falls_back_to_cutoff_when_too_big():
    from datetime import UTC, datetime

    from acb.backends.sts_backend import REVOCATION_BUDGET_CHARS, fit_revocations

    now = datetime(2026, 11, 5, 16, 0, 0, tzinfo=UTC)
    doc, cut = fit_revocations([f"g-{i:024x}" for i in range(10)], now)
    assert not cut and len(doc["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalTag/acb_grant"]) == 10
    many = [f"g-{i:024x}" for i in range(400)]
    doc, cut = fit_revocations(many, now)
    assert cut
    assert doc["Statement"] == [
        {
            "Sid": "AcbRevokeAllBefore",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": "2026-11-05T16:00:00Z"}},
        }
    ]
    assert len(json.dumps(doc)) < REVOCATION_BUDGET_CHARS

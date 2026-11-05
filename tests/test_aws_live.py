"""Live AWS proof for the STS backend and IAM agent auth. Skipped unless ACB_AWS_TESTS=1.

Needs the acb-sts stack (infra/sts-backend.yaml). The broker side runs as
acb-sts-broker-test, a role holding ONLY the broker's least-privilege policy,
so these tests prove what a real (or compromised) broker can and can't do.
"""

import json
import os
import time
import uuid
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.exceptions import ClientError

from acb.auth import AuthError, AwsIamVerifier, sign_identity_request
from acb.backends.sts_backend import REVOCATION_POLICY, StsBackend, revocation_policy
from acb.scope import parse

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(os.environ.get("ACB_AWS_TESTS") != "1", reason="set ACB_AWS_TESTS=1 to hit real AWS"),
]

REGION = os.environ.get("AWS_REGION", "us-west-2")


def session_for(role_arn: str, name: str) -> boto3.Session:
    c = boto3.client("sts", region_name=REGION).assume_role(RoleArn=role_arn, RoleSessionName=name)["Credentials"]
    return boto3.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
        region_name=REGION,
    )


@pytest.fixture(scope="module")
def stack():
    cfn = boto3.client("cloudformation", region_name=REGION)
    out = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName="acb-sts")["Stacks"][0]["Outputs"]}
    s3 = boto3.client("s3", region_name=REGION)
    for key in ("feeds/a.json", "feeds/b.json", "payroll/2026.csv"):
        s3.put_object(Bucket=out["DemoBucketName"], Key=key, Body=b'{"ok":true}')
    broker = session_for(out["BrokerTestRoleArn"], "acb-live-tests")
    backend = StsBackend(
        out["CeilingRoleArn"], broker.client("sts"), broker.client("iam"), probe_bucket=out["DemoBucketName"]
    )
    yield out, backend, broker
    backend.sync_revocations([])


def as_agent(creds):
    return boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        aws_session_token=creds["session_token"],
    )


def denied(fn) -> bool:
    try:
        fn()
        return False
    except ClientError as e:
        return e.response["Error"]["Code"] in ("AccessDenied", "403", "AccessDeniedException")


def wait_denied(fn, timeout=60) -> float | None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if denied(fn):
            return time.time() - t0
        time.sleep(2)
    return None


def test_session_policy_narrows_and_ceiling_holds(stack):
    out, backend, _ = stack
    bucket = out["DemoBucketName"]
    gid = f"g-test-{uuid.uuid4().hex[:8]}"
    creds = backend.issue(gid, "reporter", parse("read", f"s3://{bucket}/feeds/a.json"), 900)
    s3 = as_agent(creds)
    assert s3.get_object(Bucket=bucket, Key="feeds/a.json")["Body"].read() == b'{"ok":true}'
    assert denied(lambda: s3.get_object(Bucket=bucket, Key="feeds/b.json"))
    assert denied(lambda: s3.put_object(Bucket=bucket, Key="feeds/a.json", Body=b"x"))
    wide = as_agent(backend.issue(f"{gid}w", "reporter", parse("read", f"s3://{bucket}/*"), 900))
    assert wide.get_object(Bucket=bucket, Key="feeds/b.json")
    assert denied(lambda: wide.get_object(Bucket=bucket, Key="payroll/2026.csv"))


def test_compromised_broker_cannot_escape_the_boundary(stack):
    """Limit fixed: the broker can write ANY inline policy on the ceiling role. The boundary caps it."""
    out, backend, broker = stack
    bucket, role = out["DemoBucketName"], backend.role_name
    iam = broker.client("iam")
    evil = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    iam.put_role_policy(RoleName=role, PolicyName="evil", PolicyDocument=json.dumps(evil))  # broker CAN do this
    try:
        # ...but it can't take the boundary off, or swap it, or re-point the trust policy:
        for attempt in (
            lambda: iam.delete_role_permissions_boundary(RoleName=role),
            lambda: iam.put_role_permissions_boundary(
                RoleName=role, PermissionsBoundary="arn:aws:iam::aws:policy/AdministratorAccess"
            ),
            lambda: iam.attach_role_policy(RoleName=role, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"),
            lambda: iam.update_assume_role_policy(RoleName=role, PolicyDocument=json.dumps(evil)),
        ):
            assert denied(attempt)
        # IAM's own evaluator (admin view) agrees the boundary wins over the inline Allow:
        sim = boto3.client("iam", region_name=REGION).simulate_principal_policy(
            PolicySourceArn=out["CeilingRoleArn"],
            ActionNames=["s3:GetObject", "s3:DeleteBucket"],
            ResourceArns=[f"arn:aws:s3:::{bucket}/payroll/2026.csv"],
        )
        assert {r["EvalActionName"]: r["EvalDecision"] for r in sim["EvaluationResults"]} == {
            "s3:GetObject": "implicitDeny",
            "s3:DeleteBucket": "implicitDeny",
        }
        # And a live session with an everything session policy, after propagation, still can't read payroll:
        time.sleep(15)
        sess = backend.sts.assume_role(
            RoleArn=out["CeilingRoleArn"],
            RoleSessionName="g-evil-probe",
            Policy=json.dumps(evil),
            SourceIdentity="reporter",
            Tags=[{"Key": "acb_grant", "Value": "g-evil-probe"}],
        )["Credentials"]
        s3 = as_agent(
            {
                "access_key_id": sess["AccessKeyId"],
                "secret_access_key": sess["SecretAccessKey"],
                "session_token": sess["SessionToken"],
            }
        )
        assert denied(lambda: s3.get_object(Bucket=bucket, Key="payroll/2026.csv"))
        assert denied(lambda: s3.delete_object(Bucket=bucket, Key="feeds/a.json"))
        assert s3.get_object(Bucket=bucket, Key="feeds/a.json")  # inside the boundary still works
    finally:
        iam.delete_role_policy(RoleName=role, PolicyName="evil")


def test_revocation_is_confirmed_by_canary(stack):
    out, backend, _ = stack
    bucket = out["DemoBucketName"]
    keep, kill = f"g-keep-{uuid.uuid4().hex[:8]}", f"g-kill-{uuid.uuid4().hex[:8]}"
    scope = parse("read", f"s3://{bucket}/feeds/*")
    s3_keep = as_agent(backend.issue(keep, "reporter", scope, 900))
    s3_kill = as_agent(backend.issue(kill, "reporter", scope, 900))
    assert s3_kill.get_object(Bucket=bucket, Key="feeds/a.json")
    assert backend.sync_revocations([kill])["mode"] == "list"
    took = backend.confirm_revoked(kill, "reporter")
    assert took is not None, "canary was never refused"
    print(f"\ncanary refused after {took:.1f}s")
    assert wait_denied(lambda: s3_kill.get_object(Bucket=bucket, Key="feeds/a.json"), timeout=20) is not None
    assert s3_keep.get_object(Bucket=bucket, Key="feeds/a.json")


def test_cutoff_fallback_kills_older_sessions_only(stack):
    """When the revoked list outgrows the policy budget, deny by aws:TokenIssueTime instead."""
    out, backend, broker = stack
    bucket = out["DemoBucketName"]
    scope = parse("read", f"s3://{bucket}/feeds/*")
    old = as_agent(backend.issue(f"g-old-{uuid.uuid4().hex[:8]}", "reporter", scope, 900))
    time.sleep(2)
    cutoff = datetime.now(UTC) - timedelta(seconds=1)
    broker.client("iam").put_role_policy(
        RoleName=backend.role_name,
        PolicyName=REVOCATION_POLICY,
        PolicyDocument=json.dumps(revocation_policy([], cutoff=cutoff)),
    )
    took = wait_denied(lambda: old.get_object(Bucket=bucket, Key="feeds/a.json"))
    assert took is not None
    print(f"\ncutoff took effect after {took:.1f}s")
    new = as_agent(backend.issue(f"g-new-{uuid.uuid4().hex[:8]}", "reporter", scope, 900))
    assert new.get_object(Bucket=bucket, Key="feeds/a.json")  # sessions after the cutoff are unaffected
    backend.sync_revocations([])


def test_agent_authenticates_with_its_iam_role(stack):
    """Limit fixed: no API key. The agent proves its role by signing sts:GetCallerIdentity."""
    out, _, _ = stack
    agent_sess = session_for(out["AgentTestRoleArn"], "agent-task-1")
    used: set[str] = set()

    def use_nonce(n, ttl):
        if n in used:
            return False
        used.add(n)
        return True

    v = AwsIamVerifier("acb-prod", regions=(REGION,), use_nonce=use_nonce)
    header = sign_identity_request(agent_sess, "acb-prod", REGION)
    assert v.verify(header) == out["AgentTestRoleArn"]  # session ARN normalized to the role ARN
    with pytest.raises(AuthError, match="already used"):
        v.verify(header)  # replay
    with pytest.raises(AuthError, match="different broker"):
        AwsIamVerifier("acb-staging", regions=(REGION,)).verify(sign_identity_request(agent_sess, "acb-prod", REGION))
    # Tamper with a signed header after signing -> AWS itself rejects the signature.
    # (Fresh verifier: two requests signed in the same second share a signature, and the
    # replay guard above would otherwise refuse it first, which is also correct.)
    import base64

    p = json.loads(base64.b64decode(sign_identity_request(agent_sess, "acb-prod", REGION)))
    p["headers"]["X-Amz-Date"] = p["headers"]["X-Amz-Date"][:-3] + "00Z"
    with pytest.raises(AuthError, match="rejected"):
        AwsIamVerifier("acb-prod", regions=(REGION,)).verify(base64.b64encode(json.dumps(p).encode()).decode())

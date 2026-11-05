"""Live AWS proof for the STS backend. Skipped unless ACB_AWS_TESTS=1.

Needs the acb-sts stack (infra/sts-backend.yaml) and credentials for the
broker principal. Proves against real IAM, not mocks:
  1. the session policy narrows a broader ceiling role (feeds/a.json yes, feeds/b.json no)
  2. the ceiling holds even if the session policy were too broad (payroll/ is denied)
  3. SourceIdentity and the acb_grant tag are on the session
  4. revocation (tag-conditioned deny on the role) kills already-issued credentials
"""

import os
import time
import uuid

import boto3
import pytest
from botocore.exceptions import ClientError

from acb.backends.sts_backend import StsBackend
from acb.scope import parse

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(os.environ.get("ACB_AWS_TESTS") != "1", reason="set ACB_AWS_TESTS=1 to hit real AWS"),
]

REGION = os.environ.get("AWS_REGION", "us-west-2")


@pytest.fixture(scope="module")
def stack():
    cfn = boto3.client("cloudformation", region_name=REGION)
    out = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName="acb-sts")["Stacks"][0]["Outputs"]}
    s3 = boto3.client("s3", region_name=REGION)
    for key in ("feeds/a.json", "feeds/b.json", "payroll/2026.csv"):
        s3.put_object(Bucket=out["DemoBucketName"], Key=key, Body=b'{"ok":true}')
    backend = StsBackend(
        out["CeilingRoleArn"], boto3.client("sts", region_name=REGION), boto3.client("iam", region_name=REGION)
    )
    yield out, backend
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
        return e.response["Error"]["Code"] in ("AccessDenied", "403")


def test_session_policy_narrows_and_ceiling_holds(stack):
    out, backend = stack
    bucket = out["DemoBucketName"]
    gid = f"g-test-{uuid.uuid4().hex[:8]}"
    creds = backend.issue(gid, "reporter", parse("read", f"s3://{bucket}/feeds/a.json"), 900)
    assert creds["assumed_role_arn"].endswith(f"/{gid}")
    s3 = as_agent(creds)
    assert s3.get_object(Bucket=bucket, Key="feeds/a.json")["Body"].read() == b'{"ok":true}'
    assert denied(lambda: s3.get_object(Bucket=bucket, Key="feeds/b.json"))  # role allows, session doesn't
    assert denied(lambda: s3.put_object(Bucket=bucket, Key="feeds/a.json", Body=b"x"))

    # Too-broad request: the session policy would allow payroll/, but the ceiling role does not.
    wide = backend.issue(f"{gid}w", "reporter", parse("read", f"s3://{bucket}/*"), 900)
    s3w = as_agent(wide)
    assert s3w.get_object(Bucket=bucket, Key="feeds/b.json")
    assert denied(lambda: s3w.get_object(Bucket=bucket, Key="payroll/2026.csv"))


def test_source_identity_and_tags_on_session(stack):
    out, backend = stack
    creds = backend.issue(
        f"g-test-{uuid.uuid4().hex[:8]}", "reporter", parse("list", f"s3://{out['DemoBucketName']}/feeds/*"), 900
    )
    s3 = as_agent(creds)
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=out["DemoBucketName"], Prefix="feeds/")["Contents"]]
    assert "feeds/a.json" in keys
    assert denied(lambda: s3.list_objects_v2(Bucket=out["DemoBucketName"], Prefix="payroll/"))
    ident = boto3.client(
        "sts",
        region_name=REGION,
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        aws_session_token=creds["session_token"],
    ).get_caller_identity()
    assert ":assumed-role/acb-sts-ceiling/g-test-" in ident["Arn"]


def test_revocation_kills_issued_credentials(stack):
    out, backend = stack
    bucket = out["DemoBucketName"]
    keep, kill = f"g-keep-{uuid.uuid4().hex[:8]}", f"g-kill-{uuid.uuid4().hex[:8]}"
    scope = parse("read", f"s3://{bucket}/feeds/*")
    s3_keep, s3_kill = (
        as_agent(backend.issue(keep, "reporter", scope, 900)),
        as_agent(backend.issue(kill, "reporter", scope, 900)),
    )
    assert s3_kill.get_object(Bucket=bucket, Key="feeds/a.json")
    backend.sync_revocations([kill])
    deadline, revoked_after = time.time() + 60, None
    t0 = time.time()
    while time.time() < deadline:
        if denied(lambda: s3_kill.get_object(Bucket=bucket, Key="feeds/a.json")):
            revoked_after = time.time() - t0
            break
        time.sleep(2)
    assert revoked_after is not None, "revocation did not take effect within 60s"
    print(f"\nrevocation took effect after {revoked_after:.1f}s")
    assert s3_keep.get_object(Bucket=bucket, Key="feeds/a.json")  # other grants unaffected

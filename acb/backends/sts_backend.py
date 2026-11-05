"""STS backend: real AWS credentials, narrowed per grant with a session policy.

The broker assumes one pre-created role (the "ceiling") and passes an inline
session policy built from the grant's scope. AWS grants the intersection of
the role's permissions and the session policy, so a credential can never do
more than the role allows, nor more than the grant says.

The ceiling role also carries a permissions boundary equal to its own
ceiling. The broker needs iam:PutRolePolicy on that role to push revocations,
and IAM cannot restrict that permission to one policy name, so a compromised
broker could write an Allow. The boundary makes that harmless: an inline
Allow can never exceed it, and the broker has no permission to change or
remove the boundary.

Every session carries:
- SourceIdentity = agent name (persists through role chaining, shows on every
  CloudTrail event the credential produces).
- RoleSessionName = grant id, so CloudTrail ties each call to one grant.
- Session tag acb_grant = grant id, used for revocation.

Revocation: STS credentials cannot be recalled. The broker keeps one inline
deny policy on the role listing revoked grant ids (by session tag). IAM takes
seconds to propagate, so after each revocation the broker mints a canary
session tagged with the revoked id and polls until AWS refuses it, then
records when revocation actually took effect. If the list would outgrow the
inline policy budget, the broker falls back to denying every session issued
before now (aws:TokenIssueTime), which is AWS's documented way to cut off
active sessions; legitimate agents simply ask again.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..scope import Scope

REVOCATION_POLICY = "acb-revocations"
PROBE_KEY = "acb-probe/canary"
MIN_TTL = 900
MAX_SESSION_POLICY_CHARS = 2048
# Inline role policies share a 10,240-character budget; the ceiling policy lives in a managed
# boundary + managed policy, so the revocation document may use most of it. Leave headroom.
REVOCATION_BUDGET_CHARS = 9000


def session_policy(scope: Scope) -> dict:
    """Least-privilege IAM policy for exactly one scope."""
    obj_arn = f"arn:aws:s3:::{scope.bucket}/{scope.prefix}{'*' if scope.wildcard else ''}"
    if scope.action == "read":
        stmt = {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": obj_arn}
    elif scope.action == "write":
        stmt = {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": obj_arn}
    elif scope.action == "list":
        stmt = {
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": f"arn:aws:s3:::{scope.bucket}",
            "Condition": {"StringLike": {"s3:prefix": [f"{scope.prefix}*"]}},
        }
    else:  # parse() makes this unreachable; fail closed anyway
        raise ValueError(f"no session policy for action {scope.action!r}")
    stmt["Sid"] = "AcbGrant"
    return {"Version": "2012-10-17", "Statement": [stmt]}


def revocation_policy(grant_ids: list[str], cutoff: datetime | None = None) -> dict:
    """Deny-everything for listed grants, or (fallback) for every session issued before ``cutoff``."""
    statements = []
    if grant_ids:
        statements.append(
            {
                "Sid": "AcbRevokedGrants",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/acb_grant": sorted(grant_ids)}},
            }
        )
    if cutoff is not None:
        statements.append(
            {
                "Sid": "AcbRevokeAllBefore",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")}},
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


def fit_revocations(grant_ids: list[str], now: datetime) -> tuple[dict, bool]:
    """Return (policy, used_cutoff). Falls back to a TokenIssueTime cutoff when the list is too big."""
    doc = revocation_policy(grant_ids)
    if len(json.dumps(doc, separators=(",", ":"))) <= REVOCATION_BUDGET_CHARS:
        return doc, False
    return revocation_policy([], cutoff=now), True


@dataclass
class StsBackend:
    role_arn: str
    sts: object  # boto3 STS client (as the broker principal)
    iam: object | None = None  # boto3 IAM client; needed only for revocation
    probe_bucket: str | None = None  # bucket whose acb-probe/ prefix the ceiling lets canaries read
    s3_factory: object = None  # (creds dict) -> S3 client; injectable for tests
    clock: object = field(default=time.time)

    @property
    def role_name(self) -> str:
        return self.role_arn.rsplit("/", 1)[-1]

    def _assume(self, session_name: str, agent: str, grant_id: str, policy: dict, ttl: int) -> dict:
        return self.sts.assume_role(
            RoleArn=self.role_arn,
            RoleSessionName=session_name,
            DurationSeconds=ttl,
            Policy=json.dumps(policy, separators=(",", ":")),
            SourceIdentity=agent,
            Tags=[{"Key": "acb_grant", "Value": grant_id}, {"Key": "acb_agent", "Value": agent}],
        )

    def issue(self, grant_id: str, agent: str, scope: Scope, ttl: int) -> dict:
        if ttl < MIN_TTL:
            raise ValueError(f"STS sessions last at least {MIN_TTL} seconds")
        policy = session_policy(scope)
        if len(json.dumps(policy, separators=(",", ":"))) > MAX_SESSION_POLICY_CHARS:
            raise ValueError("session policy too large")
        resp = self._assume(grant_id, agent, grant_id, policy, ttl)
        c = resp["Credentials"]
        return {
            "type": "aws_sts",
            "access_key_id": c["AccessKeyId"],
            "secret_access_key": c["SecretAccessKey"],
            "session_token": c["SessionToken"],
            "expires_at": int(c["Expiration"].timestamp()),
            "assumed_role_arn": resp["AssumedRoleUser"]["Arn"],
        }

    def sync_revocations(self, grant_ids: list[str]) -> dict:
        """Make the role's deny policy cover exactly these (still-unexpired) revoked grants."""
        if self.iam is None:
            raise RuntimeError("STS revocation needs an IAM client")
        if not grant_ids:
            try:
                self.iam.delete_role_policy(RoleName=self.role_name, PolicyName=REVOCATION_POLICY)
            except self.iam.exceptions.NoSuchEntityException:
                pass
            return {"mode": "cleared", "count": 0}
        doc, used_cutoff = fit_revocations(grant_ids, datetime.fromtimestamp(self.clock(), UTC))
        self.iam.put_role_policy(RoleName=self.role_name, PolicyName=REVOCATION_POLICY, PolicyDocument=json.dumps(doc))
        return {"mode": "cutoff" if used_cutoff else "list", "count": len(grant_ids)}

    def confirm_revoked(self, grant_id: str, agent: str, timeout: float = 90.0, interval: float = 2.0) -> float | None:
        """Mint a canary session tagged as the revoked grant and poll until AWS refuses it.

        Returns seconds until refusal, or None if it never happened within ``timeout``.
        The canary may only GetObject/ListBucket under ``acb-probe/`` in the probe bucket.
        A missing probe object answers NoSuchKey (not AccessDenied) because the canary can
        list that prefix, so only a real deny counts as confirmation.

        Measured on AWS: the tag-matched deny blocks s3:GetObject in ~9 s but did NOT
        block s3:GetBucketLocation within 90 s, so the canary uses an object call.
        """
        if not self.probe_bucket:
            return None
        from botocore.exceptions import ClientError

        bucket = f"arn:aws:s3:::{self.probe_bucket}"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "AcbProbe", "Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{bucket}/{PROBE_KEY}"},
                {
                    "Sid": "AcbProbeList",
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": bucket,
                    "Condition": {"StringLike": {"s3:prefix": ["acb-probe/*"]}},
                },
            ],
        }
        t0 = self.clock()
        # AssumeRole is governed by the trust policy, so the canary is still issued after the
        # deny lands; the deny then applies to what the session does, which is what we observe.
        c = self._assume(f"{grant_id[:56]}-probe", agent, grant_id, policy, MIN_TTL)["Credentials"]
        s3 = self.s3_factory(c) if self.s3_factory else _s3_client(c)
        while self.clock() - t0 < timeout:
            try:
                s3.get_object(Bucket=self.probe_bucket, Key=PROBE_KEY)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDenied", "403"):
                    return self.clock() - t0
                if code not in ("NoSuchKey", "404"):
                    raise
            time.sleep(interval)
        return None


def _s3_client(c: dict):
    import boto3

    return boto3.client(
        "s3",
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
    )

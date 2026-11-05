"""STS backend: real AWS credentials, narrowed per grant with a session policy.

The broker assumes one pre-created role (the "ceiling") and passes an inline
session policy built from the grant's scope. AWS evaluates the intersection
of the role's policies and the session policy, so the credentials can never
do more than the role allows, and can never do more than the grant says,
even if a bug in this code built too broad a session policy. The role's
own policy is the backstop; the session policy is the precision.

Every session carries:
- SourceIdentity = agent name. It is set once, persists through role
  chaining, and shows on every CloudTrail event the agent's calls produce.
- RoleSessionName = grant id, so CloudTrail ties each call to one grant.
- Session tag acb_grant = grant id, used for revocation (below).

Revocation: STS credentials cannot be recalled once issued. The broker keeps
an inline deny policy on the role that denies every action for sessions whose
acb_grant tag is on the revoked list. IAM changes take a few seconds to
propagate, so revocation is "within seconds", not instant; the short TTL is
the second line of defence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..scope import Scope

REVOCATION_POLICY = "acb-revocations"
MIN_TTL = 900
MAX_SESSION_POLICY_CHARS = 2048  # AWS packed-size limits apply too; keep the plaintext small


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


def revocation_policy(role_name: str, grant_ids: list[str]) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AcbRevokedGrants",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/acb_grant": sorted(grant_ids)}},
            }
        ],
    }


@dataclass
class StsBackend:
    role_arn: str
    sts: object  # boto3 STS client
    iam: object | None = None  # boto3 IAM client; needed only for revocation

    @property
    def role_name(self) -> str:
        return self.role_arn.rsplit("/", 1)[-1]

    def issue(self, grant_id: str, agent: str, scope: Scope, ttl: int) -> dict:
        if ttl < MIN_TTL:
            raise ValueError(f"STS sessions last at least {MIN_TTL} seconds")
        policy = json.dumps(session_policy(scope), separators=(",", ":"))
        if len(policy) > MAX_SESSION_POLICY_CHARS:
            raise ValueError("session policy too large")
        resp = self.sts.assume_role(
            RoleArn=self.role_arn,
            RoleSessionName=grant_id,
            DurationSeconds=ttl,
            Policy=policy,
            SourceIdentity=agent,
            Tags=[{"Key": "acb_grant", "Value": grant_id}, {"Key": "acb_agent", "Value": agent}],
        )
        c = resp["Credentials"]
        return {
            "type": "aws_sts",
            "access_key_id": c["AccessKeyId"],
            "secret_access_key": c["SecretAccessKey"],
            "session_token": c["SessionToken"],
            "expires_at": int(c["Expiration"].timestamp()),
            "assumed_role_arn": resp["AssumedRoleUser"]["Arn"],
        }

    def sync_revocations(self, grant_ids: list[str]) -> None:
        """Make the role's deny policy list exactly these (still-unexpired) revoked grants."""
        if self.iam is None:
            raise RuntimeError("STS revocation needs an IAM client")
        if not grant_ids:
            try:
                self.iam.delete_role_policy(RoleName=self.role_name, PolicyName=REVOCATION_POLICY)
            except self.iam.exceptions.NoSuchEntityException:
                pass
            return
        self.iam.put_role_policy(
            RoleName=self.role_name,
            PolicyName=REVOCATION_POLICY,
            PolicyDocument=json.dumps(revocation_policy(self.role_name, grant_ids)),
        )

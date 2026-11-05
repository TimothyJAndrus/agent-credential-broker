"""Agent authentication without shared secrets.

Three ways an agent can prove who it is; a policy may enable any of them per agent:

1. **AWS IAM** (``aws_principal``): the agent signs an ``sts:GetCallerIdentity``
   request with its own AWS credentials (an ECS task role, Lambda role, EC2
   instance profile) and sends the signed headers, not the credentials. The
   broker replays that request to STS itself and learns the caller's ARN from
   AWS. The signature covers an ``X-ACB-Server-ID`` header naming this broker,
   so a request signed for one broker can't be replayed at another, and each
   signature is accepted once. This is the pattern HashiCorp Vault's IAM auth
   method uses.
2. **OIDC** (``oidc``): a workload identity token (GitHub Actions, Kubernetes
   service account, any OIDC issuer). The broker checks signature against the
   issuer's JWKS, issuer, audience, expiry, and an exact subject match.
3. **API key** (``key_sha256``): kept for local development. Only the hash is
   stored. Disable it in production by not setting it.
"""

from __future__ import annotations

import base64
import calendar
import json
import re
import time
from dataclasses import dataclass
from xml.etree import ElementTree

import jwt

SERVER_ID_HEADER = "X-ACB-Server-ID"
STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"
MAX_SKEW = 300  # seconds either side of X-Amz-Date
_ASSUMED = re.compile(r"^arn:aws:sts::(\d{12}):assumed-role/([^/]+)/[^/]+$")


class AuthError(Exception):
    """Authentication failed. The message is safe to return."""


@dataclass(frozen=True)
class OidcRule:
    issuer: str
    audience: str
    subject: str


def normalize_arn(arn: str) -> str:
    """arn:aws:sts::123:assumed-role/Role/session -> arn:aws:iam::123:role/Role.

    Policies name roles, not sessions. Roles with a path can't be recovered
    from an assumed-role ARN (AWS drops the path), so policy role ARNs must
    be written without a path; ``policy.load`` enforces that.
    """
    m = _ASSUMED.match(arn)
    return f"arn:aws:iam::{m.group(1)}:role/{m.group(2)}" if m else arn


# ---------- AWS IAM ----------


def sign_identity_request(session, server_id: str, region: str = "us-west-2") -> str:
    """Client side: build the X-Agent-AWS-Auth header value from a boto3 Session."""
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    url = f"https://sts.{region}.amazonaws.com/"
    req = AWSRequest(
        method="POST",
        url=url,
        data=STS_BODY,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            SERVER_ID_HEADER: server_id,
        },
    )
    SigV4Auth(session.get_credentials().get_frozen_credentials(), "sts", region).add_auth(req)
    payload = {"region": region, "headers": dict(req.headers.items()), "body": STS_BODY}
    return base64.b64encode(json.dumps(payload).encode()).decode()


class AwsIamVerifier:
    def __init__(
        self, server_id: str, regions: tuple[str, ...] = ("us-west-2",), http=None, use_nonce=None, clock=time.time
    ):
        self.server_id = server_id
        self.regions = regions
        self.http = http or _post
        self.use_nonce = use_nonce  # callable(nonce, ttl) -> bool
        self.clock = clock

    def verify(self, header_value: str) -> str:
        """Return the caller's (normalized) IAM ARN, or raise AuthError."""
        try:
            payload = json.loads(base64.b64decode(header_value, validate=True))
            region, headers, body = payload["region"], payload["headers"], payload["body"]
        except (ValueError, KeyError, TypeError) as e:
            raise AuthError("malformed AWS auth header") from e
        if region not in self.regions:
            raise AuthError(f"region {region!r} not accepted")
        if body != STS_BODY:  # only ever forward GetCallerIdentity
            raise AuthError("signed request must be sts:GetCallerIdentity")
        h = {k.lower(): v for k, v in headers.items()}
        if h.get(SERVER_ID_HEADER.lower()) != self.server_id:
            raise AuthError("request was signed for a different broker")
        authz = h.get("authorization", "")
        signed = re.search(r"SignedHeaders=([^,\s]+)", authz)
        if not authz.startswith("AWS4-HMAC-SHA256 ") or not signed:
            raise AuthError("not a SigV4 signature")
        if SERVER_ID_HEADER.lower() not in signed.group(1).split(";"):
            raise AuthError("X-ACB-Server-ID must be a signed header")
        try:
            ts = calendar.timegm(time.strptime(h["x-amz-date"], "%Y%m%dT%H%M%SZ"))
        except (KeyError, ValueError) as e:
            raise AuthError("missing or bad X-Amz-Date") from e
        if abs(self.clock() - ts) > MAX_SKEW:
            raise AuthError("signed request is too old or from the future")
        sig = re.search(r"Signature=([0-9a-f]{64})", authz)
        if not sig or (self.use_nonce and not self.use_nonce("sigv4:" + sig.group(1), 2 * MAX_SKEW)):
            raise AuthError("signed request was already used")
        # The broker chooses the URL; the client only supplies signed headers.
        status, text = self.http(f"https://sts.{region}.amazonaws.com/", headers, body)
        if status != 200:
            raise AuthError(f"AWS rejected the signature (HTTP {status})")
        try:
            ns = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
            arn = ElementTree.fromstring(text).find(".//s:Arn", ns).text  # noqa: S314 (response is from AWS STS)
        except (ElementTree.ParseError, AttributeError) as e:
            raise AuthError("unexpected STS response") from e
        return normalize_arn(arn)


def _post(url: str, headers: dict, body: str) -> tuple[int, str]:
    import urllib.request

    req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (fixed https STS URL)
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


# ---------- OIDC ----------


class OidcVerifier:
    """Verifies workload identity tokens. ``jwks_for(issuer) -> PyJWKSet`` is injectable for tests."""

    def __init__(self, jwks_for=None, use_nonce=None, clock=time.time):
        self._clients: dict[str, jwt.PyJWKClient] = {}
        self.jwks_for = jwks_for or self._fetch
        self.use_nonce = use_nonce
        self.clock = clock

    def _fetch(self, issuer: str):
        if issuer not in self._clients:
            import urllib.request

            conf_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
            if not conf_url.startswith("https://"):
                raise AuthError("OIDC issuer must be https")
            with urllib.request.urlopen(conf_url, timeout=5) as r:  # noqa: S310 (https enforced above)
                jwks_uri = json.loads(r.read())["jwks_uri"]
            self._clients[issuer] = jwt.PyJWKClient(jwks_uri, cache_keys=True, lifespan=300)
        return self._clients[issuer]

    def verify(self, token: str, rules: list[tuple[str, OidcRule]]) -> str:
        """Return the agent name whose OIDC rule matches this token, or raise AuthError."""
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as e:
            raise AuthError("malformed token") from e
        iss = unverified.get("iss")
        candidates = [(name, r) for name, r in rules if r.issuer == iss]
        if not candidates:
            raise AuthError("unknown issuer")
        if header.get("alg") not in ("RS256", "ES256", "EdDSA"):
            raise AuthError("unsupported token algorithm")
        src = self.jwks_for(iss)
        key = (
            src.get_signing_key_from_jwt(token).key
            if hasattr(src, "get_signing_key_from_jwt")
            else src[header.get("kid")].key
        )
        for name, r in candidates:
            try:
                claims = jwt.decode(
                    token,
                    key,
                    algorithms=[header["alg"]],
                    audience=r.audience,
                    issuer=r.issuer,
                    options={
                        "require": ["exp", "iat", "sub"],
                        "verify_exp": False,
                        "verify_iat": False,
                        "verify_nbf": False,
                    },
                )
            except jwt.InvalidAudienceError:
                continue
            except jwt.InvalidTokenError as e:
                raise AuthError(f"invalid token: {type(e).__name__}") from e
            now = self.clock()
            if now >= claims["exp"] or now < claims.get("nbf", claims["iat"]) - 30:
                raise AuthError("token expired or not yet valid")
            if claims["sub"] != r.subject:
                continue
            jti = claims.get("jti")
            if jti and self.use_nonce and not self.use_nonce(f"oidc:{iss}:{jti}", claims["exp"] - now + 60):
                raise AuthError("token was already used")
            return name
        raise AuthError("no agent matches this token's audience and subject")


__all__ = ["AuthError", "AwsIamVerifier", "OidcRule", "OidcVerifier", "normalize_arn", "sign_identity_request"]

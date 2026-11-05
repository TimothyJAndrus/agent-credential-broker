"""JWT backend: Ed25519-signed bearer tokens that a resource server checks with the public key.

Use this when the thing the agent calls is your own service. The resource
server verifies signature, audience, expiry and scope, and asks the broker
(or a cached revocation list) whether the grant id has been revoked.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

AUDIENCE = "acb-resource"
ISSUER = "agent-credential-broker"


@dataclass
class JwtBackend:
    private_key: Ed25519PrivateKey
    kid: str = "acb-1"
    clock: object = time.time

    @classmethod
    def generate(cls, clock=time.time) -> JwtBackend:
        return cls(Ed25519PrivateKey.generate(), clock=clock)

    @classmethod
    def from_pem(cls, pem: bytes, clock=time.time) -> JwtBackend:
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("signing key must be Ed25519")
        return cls(key, clock=clock)

    def issue(self, grant_id: str, agent: str, scope, ttl: int) -> dict:
        now = int(self.clock())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": agent,
            "jti": grant_id,
            "scope": str(scope),
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
        }
        token = jwt.encode(claims, self.private_key, algorithm="EdDSA", headers={"kid": self.kid})
        return {"type": "jwt", "token": token, "expires_at": now + ttl}

    def public_jwk(self) -> dict:
        raw = self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        return {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": self.kid, "alg": "EdDSA", "use": "sig"}

    def verify(self, token: str) -> dict:
        """Signature, issuer, audience, then nbf/exp against the broker's clock (not wall time).

        Raises jwt.InvalidTokenError on any failure.
        """
        claims = jwt.decode(
            token,
            self.private_key.public_key(),
            algorithms=["EdDSA"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "require": ["exp", "nbf", "jti", "scope", "sub"],
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
        )
        now = self.clock()
        if now < claims["nbf"]:
            raise jwt.ImmatureSignatureError("token not yet valid")
        if now >= claims["exp"]:
            raise jwt.ExpiredSignatureError("token expired")
        return claims

    def revoke(self, grant_id: str) -> None:
        """JWT revocation is enforced at introspection time from the grant store; nothing to push."""

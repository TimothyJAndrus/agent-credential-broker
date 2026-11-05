"""acb: small operator CLI.

python -m acb.cli hash-key            # make a new API key and the sha256 for policy.yaml
python -m acb.cli gen-signing-key PATH
python -m acb.cli verify-audit PATH   # exit 1 if the hash chain is broken
python -m acb.cli check-policy PATH
"""

from __future__ import annotations

import hashlib
import secrets
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd, *rest = argv
    if cmd == "hash-key":
        key = rest[0] if rest else "acb_" + secrets.token_urlsafe(32)
        print(f"key:        {key}\nkey_sha256: {hashlib.sha256(key.encode()).hexdigest()}")
        return 0
    if cmd == "gen-signing-key" and rest:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pem = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        p = Path(rest[0])
        p.write_bytes(pem)
        p.chmod(0o600)
        print(f"wrote {p} (mode 600)")
        return 0
    if cmd == "verify-audit" and rest:
        from .audit import AuditLog

        ok, n, msg = AuditLog(rest[0]).verify()
        print(f"{'OK' if ok else 'BROKEN'}: {n} line(s) checked: {msg}")
        return 0 if ok else 1
    if cmd == "check-policy" and rest:
        from .policy import PolicyError, load

        try:
            p = load(rest[0])
        except PolicyError as e:
            print(f"invalid: {e}")
            return 1
        rules = sum(len(r) for r in p.agents.values())
        print(f"valid: {len(p.agents)} agent(s), {rules} rule(s), {len(p.approvers)} approver(s)")
        for w in p.warnings:
            print(f"warning: {w}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

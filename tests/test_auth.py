"""Agent auth without shared secrets: IAM (signed GetCallerIdentity) and OIDC. Offline.

The live counterpart (real STS verifying a real signature) is in test_aws_live.py.
"""

import base64
import json
import textwrap
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from fastapi.testclient import TestClient

from acb.app import create_app
from acb.audit import AuditLog
from acb.auth import AuthError, AwsIamVerifier, OidcRule, OidcVerifier, normalize_arn
from acb.backends.jwt_backend import JwtBackend
from acb.policy import PolicyError, load
from acb.store import SqliteStore

ROLE = "arn:aws:iam::123456789012:role/support-bot-task"
STS_OK = """<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/support-bot-task/ecs-task-1</Arn>
</GetCallerIdentityResult></GetCallerIdentityResponse>"""


def signed(server_id="acb-prod", when=None, sig="a" * 64, region="us-west-2", body=None, signed_headers=None):
    when = when or time.gmtime()
    sh = signed_headers or "content-type;host;x-acb-server-id;x-amz-date"
    headers = {
        "X-ACB-Server-ID": server_id,
        "X-Amz-Date": time.strftime("%Y%m%dT%H%M%SZ", when),
        "Authorization": f"AWS4-HMAC-SHA256 Credential=ASIA/x, SignedHeaders={sh}, Signature={sig}",
    }
    payload = {"region": region, "headers": headers, "body": body or "Action=GetCallerIdentity&Version=2011-06-15"}
    return base64.b64encode(json.dumps(payload).encode()).decode()


class FakeSTS:
    def __init__(self, status=200, text=STS_OK):
        self.status, self.text, self.urls = status, text, []

    def __call__(self, url, headers, body):
        self.urls.append(url)
        return self.status, self.text


def verifier(http=None, **kw):
    used = set()

    def nonce(n, ttl):
        return not (n in used or used.add(n))

    return AwsIamVerifier("acb-prod", http=http or FakeSTS(), use_nonce=nonce, **kw)


def test_iam_happy_path_normalizes_session_to_role():
    assert verifier().verify(signed()) == ROLE
    assert normalize_arn("arn:aws:iam::1:user/bob") == "arn:aws:iam::1:user/bob"


@pytest.mark.parametrize(
    "header,match",
    [
        (signed(server_id="acb-staging"), "different broker"),
        (signed(when=time.gmtime(time.time() - 3600)), "too old"),
        (signed(region="us-east-1"), "region"),
        (signed(body="Action=AssumeRole&RoleArn=x"), "GetCallerIdentity"),
        (signed(signed_headers="host;x-amz-date"), "must be a signed header"),
        ("not-base64!", "malformed"),
    ],
)
def test_iam_rejections(header, match):
    with pytest.raises(AuthError, match=match):
        verifier().verify(header)


def test_iam_replay_and_aws_rejection():
    v = verifier()
    h = signed()
    v.verify(h)
    with pytest.raises(AuthError, match="already used"):
        v.verify(h)
    with pytest.raises(AuthError, match="rejected"):
        verifier(http=FakeSTS(status=403, text="<Error/>")).verify(signed(sig="b" * 64))


def test_iam_broker_chooses_the_sts_url():
    """The client can't point the broker at its own fake STS: only region is taken from the request."""
    sts = FakeSTS()
    verifier(http=sts).verify(signed())
    assert sts.urls == ["https://sts.us-west-2.amazonaws.com/"]


# ---------- OIDC ----------

ISS = "https://token.actions.githubusercontent.com"
SUB = "repo:TimothyJAndrus/agent-credential-broker:ref:refs/heads/main"


@pytest.fixture
def oidc():
    key = generate_private_key(SECP256R1())

    class Jwks:
        def __getitem__(self, kid):
            assert kid == "k1"
            return type("K", (), {"key": key.public_key()})

    used = set()
    v = OidcVerifier(jwks_for=lambda iss: Jwks(), use_nonce=lambda n, t: not (n in used or used.add(n)))

    def tok(**over):
        now = int(time.time())
        claims = {"iss": ISS, "aud": "acb-prod", "sub": SUB, "iat": now, "exp": now + 300, "jti": str(now), **over}
        return jwt.encode(claims, over.pop("_key", key), algorithm="ES256", headers={"kid": "k1"})

    rules = [("ci-bot", OidcRule(ISS, "acb-prod", SUB))]
    return v, tok, rules


def test_oidc_happy_and_replay(oidc):
    v, tok, rules = oidc
    t = tok(jti="once")
    assert v.verify(t, rules) == "ci-bot"
    with pytest.raises(AuthError, match="already used"):
        v.verify(t, rules)


@pytest.mark.parametrize(
    "over,match",
    [
        ({"aud": "someone-else"}, "no agent matches"),
        ({"sub": "repo:TimothyJAndrus/agent-credential-broker:ref:refs/heads/evil"}, "no agent matches"),
        ({"iss": "https://evil.example.com"}, "unknown issuer"),
        ({"exp": int(time.time()) - 10}, "expired"),
    ],
)
def test_oidc_rejections(oidc, over, match):
    v, tok, rules = oidc
    with pytest.raises(AuthError, match=match):
        v.verify(tok(**over), rules)


def test_oidc_wrong_key_and_alg_none(oidc):
    v, tok, rules = oidc
    other = generate_private_key(SECP256R1())
    now = int(time.time())
    claims = {"iss": ISS, "aud": "acb-prod", "sub": SUB, "iat": now, "exp": now + 300}
    with pytest.raises(AuthError, match="invalid token"):
        v.verify(jwt.encode(claims, other, algorithm="ES256", headers={"kid": "k1"}), rules)
    with pytest.raises(AuthError, match="algorithm"):
        v.verify(jwt.encode(claims, None, algorithm="none"), rules)


# ---------- policy + HTTP wiring ----------


def test_policy_auth_methods(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("version: 1\nagents:\n  a:\n    rules: []\n")
    with pytest.raises(PolicyError, match="no way to authenticate"):
        load(p)
    p.write_text("version: 1\nagents:\n  a:\n    aws_principals: ['arn:aws:iam::1:role/x']\n")
    with pytest.raises(PolicyError, match="without a path"):
        load(p)  # 1-digit account
    p.write_text("version: 1\nagents:\n  a:\n    aws_principals: ['arn:aws:iam::123456789012:role/team/x']\n")
    with pytest.raises(PolicyError, match="without a path"):
        load(p)
    p.write_text(f"version: 1\nagents:\n  a:\n    oidc: [{{issuer: '{ISS}', audience: x, subject: 'repo:*'}}]\n")
    with pytest.raises(PolicyError, match="exact"):
        load(p)


def test_http_iam_auth_end_to_end(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text(
        textwrap.dedent(f"""\
        version: 1
        server_id: acb-prod
        agents:
          support-bot:
            aws_principals: ['{ROLE}']
            rules:
              - {{action: read, resource: "s3://acme-data/kb/*"}}
        """)
    )
    pol = load(p)
    store = SqliteStore()
    audit = AuditLog(tmp_path / "a.jsonl")
    app = create_app(
        pol,
        store,
        audit,
        JwtBackend.generate(),
        aws_verifier=AwsIamVerifier("acb-prod", http=FakeSTS(), use_nonce=store.use_nonce),
    )
    c = TestClient(app)
    body = {"action": "read", "resource": "s3://acme-data/kb/a.md", "justification": "ticket"}
    h = signed()
    r = c.post("/v1/grants", headers={"X-Agent-AWS-Auth": h}, json=body)
    assert r.status_code == 201 and r.json()["grant"]["agent"] == "support-bot"
    assert c.post("/v1/grants", headers={"X-Agent-AWS-Auth": h}, json=body).status_code == 401  # replay
    assert c.post("/v1/grants", headers={"X-Agent-Key": "anything"}, json=body).status_code == 401  # no key set
    events = [r["event"] for r in audit.records()]
    assert events == ["grant.requested", "grant.issued", "auth.failed"]

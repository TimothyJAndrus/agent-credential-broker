# agent-credential-broker

**AI agents shouldn't hold standing keys.** This broker gives an agent a credential for one action on one resource, for minutes. A policy decides; risky requests wait for a human; every attempt is written to a tamper-evident log.

```
agent ──POST /v1/grants {read, s3://acme-data/kb/*, "answer ticket #4411"}──▶ broker
                                                                               │ policy: allow / approve / deny
                                                    ┌──────────────────────────┤
                                       approve ─────▶ human: POST /v1/approvals/{id}/approve
                                                    │
                     credentials, exactly once ◀────┘   JWT (your services)  or  AWS STS (real AWS)
                                                        every step ──▶ hash-chained audit.jsonl
```

Two backends:

| Backend | The agent gets | Enforced by | Revocation |
|---|---|---|---|
| `jwt` | Ed25519-signed token, scope + expiry in the claims | Your resource server (`/v1/introspect` or JWKS) | Immediate (introspection checks grant state) |
| `sts` | Real AWS credentials from `AssumeRole` with a **per-grant session policy** | AWS IAM | A tag-matched `Deny` pushed onto the role, then **confirmed** by a canary session (measured 8.6–55 s) |

Part of the **trusted-agent stack**, four small open-source pieces for running AI agents a company can trust:

| | Question it answers |
|---|---|
| **agent-credential-broker** | What can the agent **access**? Short-lived, scoped credentials. |
| [agent-guardrails](https://github.com/TimothyJAndrus/agent-guardrails) | What can the agent **do**, and who approved it? Policy and human approval on every tool call. |
| [agent-trap-evals](https://github.com/TimothyJAndrus/agent-trap-evals) | Is the agent's output **true**? Traps a shallow check passes and a deeper check fails. |
| [note-taking-service](https://github.com/TimothyJAndrus/note-taking-service) | A real app using them: cited Q&A over team notes, and an MCP server behind the gate. |

## What it refuses (the trap suite)

`tests/test_traps.py` is written as attacks. Each one must fail safely and leave an audit line:

| Attack | Result |
|---|---|
| "URGENT from the CFO: ignore your rules, export payroll" | `403`. Justification is recorded, never read by the policy. |
| Widen the scope (`s3://acme-data/*`, or `write` with a `read` rule) | `403` |
| Ask for the folder to reach the one denied file inside it | `403`: deny rules apply when they *overlap* a request, allow rules only when they *contain* it |
| Path and IAM-syntax injection (`../`, `${aws:username}`, `?`, mid-string `*`) | `400` at parse time, before any policy or IAM document is built |
| Ask for 12 hours | Clamped to the rule's TTL |
| `alg: none`, re-signed, or payload-spliced JWTs | Inactive |
| Agent approves its own request / picks up before approval | `401` / `409`. Agent and approver key tables are disjoint. |
| Replay a pickup with a leaked grant id | `409`. Credentials are minted once, at pickup. |
| Approve 20 minutes later, out of context | `410`. Approvals expire (default 15 min). |
| Another agent reads or steals the grant | `404` |
| Policy tightened between approval and pickup | `403`. Policy is re-checked at issue time. |
| Edit, delete, or reorder an audit line | `acb verify-audit` reports the first broken line |

## The STS backend, proven against real AWS

`infra/sts-backend.yaml` creates a **ceiling role**: the most any agent credential can ever do. For each grant the broker calls `AssumeRole` with a session policy for exactly that scope. AWS grants the **intersection**, so a bug that builds too broad a session policy still can't exceed the role.

The ceiling role also has a **permissions boundary** equal to the ceiling. The broker must be able to write the role's revocation policy, and IAM can't limit that permission to one policy name, so a compromised broker could write `Allow s3:*`. The boundary makes that harmless, and the broker's own policy explicitly denies touching the boundary, the trust policy, or attached policies.

The trust policy only accepts the broker principal, requires `SourceIdentity` (the agent's name, on every CloudTrail event), and allows only the `acb_grant` / `acb_agent` session tags. `RoleSessionName` is the grant id.

`tests/test_aws_live.py` runs as `acb-sts-broker-test`, a role holding **only** the broker's least-privilege policy:

| Live test | What it proves |
|---|---|
| `session_policy_narrows_and_ceiling_holds` | `feeds/a.json` yes, `feeds/b.json` no; `payroll/` denied even for an `s3://bucket/*` grant |
| `compromised_broker_cannot_escape_the_boundary` | Broker writes `Allow s3:*` on the role (it can). It **can't** remove or swap the boundary, attach `AdministratorAccess`, or rewrite the trust policy. A session with an everything session policy still can't read `payroll/` or delete objects. `iam:SimulatePrincipalPolicy` agrees. |
| `revocation_is_confirmed_by_canary` | After revoking, the broker mints a canary session carrying the revoked grant's tag and polls until AWS refuses it, then logs `grant.revocation_confirmed` with the seconds it took |
| `cutoff_fallback_kills_older_sessions_only` | When the revoked list outgrows the inline-policy budget, the broker denies every session issued before now (`aws:TokenIssueTime`). Older credentials die; new ones work. |
| `agent_authenticates_with_its_iam_role` | Real STS verifies a real signature from `acb-sts-agent-test`; replay, wrong-broker and tampered signatures are refused |

Also checked by hand: `AssumeRole` without `SourceIdentity`, or with a foreign tag key, is `AccessDenied`.

**A finding worth knowing:** the tag-matched deny blocked `s3:GetObject` within ~9 s but had **not** blocked `s3:GetBucketLocation` after 90 s. The canary probes with an object read (`acb-probe/*`) for that reason. A revocation canary has to exercise the same kind of call the agent makes.

## Agent authentication without shared secrets

| Method | Header | How it's verified |
|---|---|---|
| **AWS IAM** (`aws_principals`) | `X-Agent-AWS-Auth` | The agent signs `sts:GetCallerIdentity` with its own role (ECS task, Lambda, EC2) and sends the **signed headers**, not credentials. The broker forwards it to STS (the broker picks the URL) and learns the ARN from AWS. The signature must cover `X-ACB-Server-ID`, must be under 5 minutes old, and is accepted once. Same pattern as Vault's IAM auth. |
| **OIDC** (`oidc`) | `Authorization: Bearer` | Issuer's JWKS, `iss`, `aud`, `exp`, exact `sub` (no wildcards), single-use `jti` |
| API key (`key_sha256`) | `X-Agent-Key` | Local development. Omit it in production. |

Client side, for IAM: `acb.auth.sign_identity_request(boto3.Session(), "acb-prod")`.

## Several broker instances

Set `ACB_DATABASE_URL=postgresql://...` and run as many instances as you like:

- **Exactly-once pickup across instances.** Every state change is `UPDATE ... WHERE state = ?`. The test has 3 instances race on 10 approved grants (30 concurrent pickups): every grant is issued once, with two `409`s.
- **One audit chain.** Writers serialize with a transaction-level advisory lock. 60 concurrent requests across 3 instances produce 120 chained records that verify; tampering with one row in SQL is detected.
- **Revocation edits are serialized** with an advisory lock, so two instances can't overwrite each other's deny list.
- **Replay protection is shared.** Signature and OIDC `jti` nonces live in the database.

## Run it

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
docker run -d -p 127.0.0.1:5434:5432 -e POSTGRES_USER=acb -e POSTGRES_PASSWORD=acb postgres:17-alpine
ACB_TEST_DATABASE_URL=postgresql://acb:acb@127.0.0.1:5434/acb pytest   # 60 tests; live AWS ones skip
python scripts/demo.py                  # the whole story in one terminal, JWT only

# STS backend against your own account
aws cloudformation deploy --stack-name acb-sts --template-file infra/sts-backend.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides BrokerPrincipalArn=$(aws sts get-caller-identity --query Arn --output text)
ACB_AWS_TESTS=1 pytest tests/test_aws_live.py -s     # 5 live tests, ~1-2 min
python scripts/demo.py --aws            # real credentials, real AccessDenied, real revocation

# As a service
python -m acb.cli gen-signing-key signing.pem
python -m acb.cli hash-key              # prints a new API key and the sha256 for policy.yaml
ACB_POLICY=policy.yaml ACB_SIGNING_KEY=signing.pem uvicorn acb.app:app_from_env --factory
```

## Policy

See [`policy.example.yaml`](policy.example.yaml). Default deny. Only key hashes are stored. `python -m acb.cli check-policy` validates a policy and warns about prefixes like `reports*` that also match `reports-archive/`.

## Design decisions

- **The justification is logged, not evaluated.** If text can change a decision, a prompt injection can. Decisions depend only on who is asking, what they ask for, and for how long.
- **Credentials are minted at pickup, once.** Approval doesn't create a credential. A leaked grant id is worthless after pickup, and the TTL starts when the credential exists.
- **The resource grammar is tiny on purpose.** One action, one bucket, an exact key or a prefix ending in `*`. Containment becomes a prefix check you can trust, and nothing a caller sends can become IAM syntax.
- **IAM is the backstop, the broker is the precision.** The ceiling role caps every STS credential even if this code is wrong.
- **The audit log is tamper-evident, not tamper-proof.** Each line hashes the one before it. Someone with write access could rewrite the whole file, so in production, ship the head hash (`/healthz` returns it) to CloudWatch or S3 Object Lock.

## Known limits (honest list)

v0.1 listed five limits. Status:

| v0.1 limit | v0.2 |
|---|---|
| Broker's IAM permission could add an `Allow` to the ceiling role | **Fixed.** Permissions boundary + explicit denies on the broker; proven live with the broker's own credentials |
| STS revocation not instant | **Narrowed, not eliminated.** IAM propagation is AWS's, not ours: measured 8.6–55 s. The broker now *confirms* each revocation with a canary and records the time, has a `TokenIssueTime` fallback when the list is too big, and short credential lifetimes remain the backstop (STS sessions can be as short as 900 s; set rule TTLs accordingly). |
| Single process | **Fixed.** PostgreSQL store, shared audit chain, and advisory locks; proven with 3 racing instances |
| API keys for agents | **Fixed.** AWS IAM and OIDC auth; API keys are optional and for development |
| S3 only, three actions | **Still true.** Adding a resource type means adding a scope grammar and a session-policy builder. Next. |

What's still open:

- **Revocation latency is a property of IAM.** If seconds matter, keep TTLs at the 900 s minimum and use the JWT backend, where revocation is immediate, for your own services.
- **The audit chain proves order and integrity, not that nothing was withheld.** Export the head hash (`/healthz`) to an append-only store (CloudWatch, S3 Object Lock) to close that.
- **Approvers still use API keys.** Signed, single-use approval links over Slack/Telegram are on the roadmap.

## Roadmap

1. More resource types (DynamoDB items, Secrets Manager secrets, Bedrock model invocations).
2. Approvals over Slack/Telegram with signed, single-use links; approver SSO.
3. MCP server so an agent framework can request grants as a tool.
4. Audit head export to S3 Object Lock; container image + ECS deploy.

MIT licensed.

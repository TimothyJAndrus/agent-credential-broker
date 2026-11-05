"""HTTP API.

Agents authenticate with X-Agent-Key, approvers with X-Approver-Key. The two
key tables are disjoint, so no credential can both ask and approve.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .audit import AuditLog
from .backends.jwt_backend import JwtBackend
from .backends.sts_backend import StsBackend
from .policy import Policy, evaluate, load
from .scope import ScopeError, parse
from .store import Store

log = logging.getLogger("acb")


class GrantRequest(BaseModel):
    action: str = Field(examples=["read"])
    resource: str = Field(examples=["s3://acme-data/reports/*"])
    ttl_seconds: int = Field(default=900, ge=1, le=43200)
    justification: str = Field(min_length=1, max_length=500)


class DecisionBody(BaseModel):
    note: str = Field(default="", max_length=500)


class IntrospectBody(BaseModel):
    token: str


def create_app(
    policy: Policy,
    store: Store,
    audit: AuditLog,
    jwt_backend: JwtBackend,
    sts_backend: StsBackend | None = None,
    clock=time.time,
    approval_window: int = 900,
) -> FastAPI:
    app = FastAPI(title="Agent Credential Broker", version=__version__)
    for w in policy.warnings:
        log.warning("policy: %s", w)

    def agent(x_agent_key: str = Header(default="")) -> str:
        name = policy.authenticate(x_agent_key, "agent") if x_agent_key else None
        if not name:
            raise HTTPException(401, "unknown agent key")
        return name

    def approver(x_approver_key: str = Header(default="")) -> str:
        name = policy.authenticate(x_approver_key, "approver") if x_approver_key else None
        if not name:
            raise HTTPException(401, "unknown approver key")
        return name

    def backend_for(name: str):
        if name == "jwt":
            return jwt_backend
        if sts_backend is None:
            raise HTTPException(503, "STS backend is not configured")
        return sts_backend

    def view(g) -> dict:
        return {
            "id": g.id,
            "agent": g.agent,
            "scope": g.scope,
            "backend": g.backend,
            "ttl_seconds": g.ttl,
            "state": g.state,
            "justification": g.justification,
            "approve_by": g.approve_by,
            "decided_by": g.decided_by,
            "expires_at": g.expires_at,
        }

    def mint(g) -> dict:
        """Issue credentials for an allowed/approved grant, exactly once."""
        action, _, resource = g.scope.partition(":")
        scope = parse(action, resource)
        # Policy may have changed since the request; re-check at the moment of issue.
        d = evaluate(policy, g.agent, scope, g.ttl)
        if d.decision == "deny":
            store.transition(g.id, g.state, "denied", decided_by="policy")
            audit.write("grant.denied_at_issue", grant=g.id, agent=g.agent, scope=g.scope, reason=d.reason)
            raise HTTPException(403, f"denied at issue: {d.reason}")
        now = clock()
        if not store.transition(g.id, g.state, "issued", issued_at=now, expires_at=now + d.ttl):
            raise HTTPException(409, "credentials for this grant were already issued")
        try:
            creds = backend_for(g.backend).issue(g.id, g.agent, scope, d.ttl)
        except HTTPException:
            raise
        except Exception as e:  # backend failure: record it, return no partial credentials
            store.transition(g.id, "issued", "denied", decided_by="backend-error")
            audit.write("grant.issue_failed", grant=g.id, agent=g.agent, error=type(e).__name__)
            log.exception("backend issue failed for %s", g.id)
            raise HTTPException(502, "credential backend failed") from e
        audit.write(
            "grant.issued",
            grant=g.id,
            agent=g.agent,
            scope=g.scope,
            backend=g.backend,
            ttl=d.ttl,
            expires_at=creds["expires_at"],
        )
        return {"grant": view(store.get(g.id)), "credentials": creds}

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__, "audit_head": audit.head}

    @app.get("/.well-known/jwks.json")
    def jwks():
        return {"keys": [jwt_backend.public_jwk()]}

    @app.post("/v1/grants", status_code=201)
    def request_grant(body: GrantRequest, who: str = Depends(agent)):
        try:
            scope = parse(body.action, body.resource)
        except ScopeError as e:
            audit.write("grant.rejected", agent=who, action=body.action, resource=body.resource, reason=str(e))
            raise HTTPException(400, str(e)) from e
        d = evaluate(policy, who, scope, body.ttl_seconds)
        common = {
            "agent": who,
            "scope": str(scope),
            "justification": body.justification,
            "requested_ttl": body.ttl_seconds,
        }
        if d.decision == "deny":
            audit.write("grant.denied", reason=d.reason, **common)
            raise HTTPException(403, d.reason)
        state = "approved" if d.decision == "allow" else "pending"
        g = store.create(who, str(scope), d.backend, d.ttl, body.justification, state, approval_window)
        audit.write("grant.requested", grant=g.id, decision=d.decision, ttl=d.ttl, backend=d.backend, **common)
        if state == "pending":
            nxt = "wait for approval, then POST /v1/grants/{id}/credentials"
            return JSONResponse(status_code=202, content={"grant": view(g), "next": nxt})
        return mint(g)

    @app.get("/v1/grants/{grant_id}")
    def get_grant(grant_id: str, who: str = Depends(agent)):
        g = store.get(grant_id)
        if not g or g.agent != who:
            raise HTTPException(404, "no such grant")
        return view(g)

    @app.post("/v1/grants/{grant_id}/credentials")
    def pickup(grant_id: str, who: str = Depends(agent)):
        g = store.get(grant_id)
        if not g or g.agent != who:
            raise HTTPException(404, "no such grant")
        if g.state == "issued":
            audit.write("grant.replay_blocked", grant=g.id, agent=who)
            raise HTTPException(409, "credentials for this grant were already issued")
        if g.state != "approved":
            raise HTTPException(409, f"grant is {g.state}, not approved")
        return mint(g)

    @app.post("/v1/grants/{grant_id}/revoke")
    def revoke_by_agent(grant_id: str, who: str = Depends(agent)):
        g = store.get(grant_id)
        if not g or g.agent != who:
            raise HTTPException(404, "no such grant")
        return _revoke(g, who)

    def _revoke(g, who: str) -> dict:
        frm = g.state
        if frm not in ("pending", "approved", "issued"):
            raise HTTPException(409, f"grant is already {frm}")
        if not store.transition(g.id, frm, "revoked", decided_by=who):
            raise HTTPException(409, "grant changed state; retry")
        pushed = None
        if frm == "issued" and g.backend == "sts":
            try:
                backend_for("sts").sync_revocations(store.revoked_unexpired("sts"))
                pushed = True
            except Exception:
                log.exception("STS revocation sync failed")
                pushed = False
        audit.write("grant.revoked", grant=g.id, agent=g.agent, by=who, was=frm, sts_deny_pushed=pushed)
        return {"grant": view(store.get(g.id)), "sts_deny_pushed": pushed}

    @app.get("/v1/approvals")
    def approvals(who: str = Depends(approver)):
        now = clock()
        return {"pending": [view(g) for g in store.pending() if g.approve_by and g.approve_by > now]}

    @app.post("/v1/approvals/{grant_id}/approve")
    def approve(grant_id: str, body: DecisionBody | None = None, who: str = Depends(approver)):
        g = store.get(grant_id)
        if not g:
            raise HTTPException(404, "no such grant")
        if g.state != "pending":
            raise HTTPException(409, f"grant is {g.state}, not pending")
        if g.approve_by is not None and clock() > g.approve_by:
            store.transition(g.id, "pending", "denied", decided_by="expired")
            audit.write("grant.approval_expired", grant=g.id, agent=g.agent, by=who)
            raise HTTPException(410, "approval window closed; the agent must ask again")
        if not store.transition(g.id, "pending", "approved", decided_by=who):
            raise HTTPException(409, "grant changed state; retry")
        audit.write("grant.approved", grant=g.id, agent=g.agent, scope=g.scope, by=who, note=body.note if body else "")
        return view(store.get(g.id))

    @app.post("/v1/approvals/{grant_id}/deny")
    def deny(grant_id: str, body: DecisionBody | None = None, who: str = Depends(approver)):
        g = store.get(grant_id)
        if not g:
            raise HTTPException(404, "no such grant")
        if not store.transition(g.id, "pending", "denied", decided_by=who):
            raise HTTPException(409, f"grant is {g.state}, not pending")
        note = body.note if body else ""
        audit.write("grant.denied_by_human", grant=g.id, agent=g.agent, scope=g.scope, by=who, note=note)
        return view(store.get(g.id))

    @app.post("/v1/approvals/{grant_id}/revoke")
    def revoke_by_approver(grant_id: str, who: str = Depends(approver)):
        g = store.get(grant_id)
        if not g:
            raise HTTPException(404, "no such grant")
        return _revoke(g, who)

    @app.post("/v1/introspect")
    def introspect(body: IntrospectBody):
        """For resource servers: is this JWT valid right now, and what may it do?"""
        try:
            claims = jwt_backend.verify(body.token)
        except jwt.InvalidTokenError as e:
            return {"active": False, "reason": type(e).__name__}
        g = store.get(claims["jti"])
        if not g or g.state != "issued":
            return {"active": False, "reason": "revoked" if g and g.state == "revoked" else "unknown grant"}
        if g.agent != claims["sub"] or g.scope != claims["scope"]:
            return {"active": False, "reason": "token does not match its grant"}
        return {"active": True, "sub": claims["sub"], "scope": claims["scope"], "exp": claims["exp"], "grant": g.id}

    return app


def app_from_env() -> FastAPI:
    """uvicorn entrypoint: ``uvicorn acb.app:app_from_env --factory``."""
    logging.basicConfig(level=os.environ.get("ACB_LOG_LEVEL", "INFO"))
    policy = load(os.environ.get("ACB_POLICY", "policy.yaml"))
    data = Path(os.environ.get("ACB_DATA_DIR", "data"))
    data.mkdir(parents=True, exist_ok=True)
    key_path = os.environ.get("ACB_SIGNING_KEY")
    if key_path:
        jb = JwtBackend.from_pem(Path(key_path).read_bytes())
    else:
        log.warning("ACB_SIGNING_KEY not set: using an ephemeral key; tokens die with the process")
        jb = JwtBackend.generate()
    sts = None
    if policy.sts_role_arn:
        import boto3

        session = boto3.Session(region_name=policy.sts_region)
        sts = StsBackend(policy.sts_role_arn, session.client("sts"), session.client("iam"))
    return create_app(
        policy,
        Store(str(data / "grants.db")),
        AuditLog(data / "audit.jsonl"),
        jb,
        sts,
        approval_window=int(os.environ.get("ACB_APPROVAL_WINDOW", "900")),
    )

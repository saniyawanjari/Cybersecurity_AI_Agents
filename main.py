"""Supervisor: Capability-Based Autonomous Agent Authorization Framework with Audit Log."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import ipaddress
import os
from typing import Optional, List

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

import agent_a
import agent_b
import audit
from config import settings
from db import get_db, init_db
from models import AuditLog, RevokedToken
import soc_tools


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables on application startup."""
    init_db()
    yield


app = FastAPI(
    title="SOC Agent Framework Supervisor",
    version="phase-5",
    description="Capability-based supervisor for autonomous cybersecurity agents with tamper-evident audit logging.",
    lifespan=lifespan,
)


class BlockRequest(BaseModel):
    ip: str


class IsolateRequest(BaseModel):
    host: str


class RevokeTokenRequest(BaseModel):
    jti: str


def require_admin(x_admin_key: Optional[str] = Header(default=None)):
    """Enforce admin authorization using x-admin-key header."""
    if not x_admin_key or x_admin_key != settings.ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing admin key")
    return x_admin_key


# =====================================================================
# Agent Endpoints (Protected by Supervisor OPA Enforcement & Audit Log)
# =====================================================================


@app.get("/api/v1/agent-a/report")
def get_agent_a_report(
    response: Response,
    x_agent_role: Optional[str] = Header(default=None),
    x_agent_did: Optional[str] = Header(default=None),
    x_token_jti: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Agent A - Log Analyst report endpoint. Requires 'read_logs' on 'server_logs.txt'."""
    decision_ms = audit.enforce(
        db=db,
        role=x_agent_role,
        action="read_logs",
        resource="server_logs.txt",
        agent_did=x_agent_did,
        token_jti=x_token_jti,
        auth_header=authorization,
    )
    response.headers["X-Decision-Time-ms"] = f"{decision_ms:.2f}"
    return agent_a.analyze_logs() if hasattr(agent_a, "analyze_logs") else agent_a.run_analysis()


@app.get("/api/v1/agent-b/threats")
def get_agent_b_threats(
    response: Response,
    x_agent_role: Optional[str] = Header(default=None),
    x_agent_did: Optional[str] = Header(default=None),
    x_token_jti: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Agent B - Threat Detector threats endpoint. Requires read_logs and report_threat."""
    d1 = audit.enforce(
        db=db,
        role=x_agent_role,
        action="read_logs",
        resource="server_logs.txt",
        agent_did=x_agent_did,
        token_jti=x_token_jti,
        auth_header=authorization,
    )
    d2 = audit.enforce(
        db=db,
        role=x_agent_role,
        action="report_threat",
        resource="threats",
        agent_did=x_agent_did,
        token_jti=x_token_jti,
        auth_header=authorization,
    )
    response.headers["X-Decision-Time-ms"] = f"{(d1 + d2):.2f}"
    report = agent_a.analyze_logs() if hasattr(agent_a, "analyze_logs") else agent_a.run_analysis()
    return agent_b.detect_threats(report)


@app.post("/api/v1/agent-c/block")
def post_agent_c_block(
    payload: BlockRequest,
    response: Response,
    x_agent_role: Optional[str] = Header(default=None),
    x_agent_did: Optional[str] = Header(default=None),
    x_token_jti: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Agent C - Incident Responder: block suspicious IP. Requires 'block_ip' on requested IP."""
    try:
        ipaddress.ip_address(payload.ip)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid IP address format: '{payload.ip}'"
        )

    decision_ms = audit.enforce(
        db=db,
        role=x_agent_role,
        action="block_ip",
        resource=payload.ip,
        agent_did=x_agent_did,
        token_jti=x_token_jti,
        auth_header=authorization,
    )
    response.headers["X-Decision-Time-ms"] = f"{decision_ms:.2f}"

    try:
        return soc_tools.block_ip(payload.ip)
    except PermissionError as err:
        raise HTTPException(status_code=403, detail=str(err))


@app.post("/api/v1/agent-c/isolate")
def post_agent_c_isolate(
    payload: IsolateRequest,
    response: Response,
    x_agent_role: Optional[str] = Header(default=None),
    x_agent_did: Optional[str] = Header(default=None),
    x_token_jti: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Agent C - Incident Responder: isolate compromised host."""
    host = payload.host.strip()
    if not host:
        raise HTTPException(status_code=422, detail="Host parameter cannot be empty")

    decision_ms = audit.enforce(
        db=db,
        role=x_agent_role,
        action="isolate_host",
        resource=host,
        agent_did=x_agent_did,
        token_jti=x_token_jti,
        auth_header=authorization,
    )
    response.headers["X-Decision-Time-ms"] = f"{decision_ms:.2f}"

    try:
        return soc_tools.isolate_host(host)
    except PermissionError as err:
        raise HTTPException(status_code=403, detail=str(err))


@app.get("/api/v1/soc/blocked")
def get_soc_blocked():
    """Unauthenticated public inspection endpoint to observe simulated SOC state."""
    return {
        "blocked_ips": soc_tools.list_blocked(),
        "isolated_hosts": soc_tools.list_isolated()
    }


# =====================================================================
# Admin Endpoints (Secured with x-admin-key)
# =====================================================================


@app.get("/api/v1/audit")
def get_audit_logs(
    decision: Optional[str] = Query(default=None),
    agent: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    _admin: str = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Retrieve filtered audit logs."""
    query = db.query(AuditLog)
    if decision:
        query = query.filter(AuditLog.decision == decision.upper())
    if agent:
        query = query.filter((AuditLog.agent_did == agent) | (AuditLog.role == agent))

    records = query.order_by(AuditLog.id.desc()).limit(limit).all()
    return records


@app.get("/api/v1/audit/stats")
def get_audit_stats(
    _admin: str = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Retrieve statistical summary of decisions, latencies, and agent activity."""
    total = db.query(AuditLog).count()
    allowed = db.query(AuditLog).filter(AuditLog.decision == "ALLOW").count()
    denied = db.query(AuditLog).filter(AuditLog.decision == "DENY").count()
    errors = db.query(AuditLog).filter(AuditLog.decision == "ERROR").count()

    avg_latency = db.query(func.avg(AuditLog.latency_ms)).scalar() or 0.0

    agent_counts = (
        db.query(AuditLog.role, func.count(AuditLog.id))
        .filter(AuditLog.role.isnot(None))
        .group_by(AuditLog.role)
        .all()
    )
    per_agent = {role: count for role, count in agent_counts}

    return {
        "total": total,
        "allowed": allowed,
        "denied": denied,
        "errors": errors,
        "per_agent": per_agent,
        "average_latency_ms": round(float(avg_latency), 2),
    }


@app.get("/api/v1/audit/verify-chain")
def get_verify_chain(
    _admin: str = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Verify cryptographic SHA-256 hash chain integrity across all audit records."""
    return audit.verify_chain(db)


@app.post("/api/v1/tokens/revoke")
def revoke_token(
    payload: RevokeTokenRequest,
    _admin: str = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Revoke a capability token by its JTI (JWT ID)."""
    existing = db.query(RevokedToken).filter(RevokedToken.jti == payload.jti).first()
    if not existing:
        revocation = RevokedToken(
            jti=payload.jti,
            revoked_at=datetime.now(timezone.utc),
        )
        db.add(revocation)
        db.commit()

    return {"status": "revoked", "jti": payload.jti}

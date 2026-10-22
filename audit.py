"""Audit logging, cryptographic hash chaining, and policy enforcement timing."""
import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from config import settings
from models import AuditLog, RevokedToken

# Fixed genesis hash for the very first block/row in the chain
GENESIS_HASH = "0" * 64


def compute_row_hash(
    prev_hash: str,
    timestamp_str: str,
    request_id: str,
    agent_did: Optional[str],
    role: Optional[str],
    action: str,
    resource: str,
    decision: str,
    reason: Optional[str],
    http_status: int,
    token_jti: Optional[str],
) -> str:
    """Compute deterministic SHA-256 hash linking the previous hash with row fields."""
    canonical_str = (
        f"{prev_hash}|{timestamp_str}|{request_id}|{agent_did or ''}|"
        f"{role or ''}|{action}|{resource}|{decision}|"
        f"{reason or ''}|{http_status}|{token_jti or ''}"
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def write_audit(
    db: Session,
    request_id: str,
    agent_did: Optional[str],
    role: Optional[str],
    action: str,
    resource: str,
    decision: str,
    reason: Optional[str],
    http_status: int,
    latency_ms: float,
    token_verify_ms: float,
    opa_ms: float,
    token_jti: Optional[str] = None,
) -> AuditLog:
    """Write an audit log entry linked to the previous entry via SHA-256 hash chain."""
    last_row = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last_row.row_hash if last_row else GENESIS_HASH

    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y-%m-%d %H:%M:%S")

    row_hash = compute_row_hash(
        prev_hash=prev_hash,
        timestamp_str=ts_str,
        request_id=request_id,
        agent_did=agent_did,
        role=role,
        action=action,
        resource=resource,
        decision=decision,
        reason=reason,
        http_status=http_status,
        token_jti=token_jti,
    )

    entry = AuditLog(
        timestamp=now,
        request_id=request_id,
        agent_did=agent_did,
        role=role,
        action=action,
        resource=resource,
        decision=decision,
        reason=reason,
        http_status=http_status,
        latency_ms=round(latency_ms, 2),
        token_verify_ms=round(token_verify_ms, 2),
        opa_ms=round(opa_ms, 2),
        token_jti=token_jti,
        prev_hash=prev_hash,
        row_hash=row_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def verify_chain(db: Session) -> dict:
    """Verify cryptographic integrity of the audit log chain.

    Returns the first broken row ID if tampering or chain mismatch is detected.
    """
    rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    if not rows:
        return {
            "valid": True,
            "broken_id": None,
            "total_rows": 0,
            "message": "Audit log is empty",
        }

    expected_prev_hash = GENESIS_HASH
    for row in rows:
        # 1. Verify that prev_hash links to the previous row's row_hash
        if row.prev_hash != expected_prev_hash:
            return {
                "valid": False,
                "broken_id": row.id,
                "error": f"Previous hash link broken at row {row.id}",
                "total_rows": len(rows),
            }

        # 2. Recompute and verify the row's own hash
        ts_str = row.timestamp.strftime("%Y-%m-%d %H:%M:%S") if row.timestamp else ""
        computed_hash = compute_row_hash(
            prev_hash=row.prev_hash,
            timestamp_str=ts_str,
            request_id=row.request_id,
            agent_did=row.agent_did,
            role=row.role,
            action=row.action,
            resource=row.resource,
            decision=row.decision,
            reason=row.reason,
            http_status=row.http_status,
            token_jti=row.token_jti,
        )

        if row.row_hash != computed_hash:
            return {
                "valid": False,
                "broken_id": row.id,
                "error": f"Content tampering detected at row {row.id}",
                "total_rows": len(rows),
            }

        expected_prev_hash = row.row_hash

    return {
        "valid": True,
        "broken_id": None,
        "total_rows": len(rows),
        "message": "Cryptographic hash chain is valid and intact",
    }


def enforce(
    db: Session,
    role: Optional[str],
    action: str,
    resource: str,
    agent_did: Optional[str] = None,
    token_jti: Optional[str] = None,
    auth_header: Optional[str] = None,
) -> float:
    """Enforce authorization and record an audit row on EVERY path (401, 403, 503, 200).

    Returns total decision latency in milliseconds or raises HTTPException.
    """
    t_start = time.perf_counter()
    request_id = str(uuid.uuid4())

    # 1. Token Verification Phase
    t_token_start = time.perf_counter()
    if token_jti:
        is_revoked = db.query(RevokedToken).filter(RevokedToken.jti == token_jti).first() is not None
        if is_revoked:
            token_verify_ms = (time.perf_counter() - t_token_start) * 1000
            latency_ms = (time.perf_counter() - t_start) * 1000
            write_audit(
                db=db,
                request_id=request_id,
                agent_did=agent_did,
                role=role,
                action=action,
                resource=resource,
                decision="DENY",
                reason="Capability token has been revoked",
                http_status=401,
                latency_ms=latency_ms,
                token_verify_ms=token_verify_ms,
                opa_ms=0.0,
                token_jti=token_jti,
            )
            raise HTTPException(
                status_code=401,
                detail="Capability token has been revoked",
                headers={"X-Decision-Time-ms": f"{latency_ms:.2f}"},
            )

    if auth_header == "invalid":
        token_verify_ms = (time.perf_counter() - t_token_start) * 1000
        latency_ms = (time.perf_counter() - t_start) * 1000
        write_audit(
            db=db,
            request_id=request_id,
            agent_did=agent_did,
            role=role,
            action=action,
            resource=resource,
            decision="DENY",
            reason="Missing or invalid authentication token",
            http_status=401,
            latency_ms=latency_ms,
            token_verify_ms=token_verify_ms,
            opa_ms=0.0,
            token_jti=token_jti,
        )
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authentication token",
            headers={"X-Decision-Time-ms": f"{latency_ms:.2f}"},
        )

    token_verify_ms = (time.perf_counter() - t_token_start) * 1000

    # 2. OPA Authorization Phase
    t_opa_start = time.perf_counter()
    try:
        resp = httpx.post(
            settings.OPA_URL,
            json={
                "input": {
                    "role": role,
                    "action": action,
                    "resource": resource,
                    "agent_did": agent_did,
                }
            },
            timeout=3.0,
        )
        resp.raise_for_status()
        allowed = resp.json().get("result", False) is True
    except (httpx.HTTPError, ValueError) as exc:
        opa_ms = (time.perf_counter() - t_opa_start) * 1000
        latency_ms = (time.perf_counter() - t_start) * 1000
        write_audit(
            db=db,
            request_id=request_id,
            agent_did=agent_did,
            role=role,
            action=action,
            resource=resource,
            decision="ERROR",
            reason="Policy engine (OPA) unreachable",
            http_status=503,
            latency_ms=latency_ms,
            token_verify_ms=token_verify_ms,
            opa_ms=opa_ms,
            token_jti=token_jti,
        )
        raise HTTPException(
            status_code=503,
            detail="Policy engine (OPA) unreachable",
            headers={"X-Decision-Time-ms": f"{latency_ms:.2f}"},
        ) from exc

    opa_ms = (time.perf_counter() - t_opa_start) * 1000

    # 3. Decision Evaluation Phase
    latency_ms = (time.perf_counter() - t_start) * 1000
    if not allowed:
        reason = f"Role '{role}' is not allowed to perform '{action}' on '{resource}'"
        write_audit(
            db=db,
            request_id=request_id,
            agent_did=agent_did,
            role=role,
            action=action,
            resource=resource,
            decision="DENY",
            reason=reason,
            http_status=403,
            latency_ms=latency_ms,
            token_verify_ms=token_verify_ms,
            opa_ms=opa_ms,
            token_jti=token_jti,
        )
        raise HTTPException(
            status_code=403,
            detail=reason,
            headers={"X-Decision-Time-ms": f"{latency_ms:.2f}"},
        )

    # 4. Success / Allowed
    reason = "Action authorized by policy"
    write_audit(
        db=db,
        request_id=request_id,
        agent_did=agent_did,
        role=role,
        action=action,
        resource=resource,
        decision="ALLOW",
        reason=reason,
        http_status=200,
        latency_ms=latency_ms,
        token_verify_ms=token_verify_ms,
        opa_ms=opa_ms,
        token_jti=token_jti,
    )
    return latency_ms

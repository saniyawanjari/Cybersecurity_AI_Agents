"""Tests for Phase 5: Database, Audit Logging, Hash Chaining, and Admin Endpoints."""
from unittest.mock import patch, MagicMock
import pytest
import httpx
from fastapi.testclient import TestClient

import audit
from config import settings
from db import SessionLocal, init_db
from main import app
from models import AuditLog, Base, RevokedToken

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_database():
    """Ensure tables are initialized and cleared before each test."""
    init_db()
    db = SessionLocal()
    try:
        db.query(AuditLog).delete()
        db.query(RevokedToken).delete()
        db.commit()
    finally:
        db.close()
    yield


def test_200_allowed_creates_audit_row():
    """200 Allowed response must create exactly one audit row with decision ALLOW and reason."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": True}
    mock_resp.raise_for_status.return_value = None

    with patch("httpx.post", return_value=mock_resp):
        response = client.get(
            "/api/v1/agent-a/report",
            headers={"x-agent-role": "log_analyst"},
        )
        assert response.status_code == 200
        assert "X-Decision-Time-ms" in response.headers

    db = SessionLocal()
    try:
        rows = db.query(AuditLog).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.decision == "ALLOW"
        assert row.http_status == 200
        assert row.role == "log_analyst"
        assert row.reason == "Action authorized by policy"
        assert row.latency_ms > 0
    finally:
        db.close()


def test_401_unauthorized_creates_audit_row():
    """401 Unauthorized response (e.g. revoked token) must create exactly one row with reason."""
    db = SessionLocal()
    try:
        revoked = RevokedToken(jti="revoked-token-uuid-123")
        db.add(revoked)
        db.commit()
    finally:
        db.close()

    response = client.get(
        "/api/v1/agent-a/report",
        headers={
            "x-agent-role": "log_analyst",
            "x-token-jti": "revoked-token-uuid-123",
        },
    )
    assert response.status_code == 401
    assert "X-Decision-Time-ms" in response.headers

    db = SessionLocal()
    try:
        rows = db.query(AuditLog).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.decision == "DENY"
        assert row.http_status == 401
        assert "revoked" in row.reason.lower()
        assert row.token_jti == "revoked-token-uuid-123"
    finally:
        db.close()


def test_403_forbidden_creates_audit_row():
    """403 Forbidden response (OPA denies) must create exactly one row with reason."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": False}
    mock_resp.raise_for_status.return_value = None

    with patch("httpx.post", return_value=mock_resp):
        response = client.get(
            "/api/v1/agent-a/report",
            headers={"x-agent-role": "incident_responder"},
        )
        assert response.status_code == 403
        assert "X-Decision-Time-ms" in response.headers

    db = SessionLocal()
    try:
        rows = db.query(AuditLog).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.decision == "DENY"
        assert row.http_status == 403
        assert "not allowed" in row.reason.lower()
    finally:
        db.close()


def test_503_unreachable_opa_creates_audit_row():
    """503 Service Unavailable (OPA unreachable) must create exactly one row with reason."""
    with patch("httpx.post", side_effect=httpx.ConnectError("Connection refused")):
        response = client.get(
            "/api/v1/agent-a/report",
            headers={"x-agent-role": "log_analyst"},
        )
        assert response.status_code == 503
        assert "X-Decision-Time-ms" in response.headers

    db = SessionLocal()
    try:
        rows = db.query(AuditLog).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.decision == "ERROR"
        assert row.http_status == 503
        assert "unreachable" in row.reason.lower()
    finally:
        db.close()


def test_hash_chain_valid_and_tamper_detection():
    """Editing a row in the database must cause verify-chain to return valid: false."""
    db = SessionLocal()
    try:
        # Create 3 audit records
        audit.write_audit(
            db, "req-1", "did:1", "log_analyst", "read_logs", "server_logs.txt",
            "ALLOW", "OK", 200, 1.5, 0.2, 1.0
        )
        audit.write_audit(
            db, "req-2", "did:2", "threat_detector", "read_logs", "server_logs.txt",
            "DENY", "Forbidden", 403, 1.2, 0.1, 0.9
        )
        audit.write_audit(
            db, "req-3", "did:1", "log_analyst", "read_logs", "server_logs.txt",
            "ALLOW", "OK", 200, 1.4, 0.2, 0.9
        )

        # Verify chain is valid initially
        chain_status = audit.verify_chain(db)
        assert chain_status["valid"] is True
        assert chain_status["broken_id"] is None
        assert chain_status["total_rows"] == 3

        # Tamper directly with row 2 (change decision from DENY to ALLOW)
        row_to_tamper = db.query(AuditLog).filter(AuditLog.id == 2).first()
        row_to_tamper.decision = "ALLOW"
        db.commit()

        # Re-verify: must detect tampering at row 2!
        tampered_status = audit.verify_chain(db)
        assert tampered_status["valid"] is False
        assert tampered_status["broken_id"] == 2
    finally:
        db.close()


def test_admin_endpoints():
    """Test admin audit querying, statistics, and token revocation."""
    db = SessionLocal()
    try:
        audit.write_audit(
            db, "req-1", "did:agent-a", "log_analyst", "read_logs", "server_logs.txt",
            "ALLOW", "OK", 200, 10.0, 1.0, 8.0
        )
        audit.write_audit(
            db, "req-2", "did:agent-b", "threat_detector", "block_ip", "firewall",
            "DENY", "Forbidden", 403, 5.0, 1.0, 3.0
        )
    finally:
        db.close()

    # 1. Unauthenticated admin call fails
    res_unauth = client.get("/api/v1/audit")
    assert res_unauth.status_code == 403

    # 2. Query logs with admin key
    res_logs = client.get(
        "/api/v1/audit?decision=ALLOW",
        headers={"x-admin-key": settings.ADMIN_KEY},
    )
    assert res_logs.status_code == 200
    logs = res_logs.json()
    assert len(logs) == 1
    assert logs[0]["decision"] == "ALLOW"

    # 3. Query stats
    res_stats = client.get(
        "/api/v1/audit/stats",
        headers={"x-admin-key": settings.ADMIN_KEY},
    )
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["total"] == 2
    assert stats["allowed"] == 1
    assert stats["denied"] == 1
    assert stats["per_agent"]["log_analyst"] == 1

    # 4. Revoke token endpoint
    res_revoke = client.post(
        "/api/v1/tokens/revoke",
        json={"jti": "jti-admin-revoked-001"},
        headers={"x-admin-key": settings.ADMIN_KEY},
    )
    assert res_revoke.status_code == 200
    assert res_revoke.json()["status"] == "revoked"

    # 5. Verify chain endpoint
    res_chain = client.get(
        "/api/v1/audit/verify-chain",
        headers={"x-admin-key": settings.ADMIN_KEY},
    )
    assert res_chain.status_code == 200
    assert res_chain.json()["valid"] is True

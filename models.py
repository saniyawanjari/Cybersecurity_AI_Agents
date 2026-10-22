"""SQLAlchemy 2.0 database models for SOC Guard.

Defines schemas for:
- agents: decentralized identity, role, and operational status
- audit_log: tamper-evident hash-chained decision log
- revoked_tokens: revoked capability token tracking
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base declarative class for SQLAlchemy 2.0 models."""
    pass


class Agent(Base):
    """Agent identity registry table."""

    __tablename__ = "agents"

    did: Mapped[str] = mapped_column(String(255), primary_key=True)
    role: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class AuditLog(Base):
    """Cryptographically chained audit log of every supervisor decision."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_did: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)  # ALLOW / DENY / ERROR
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    http_status: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    token_verify_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    opa_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    token_jti: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class RevokedToken(Base):
    """Revoked capability token identifiers."""

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(128), primary_key=True)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

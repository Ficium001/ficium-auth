# =============================================================
# ficium-auth — Database models
# Auth schema — separate from institution schema
# =============================================================

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text,
    UniqueConstraint, Index, func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Users ─────────────────────────────────────────────────────
class AuthUser(Base):
    __tablename__ = "auth_users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_auth_users_email"),
        Index("ix_auth_users_email", "email"),
        Index("ix_auth_users_institution_id", "institution_id"),
        {"schema": "auth_portal"},
    )

    id:             Mapped[uuid.UUID]         = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    institution_id: Mapped[uuid.UUID]         = mapped_column(UUID(as_uuid=True), nullable=False)
    email:          Mapped[str]               = mapped_column(String(255), nullable=False)
    email_verified: Mapped[bool]              = mapped_column(Boolean, default=False, nullable=False)
    password_hash:  Mapped[str]               = mapped_column(Text, nullable=False)
    role:           Mapped[str]               = mapped_column(String(50), nullable=False, default="analyst")
    is_active:      Mapped[bool]              = mapped_column(Boolean, default=True, nullable=False)
    mfa_enabled:    Mapped[bool]              = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret:     Mapped[Optional[str]]     = mapped_column(Text, nullable=True)   # encrypted
    last_login_at:  Mapped[Optional[datetime]]= mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip:  Mapped[Optional[str]]     = mapped_column(String(45), nullable=True)
    failed_attempts:Mapped[int]               = mapped_column(Integer, default=0, nullable=False)
    locked_until:   Mapped[Optional[datetime]]= mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime]     = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at:     Mapped[datetime]          = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now())
    updated_at:     Mapped[datetime]          = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    sessions:       Mapped[list["AuthSession"]]     = relationship(back_populates="user", cascade="all, delete-orphan")
    mfa_backup_codes: Mapped[list["MFABackupCode"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    audit_events:   Mapped[list["AuthAuditEvent"]]  = relationship(back_populates="user")


# ── Sessions ──────────────────────────────────────────────────
class AuthSession(Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (
        Index("ix_auth_sessions_user_id", "user_id"),
        Index("ix_auth_sessions_refresh_token_hash", "refresh_token_hash"),
        Index("ix_auth_sessions_expires_at", "expires_at"),
        {"schema": "auth_portal"},
    )

    id:                  Mapped[uuid.UUID]        = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id:             Mapped[uuid.UUID]        = mapped_column(UUID(as_uuid=True), ForeignKey("auth_portal.auth_users.id", ondelete="CASCADE"), nullable=False)
    refresh_token_hash:  Mapped[str]              = mapped_column(String(64), nullable=False, unique=True)
    ip_address:          Mapped[Optional[str]]    = mapped_column(String(45), nullable=True)
    user_agent:          Mapped[Optional[str]]    = mapped_column(Text, nullable=True)
    device_fingerprint:  Mapped[Optional[str]]    = mapped_column(String(64), nullable=True)
    is_active:           Mapped[bool]             = mapped_column(Boolean, default=True, nullable=False)
    created_at:          Mapped[datetime]         = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now())
    last_used_at:        Mapped[datetime]         = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at:          Mapped[datetime]         = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at:          Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason:       Mapped[Optional[str]]    = mapped_column(String(100), nullable=True)

    user: Mapped["AuthUser"] = relationship(back_populates="sessions")


# ── MFA backup codes ──────────────────────────────────────────
class MFABackupCode(Base):
    __tablename__ = "mfa_backup_codes"
    __table_args__ = (
        Index("ix_mfa_backup_codes_user_id", "user_id"),
        {"schema": "auth_portal"},
    )

    id:         Mapped[uuid.UUID]         = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id:    Mapped[uuid.UUID]         = mapped_column(UUID(as_uuid=True), ForeignKey("auth_portal.auth_users.id", ondelete="CASCADE"), nullable=False)
    code_hash:  Mapped[str]               = mapped_column(String(64), nullable=False)
    used_at:    Mapped[Optional[datetime]]= mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime]          = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped["AuthUser"] = relationship(back_populates="mfa_backup_codes")


# ── Password reset tokens ─────────────────────────────────────
class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    __table_args__ = (
        Index("ix_pwd_reset_token_hash", "token_hash"),
        Index("ix_pwd_reset_user_id", "user_id"),
        {"schema": "auth_portal"},
    )

    id:          Mapped[uuid.UUID]   = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id:     Mapped[uuid.UUID]   = mapped_column(UUID(as_uuid=True), ForeignKey("auth_portal.auth_users.id", ondelete="CASCADE"), nullable=False)
    token_hash:  Mapped[str]         = mapped_column(String(64), nullable=False, unique=True)
    used:        Mapped[bool]        = mapped_column(Boolean, default=False, nullable=False)
    ip_address:  Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    created_at:  Mapped[datetime]    = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at:  Mapped[datetime]    = mapped_column(DateTime(timezone=True), nullable=False)
    used_at:     Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Email verification tokens ─────────────────────────────────
class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"
    __table_args__ = (
        Index("ix_email_verify_token_hash", "token_hash"),
        {"schema": "auth_portal"},
    )

    id:          Mapped[uuid.UUID]   = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id:     Mapped[uuid.UUID]   = mapped_column(UUID(as_uuid=True), ForeignKey("auth_portal.auth_users.id", ondelete="CASCADE"), nullable=False)
    token_hash:  Mapped[str]         = mapped_column(String(64), nullable=False, unique=True)
    used:        Mapped[bool]        = mapped_column(Boolean, default=False, nullable=False)
    created_at:  Mapped[datetime]    = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at:  Mapped[datetime]    = mapped_column(DateTime(timezone=True), nullable=False)


# ── IP allowlist ──────────────────────────────────────────────
class IPAllowlist(Base):
    __tablename__ = "ip_allowlist"
    __table_args__ = (
        Index("ix_ip_allowlist_institution_id", "institution_id"),
        {"schema": "auth_portal"},
    )

    id:             Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    institution_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    cidr:           Mapped[str]       = mapped_column(String(50), nullable=False)   # e.g. 192.168.1.0/24
    label:          Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_by:     Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at:     Mapped[datetime]  = mapped_column(DateTime(timezone=True), default=utcnow)


# ── Audit log ─────────────────────────────────────────────────
class AuthAuditEvent(Base):
    __tablename__ = "auth_audit_events"
    __table_args__ = (
        Index("ix_auth_audit_user_id", "user_id"),
        Index("ix_auth_audit_institution_id", "institution_id"),
        Index("ix_auth_audit_created_at", "created_at"),
        Index("ix_auth_audit_event_type", "event_type"),
        {"schema": "auth_portal"},
    )

    id:             Mapped[uuid.UUID]      = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id:        Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("auth_portal.auth_users.id", ondelete="SET NULL"), nullable=True)
    institution_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    event_type:     Mapped[str]            = mapped_column(String(50), nullable=False)
    # Event types: login.success, login.failed, login.locked,
    #              logout, token.refresh, token.revoked,
    #              password.reset.requested, password.reset.completed,
    #              password.changed, email.verified,
    #              mfa.enrolled, mfa.verified, mfa.failed, mfa.disabled,
    #              session.created, session.revoked, session.expired,
    #              ip.blocked, suspicious.login
    outcome:        Mapped[str]            = mapped_column(String(20), nullable=False)   # success | failed | blocked
    ip_address:     Mapped[Optional[str]]  = mapped_column(String(45), nullable=True)
    user_agent:     Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    metadata:       Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at:     Mapped[datetime]       = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now())

    user: Mapped[Optional["AuthUser"]] = relationship(back_populates="audit_events")

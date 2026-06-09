# =============================================================
# ficium-auth — Audit service
# Every auth event logged — append only, FSC compliant
# =============================================================

import uuid
from typing import Optional, Any
from datetime import datetime, timezone

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.auth import AuthAuditEvent

log = structlog.get_logger()


class AuditService:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        event_type:     str,
        outcome:        str,
        user_id:        Optional[uuid.UUID] = None,
        institution_id: Optional[uuid.UUID] = None,
        ip_address:     Optional[str]       = None,
        user_agent:     Optional[str]       = None,
        metadata:       Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Append an audit event. Never raises — audit must not break auth flow.
        """
        try:
            event = AuthAuditEvent(
                user_id=user_id,
                institution_id=institution_id,
                event_type=event_type,
                outcome=outcome,
                ip_address=ip_address,
                user_agent=user_agent,
                event_metadata=metadata,
            )
            self.db.add(event)
            await self.db.flush()

            # Also emit structured log for SIEM integration
            log.info(
                "auth_event",
                event_type=event_type,
                outcome=outcome,
                user_id=str(user_id) if user_id else None,
                institution_id=str(institution_id) if institution_id else None,
                ip_address=ip_address,
            )
        except Exception as e:
            # Audit failure must never block auth
            log.error("audit_write_failed", error=str(e), event_type=event_type)


# ── Event type constants ──────────────────────────────────────
class AuditEvent:
    LOGIN_SUCCESS           = "login.success"
    LOGIN_FAILED            = "login.failed"
    LOGIN_LOCKED            = "login.locked"
    LOGIN_BLOCKED_IP        = "login.blocked_ip"
    LOGOUT                  = "logout"
    TOKEN_REFRESH           = "token.refresh"
    TOKEN_REVOKED           = "token.revoked"
    PASSWORD_RESET_REQUESTED = "password.reset.requested"
    PASSWORD_RESET_COMPLETED = "password.reset.completed"
    PASSWORD_CHANGED        = "password.changed"
    EMAIL_VERIFIED          = "email.verified"
    EMAIL_VERIFY_RESENT     = "email.verify.resent"
    MFA_ENROLLED            = "mfa.enrolled"
    MFA_VERIFIED            = "mfa.verified"
    MFA_FAILED              = "mfa.failed"
    MFA_DISABLED            = "mfa.disabled"
    MFA_BACKUP_USED         = "mfa.backup_used"
    SESSION_CREATED         = "session.created"
    SESSION_REVOKED         = "session.revoked"
    SESSION_EXPIRED         = "session.expired"
    SUSPICIOUS_LOGIN        = "suspicious.login"
    REGISTER_SUCCESS        = "register.success"
    REGISTER_FAILED         = "register.failed"
    IP_ALLOWLIST_ADDED      = "ip_allowlist.added"
    IP_ALLOWLIST_REMOVED    = "ip_allowlist.removed"

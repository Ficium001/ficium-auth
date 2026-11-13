# =============================================================
# ficium-auth - first admin of a provisioned institution
#
#   POST /auth/institution/invite {email}
#     caller: a Ficium staff token (platform institution, staff role) signed in WITH MFA
#             (the same gate as /auth/staff/provision)
#     -> emails a single-use set-password link (72 h) ONLY to that address, for a login
#        that portal-api created with institution.provision (four-eyes, after the contract)
#        and that has never been activated. The link is never returned to the caller.
#     Re-calling re-sends it (older links cancelled).
#
# This endpoint never creates a login: portal-api's provisioning does, in the same
# transaction as the institution and its primary-admin member. It refuses every
# account that is active, deactivated, or belongs to Ficium staff.
# =============================================================
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from ..core.config import settings
from ..core.database import SupabaseDB, db_dependency
from ..core.redis import check_rate_limit
from ..core.security import generate_secure_token, hash_token
from ..middleware.auth_middleware import get_client_ip
from ..services.email import send_institution_invite_email
from .staff import UNUSABLE, staff_caller

log = structlog.get_logger()
router = APIRouter(prefix="/auth/institution", tags=["Institution invite"])


class InviteRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
            raise ValueError("invalid email")
        return v


class InviteResponse(BaseModel):
    status:     str    # sent
    email_sent: bool


@router.post("/invite", response_model=InviteResponse)
async def invite(
    body: InviteRequest,
    request: Request,
    caller: dict[str, Any] = Depends(staff_caller),
    db: SupabaseDB = Depends(db_dependency),
) -> InviteResponse:
    allowed, _ = await check_rate_limit(f"institution_invite:{caller['sub']}", 20, 3600)
    if not allowed:
        raise HTTPException(429, "Too many invitations in the last hour.")

    user = await db.get_user_by_email(body.email)
    if not user:
        raise HTTPException(404, "No invitation is waiting for that email.")
    if str(user.get("institution_id")) == settings.platform_institution_id:
        raise HTTPException(409, "That is a Ficium staff account; invite staff from the Team page.")
    if user.get("password_hash") != UNUSABLE:
        raise HTTPException(409, "That account is already active.")
    if not user.get("is_active", False):
        raise HTTPException(409, "That account is deactivated.")

    await db.cancel_reset_tokens(user["id"])
    raw = generate_secure_token()
    await db.create_password_reset_token({
        "user_id": user["id"], "token_hash": hash_token(raw), "ip_address": get_client_ip(request),
        "expires_at": (datetime.now(UTC) + timedelta(seconds=settings.institution_invite_ttl)).isoformat(),
    })
    email_sent = True
    try:
        await send_institution_invite_email(
            user["email"], f"{settings.portal_public_url.rstrip('/')}/reset-password?token={raw}",
            user.get("username") or user["email"])
    except Exception as exc:   # noqa: BLE001 - provider errors vary; never leak them, report the fact
        email_sent = False
        log.error("institution_invite_email_failed", error=str(exc))

    await db.log_audit({
        "user_id": user["id"], "institution_id": user.get("institution_id"),
        "event_type": "institution_user.invited", "outcome": "success",
        "ip_address": get_client_ip(request),
        "event_metadata": {"by": caller.get("sub"), "email_sent": email_sent},
    })
    return InviteResponse(status="sent", email_sent=email_sent)

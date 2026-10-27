# =============================================================
# ficium-auth — staff provisioning (for ficium-admin's Team page)
#
#   POST /auth/staff/provision {email, username}
#     caller: a Ficium staff token (platform institution, staff role) signed in WITH MFA
#     -> creates a `ficium_staff` login in the platform institution (no portal powers),
#        password unusable until the invitee sets it from a 24 h single-use link
#        emailed ONLY to the invitee (never returned to the caller).
#     Re-calling for a not-yet-activated invite re-sends the link (old links cancelled).
#
# ficium-admin additionally checks its own `iam.manage` permission before calling.
# =============================================================
import re
from datetime import datetime, timedelta, timezone, UTC
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from pydantic import BaseModel, Field, field_validator

from ..core.config import settings
from ..core.database import SupabaseDB, db_dependency
from ..core.redis import check_rate_limit, is_token_blacklisted
from ..core.security import generate_secure_token, hash_token, verify_access_token
from ..middleware.auth_middleware import get_client_ip
from ..services.email import send_staff_invite_email

log = structlog.get_logger()
router = APIRouter(prefix="/auth/staff", tags=["Staff"])
_bearer = HTTPBearer(auto_error=False)

UNUSABLE = "!invited-not-activated"   # never a valid Argon2 hash: login fails until a password is set
STAFF_ROLE = "ficium_staff"


def _csv(v: str) -> list[str]:
    return [x.strip().lower() for x in v.split(",") if x.strip()]


class ProvisionRequest(BaseModel):
    email:    str = Field(..., min_length=5, max_length=254)
    username: str | None = Field(None, min_length=3, max_length=40)   # required to create; optional to re-send

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
            raise ValueError("invalid email")
        return v

    @field_validator("username")
    @classmethod
    def _username(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,39}", v):
            raise ValueError("3-40 characters: letters, digits, dot, dash, underscore")
        return v


class ProvisionResponse(BaseModel):
    status:     str    # created | resent
    email_sent: bool


async def staff_caller(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> dict[str, Any]:
    if not credentials:
        raise HTTPException(401, "Authentication required.")
    try:
        claims = verify_access_token(credentials.credentials)
    except JWTError as exc:
        raise HTTPException(401, "Invalid or expired token.") from exc
    if claims.get("jti") and await is_token_blacklisted(claims["jti"]):
        raise HTTPException(401, "Token has been revoked.")
    if str(claims.get("institution_id")) != settings.platform_institution_id \
       or str(claims.get("user_role", "")).lower() not in _csv(settings.staff_roles):
        raise HTTPException(403, "Only Ficium staff can invite staff.")
    if "mfa" not in (claims.get("amr") or []):
        raise HTTPException(403, "Sign in with two-factor authentication to invite staff.")
    return claims


@router.post("/provision", response_model=ProvisionResponse)
async def provision(
    body: ProvisionRequest,
    request: Request,
    caller: dict[str, Any] = Depends(staff_caller),
    db: SupabaseDB = Depends(db_dependency),
) -> ProvisionResponse:
    allowed, _ = await check_rate_limit(f"staff_provision:{caller['sub']}", 20, 3600)
    if not allowed:
        raise HTTPException(429, "Too many invitations in the last hour.")
    if body.email.split("@", 1)[1] not in _csv(settings.staff_email_domains):
        raise HTTPException(400, "Staff must use a Ficium email address.")

    existing = await db.get_user_by_email(body.email)
    by_name = await db.get_user_by_username(body.username) if body.username else None
    if existing:
        # Only a not-yet-activated staff invite may be re-sent; never touch any other account.
        if existing.get("password_hash") != UNUSABLE or str(existing.get("institution_id")) != settings.platform_institution_id:
            raise HTTPException(409, "That email already has an account.")
        if body.username and existing["username"] != body.username:
            raise HTTPException(409, f"That email was invited as '{existing['username']}'.")
        user, status = existing, "resent"
    else:
        if not body.username:
            raise HTTPException(422, "A username is required for a new invitation.")
        if by_name:
            raise HTTPException(409, "That username is taken.")
        user = await db.create_user({
            "institution_id": settings.platform_institution_id,
            "email": body.email, "email_verified": False, "username": body.username,
            "password_hash": UNUSABLE, "role": STAFF_ROLE, "is_active": True,
            "mfa_enabled": False, "must_change_password": False,
        })
        status = "created"

    await db.cancel_reset_tokens(user["id"])
    raw = generate_secure_token()
    await db.create_password_reset_token({
        "user_id": user["id"], "token_hash": hash_token(raw), "ip_address": get_client_ip(request),
        "expires_at": (datetime.now(UTC) + timedelta(seconds=settings.staff_invite_ttl)).isoformat(),
    })
    email_sent = True
    try:
        await send_staff_invite_email(
            body.email, f"{settings.admin_public_url.rstrip('/')}/reset-password?token={raw}",
            user["username"], inviter=str(caller.get("email") or "A Ficium administrator"))
    except Exception as exc:   # noqa: BLE001 — provider errors vary; never leak them, report the fact
        email_sent = False
        log.error("staff_invite_email_failed", error=str(exc))

    await db.log_audit({
        "user_id": user["id"], "institution_id": settings.platform_institution_id,
        "event_type": f"staff.{status}", "outcome": "success", "ip_address": get_client_ip(request),
        "event_metadata": {"by": caller.get("sub"), "email_sent": email_sent},
    })
    return ProvisionResponse(status=status, email_sent=email_sent)

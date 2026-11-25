# =============================================================
# ficium-auth — staff provisioning (for ficium-admin's Team page)
#
#   POST /auth/staff/provision {email, username}
#     caller: a Ficium staff token (platform institution, staff role) signed in WITH MFA
#     -> creates a `ficium_staff` login in the platform institution (no portal powers),
#        password unusable until the invitee sets it from a 24 h single-use link
#        emailed ONLY to the invitee (never returned to the caller).
#     Re-calling for a not-yet-activated invite re-sends the link (old links cancelled).
#     If the person already has an ACTIVATED staff login (e.g. invited to the other admin
#     site first), nothing is touched: status "existing" — they sign in with what they have.
#
#   POST /auth/staff/lookup {emails[]}
#     -> username, whether the login is activated, MFA on, locked, last sign-in, for platform
#        staff accounts only (bank users are never returned). Identity stays owned here; the
#        admin sites show it next to their own roles instead of copying it.
#
#   POST /auth/staff/reset {email, reset_mfa}
#     -> an admin-requested, four-eyes-approved sign-in reset (ficium-admin enforces the second
#        person before calling): password made unusable, every session signed out, lockout
#        cleared, optionally the authenticator removed, and a 24 h set-password link emailed
#        ONLY to the person. The caller never sees it and cannot reset themselves.
#
# ficium-admin additionally checks its own `iam.manage` permission before calling.
# =============================================================
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError as JWTError
from pydantic import BaseModel, Field, field_validator

from ..core.config import settings
from ..core.database import SupabaseDB, db_dependency
from ..core.redis import (
    check_rate_limit,
    clear_account_failures,
    is_account_locked,
    is_token_blacklisted,
)
from ..core.security import generate_secure_token, hash_token, verify_access_token
from ..middleware.auth_middleware import get_client_ip
from ..services.email import send_staff_invite_email, send_staff_reset_email

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
    status:     str    # created | resent | existing
    email_sent: bool


_EMAIL = re.compile(r"[^@\s\"(),]+@[^@\s\"(),]+\.[^@\s\"(),]+")


class LookupRequest(BaseModel):
    emails: list[str] = Field(..., max_length=200)

    @field_validator("emails")
    @classmethod
    def _emails(cls, v: list[str]) -> list[str]:
        out = sorted({e.strip().lower() for e in v})
        if any(not _EMAIL.fullmatch(e) or len(e) > 254 for e in out):
            raise ValueError("invalid email")
        return out


class StaffAccount(BaseModel):
    email:         str
    username:      str
    activated:     bool          # a password has been set
    mfa_enabled:   bool
    locked:        bool          # too many failed sign-ins right now
    active:        bool
    last_login_at: str | None


class LookupResponse(BaseModel):
    accounts: list[StaffAccount]


class ResetRequest(BaseModel):
    email:     str = Field(..., min_length=5, max_length=254)
    reset_mfa: bool = False

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL.fullmatch(v):
            raise ValueError("invalid email")
        return v


class ResetResponse(BaseModel):
    status:     str    # reset
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
        platform = str(existing.get("institution_id")) == settings.platform_institution_id
        staff = platform and str(existing.get("role", "")).lower() in {STAFF_ROLE, *_csv(settings.staff_roles)}
        if staff and existing.get("password_hash") != UNUSABLE:
            # Already signs in as Ficium staff (e.g. on the other admin site): grant nothing here,
            # touch nothing, send nothing. The admin site's own roles decide what they may do.
            if body.username and existing["username"] != body.username:
                raise HTTPException(409, f"They already have a Ficium login with the username '{existing['username']}'. Use that.")
            if not existing.get("is_active", True):
                raise HTTPException(409, "Their Ficium login is switched off.")
            await db.log_audit({
                "user_id": existing["id"], "institution_id": settings.platform_institution_id,
                "event_type": "staff.existing", "outcome": "success", "ip_address": get_client_ip(request),
                "event_metadata": {"by": caller.get("sub")},
            })
            return ProvisionResponse(status="existing", email_sent=False)
        # Only a not-yet-activated staff invite may be re-sent; never touch any other account.
        if not staff:
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


@router.post("/lookup", response_model=LookupResponse)
async def lookup(
    body: LookupRequest,
    caller: dict[str, Any] = Depends(staff_caller),
    db: SupabaseDB = Depends(db_dependency),
) -> LookupResponse:
    allowed, _ = await check_rate_limit(f"staff_lookup:{caller['sub']}", 600, 3600)
    if not allowed:
        raise HTTPException(429, "Too many requests.")
    rows = await db.get_users_by_emails(settings.platform_institution_id, body.emails)
    out = []
    for u in rows:
        out.append(StaffAccount(
            email=str(u["email"]).lower(), username=u["username"],
            activated=u.get("password_hash") != UNUSABLE, mfa_enabled=bool(u.get("mfa_enabled")),
            locked=await is_account_locked(u["username"]), active=bool(u.get("is_active", True)),
            last_login_at=u.get("last_login_at"),
        ))
    return LookupResponse(accounts=out)


@router.post("/reset", response_model=ResetResponse)
async def reset(
    body: ResetRequest,
    request: Request,
    caller: dict[str, Any] = Depends(staff_caller),
    db: SupabaseDB = Depends(db_dependency),
) -> ResetResponse:
    allowed, _ = await check_rate_limit(f"staff_reset:{caller['sub']}", 10, 3600)
    if not allowed:
        raise HTTPException(429, "Too many resets in the last hour.")
    user = await db.get_user_by_email(body.email)
    if not user or str(user.get("institution_id")) != settings.platform_institution_id \
       or str(user.get("role", "")).lower() not in {STAFF_ROLE, *_csv(settings.staff_roles)}:
        raise HTTPException(404, "No Ficium staff login with that email.")
    if str(user["id"]) == str(caller.get("sub")):
        raise HTTPException(403, "You cannot reset your own sign-in. Use 'Forgot password'.")
    if user.get("password_hash") == UNUSABLE:
        raise HTTPException(409, "They haven't set a password yet. Re-send the invitation instead.")

    changes: dict[str, Any] = {"password_hash": UNUSABLE, "must_change_password": False}
    if body.reset_mfa:
        changes |= {"mfa_enabled": False, "mfa_secret": None}
    await db.update_user(user["id"], changes)
    if body.reset_mfa:
        await db.delete_backup_codes(user["id"])
    await db.revoke_all_user_sessions(user["id"])
    await clear_account_failures(user["username"])

    await db.cancel_reset_tokens(user["id"])
    raw = generate_secure_token()
    await db.create_password_reset_token({
        "user_id": user["id"], "token_hash": hash_token(raw), "ip_address": get_client_ip(request),
        "expires_at": (datetime.now(UTC) + timedelta(seconds=settings.staff_invite_ttl)).isoformat(),
    })
    email_sent = True
    try:
        await send_staff_reset_email(
            user["email"], f"{settings.admin_public_url.rstrip('/')}/reset-password?token={raw}",
            user["username"], reset_mfa=body.reset_mfa)
    except Exception as exc:   # noqa: BLE001
        email_sent = False
        log.error("staff_reset_email_failed", error=str(exc))

    await db.log_audit({
        "user_id": user["id"], "institution_id": settings.platform_institution_id,
        "event_type": "staff.reset", "outcome": "success", "ip_address": get_client_ip(request),
        "event_metadata": {"by": caller.get("sub"), "reset_mfa": body.reset_mfa, "email_sent": email_sent},
    })
    return ResetResponse(status="reset", email_sent=email_sent)

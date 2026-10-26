# =============================================================
# ficium-auth — Auth API router (Supabase REST DB backend)
# =============================================================

import uuid
from datetime import datetime, timezone, timedelta
from typing import Literal, Optional, cast

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie
from jose import JWTError

from ..core.database import db_dependency, SupabaseDB
from ..core.config import settings
from ..core.security import (
    hash_password, verify_password, validate_password_policy,
    PasswordPolicyError, issue_access_token, generate_secure_token,
    hash_token, generate_refresh_token, verify_access_token, get_token_from_header,
)
from ..core.redis import (
    check_rate_limit, is_locked_out, record_failed_login,
    clear_failed_logins, add_user_session,
    remove_user_session, get_user_session_ids, cache_set, RedisKeys,
)
from ..schemas.auth import (
    LoginRequest, LoginResponse,
    ForgotPasswordRequest, ForgotPasswordResponse,
    ResetPasswordRequest, ChangePasswordRequest, ForceChangePasswordRequest, PasswordActionResponse,
    VerifyEmailRequest, SessionListResponse, SessionInfo, MeResponse,
)
from ..services.email import (
    send_password_reset_email,
)
from ..middleware.auth_middleware import get_current_user, AuthenticatedUser, get_client_ip, get_user_agent

log = structlog.get_logger()
router = APIRouter(prefix="/auth", tags=["Authentication"])


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=settings.session_cookie_httponly,
        secure=settings.session_cookie_secure,
        samesite=cast(Literal["lax", "strict", "none"], settings.session_cookie_samesite),
        # Only set Domain if explicitly configured — an unset/empty
        # Domain makes this a host-only cookie scoped to whatever host
        # actually issued it, which is always valid. A misconfigured
        # Domain (e.g. one that isn't the issuing host or a parent of
        # it) causes the browser to silently drop the cookie entirely.
        domain=settings.session_cookie_domain or None,
        max_age=settings.jwt_refresh_ttl,
        path="/auth/refresh",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/auth/refresh",
    )


def amr_for(mfa_verified: bool, method: str = "otp") -> list[str]:
    """RFC 8176 authentication methods. 'mfa' is what relying parties should check."""
    return ["pwd", method, "mfa"] if mfa_verified else ["pwd"]


async def start_session(
    db: SupabaseDB, user: dict, request: Request, response: Response,
    mfa_verified: bool, method: str = "otp",
) -> LoginResponse:
    """Create a session + refresh cookie and issue an access token. Shared by
    password login (no MFA) and /auth/mfa/verify (MFA completed)."""
    ip         = get_client_ip(request)
    user_agent = get_user_agent(request)
    session_id         = str(uuid.uuid4())
    raw_rt, rt_hash    = generate_refresh_token()

    # Fetch module permissions from institution.group via custom_group_id
    module_permissions = await db.get_member_module_permissions(
        user_id=user["id"],
        institution_id=user["institution_id"],
    )

    access_token, exp  = issue_access_token(
        user_id=user["id"],
        institution_id=user["institution_id"],
        role=user["role"],
        session_id=session_id,
        extra_claims={
            "email":              user["email"],
            "module_permissions": module_permissions,
            "amr":                amr_for(mfa_verified, method),
        },
    )

    # Enforce concurrent session limit
    session_ids = await get_user_session_ids(user["id"])
    if len(session_ids) >= settings.session_max_concurrent:
        oldest = next(iter(session_ids))
        await remove_user_session(user["id"], oldest)
        await db.update_session(oldest, {
            "is_active":    False,
            "revoked_at":   datetime.now(timezone.utc).isoformat(),
            "revoke_reason": "session_limit",
        })

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=settings.jwt_refresh_ttl)).isoformat()
    await db.create_session({
        "id":                 session_id,
        "user_id":            user["id"],
        "refresh_token_hash": rt_hash,
        "ip_address":         ip,
        "user_agent":         user_agent[:500] if user_agent else None,
        "is_active":          True,
        "expires_at":         expires_at,
        "mfa_verified":       mfa_verified,
    })

    await add_user_session(user["id"], session_id)

    await db.update_user(user["id"], {
        "last_login_at": datetime.now(timezone.utc).isoformat(),
        "last_login_ip": ip,
    })

    _set_refresh_cookie(response, raw_rt)

    await db.log_audit({
        "user_id":        user["id"],
        "institution_id": user["institution_id"],
        "event_type":     "login.success",
        "outcome":        "success",
        "ip_address":     ip,
        "event_metadata": {"session_id": session_id, "mfa": mfa_verified},
    })

    return LoginResponse(
        access_token=access_token,
        expires_in=settings.jwt_access_ttl,
        must_change_password=bool(user.get("must_change_password", False)),
    )


# ── Register (removed 2026-10-21) ─────────────────────────────
# Self-registration lives in portal-api (POST /auth/register): one database
# transaction creates the institution, this service's login row and the
# primary admin. The endpoint that was here posted to a table name that does
# not exist (institution/institutions) and never created the member, so it
# could not have worked; it is removed rather than left as a public surface.


# ── Login ─────────────────────────────────────────────────────
@router.post("/login", response_model=LoginResponse)
async def login(
    body:     LoginRequest,
    request:  Request,
    response: Response,
    db:       SupabaseDB = Depends(db_dependency),
) -> LoginResponse:
    ip         = get_client_ip(request)

    allowed, _ = await check_rate_limit(
        f"login:{ip}", settings.rate_limit_login, settings.rate_limit_login_window
    )
    if not allowed:
        raise HTTPException(429, "Too many login attempts.")

    if await is_locked_out(ip):
        raise HTTPException(429, "Account temporarily locked due to repeated failed attempts.")

    user = await db.get_user_by_username(body.username)

    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy"
    pw_ok = verify_password(body.password, user["password_hash"] if user else dummy_hash)

    if not user or not pw_ok:
        await record_failed_login(ip, user["id"] if user else None)
        await db.log_audit({
            "user_id":    user["id"] if user else None,
            "event_type": "login.failed",
            "outcome":    "failed",
            "ip_address": ip,
            "event_metadata": {"username": body.username},
        })
        raise HTTPException(401, "Incorrect username or password.")

    if not user["is_active"]:
        raise HTTPException(403, "Account is deactivated. Contact your administrator.")

    await clear_failed_logins(ip, user["id"])

    if user.get("mfa_enabled"):
        challenge_id = generate_secure_token(16)
        await cache_set(
            RedisKeys.mfa_challenge(challenge_id),
            {"user_id": user["id"], "ip": ip},
            settings.mfa_challenge_ttl,
        )
        return LoginResponse(mfa_required=True, mfa_token=challenge_id)

    return await start_session(db, user, request, response, mfa_verified=False)


# ── Forced password change (after admin reset) ────────────────
@router.post("/password/force-change", response_model=PasswordActionResponse)
async def force_change_password(
    body:    ForceChangePasswordRequest,
    request: Request,
    db:      SupabaseDB = Depends(db_dependency),
    current: AuthenticatedUser = Depends(get_current_user),
) -> PasswordActionResponse:
    """
    Used when must_change_password=true. User is already authenticated —
    just validate and set the new password, then clear the flag.
    """
    log.info("force_change_attempt", user_id=current.user_id)
    if len(body.new_password) < 12:
        raise HTTPException(400, "Password must be at least 12 characters.")

    new_hash = hash_password(body.new_password)

    try:
        await db.update_user(current.user_id, {
            "password_hash":        new_hash,
            "must_change_password": False,
            "updated_at":           datetime.now(timezone.utc).isoformat(),
        })
        log.info("force_change_success", user_id=current.user_id)
    except Exception as e:
        log.error("force_change_db_error", user_id=current.user_id, error=str(e))
        raise HTTPException(500, f"Failed to update password: {str(e)}")

    await db.log_audit({
        "user_id":        current.user_id,
        "event_type":     "password_force_changed",
        "event_metadata": {"ip": get_client_ip(request)},
    })

    return PasswordActionResponse(message="Password updated successfully.")


# ── Logout ────────────────────────────────────────────────────
@router.post("/logout")
async def logout(
    request:  Request,
    response: Response,
    db:       SupabaseDB = Depends(db_dependency),
) -> dict:
    """
    Always clears the client's session, even if the access token has
    already expired. An expired token still proves prior possession
    (signature is checked), so it's enough to identify and revoke the
    session — logout must never require a *currently valid* token,
    or an expired session becomes impossible to explicitly sign out of.
    """
    ip = get_client_ip(request)
    _clear_refresh_cookie(response)

    token = get_token_from_header(request.headers.get("Authorization"))
    if not token:
        return {"message": "Signed out successfully."}

    try:
        claims = verify_access_token(token, ignore_exp=True)
    except JWTError:
        # Malformed/unsigned token — nothing valid to revoke.
        return {"message": "Signed out successfully."}

    user_id, session_id = claims.get("sub"), claims.get("session_id")
    if user_id and session_id:
        await db.update_session(session_id, {
            "is_active":     False,
            "revoked_at":    datetime.now(timezone.utc).isoformat(),
            "revoke_reason": "logout",
        })
        await remove_user_session(user_id, session_id)

        await db.log_audit({
            "user_id":    user_id,
            "event_type": "logout",
            "outcome":    "success",
            "ip_address": ip,
        })

    return {"message": "Signed out successfully."}


# ── Refresh ───────────────────────────────────────────────────
@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(
    request:  Request,
    response: Response,
    db:       SupabaseDB = Depends(db_dependency),
    refresh_cookie: Optional[str] = Cookie(None, alias=settings.session_cookie_name),
) -> LoginResponse:
    if not refresh_cookie:
        raise HTTPException(401, "No refresh token.")

    token_hash = hash_token(refresh_cookie)
    session    = await db.get_session_by_token_hash(token_hash)

    if not session:
        raise HTTPException(401, "Invalid or expired session.")

    expires_at = datetime.fromisoformat(session["expires_at"].replace("Z", "+00:00"))
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(401, "Session expired.")

    user = await db.get_user_by_id(session["user_id"])
    if not user or not user["is_active"]:
        raise HTTPException(403, "Account deactivated.")

    # Rotate refresh token
    new_raw_rt, new_rt_hash = generate_refresh_token()
    new_session_id          = str(uuid.uuid4())
    new_expires             = (datetime.now(timezone.utc) + timedelta(seconds=settings.jwt_refresh_ttl)).isoformat()

    await db.update_session(session["id"], {
        "is_active":    False,
        "revoked_at":   datetime.now(timezone.utc).isoformat(),
        "revoke_reason": "rotated",
    })
    await remove_user_session(user["id"], session["id"])

    mfa_verified = bool(session.get("mfa_verified", False))
    await db.create_session({
        "id":                 new_session_id,
        "user_id":            user["id"],
        "refresh_token_hash": new_rt_hash,
        "ip_address":         get_client_ip(request),
        "is_active":          True,
        "expires_at":         new_expires,
        "mfa_verified":       mfa_verified,   # MFA proof survives rotation, never upgrades
    })
    await add_user_session(user["id"], new_session_id)

    # Re-fetch module permissions on token refresh (group may have changed)
    module_permissions = await db.get_member_module_permissions(
        user_id=user["id"],
        institution_id=user["institution_id"],
    )

    access_token, exp = issue_access_token(
        user_id=user["id"],
        institution_id=user["institution_id"],
        role=user["role"],
        session_id=new_session_id,
        extra_claims={
            "email":              user["email"],
            "module_permissions": module_permissions,
            "amr":                amr_for(mfa_verified),
        },
    )
    _set_refresh_cookie(response, new_raw_rt)

    return LoginResponse(
        access_token=access_token,
        expires_in=settings.jwt_access_ttl,
        must_change_password=bool(user.get("must_change_password", False)),
    )


# ── Me ────────────────────────────────────────────────────────
@router.get("/me", response_model=MeResponse)
async def me(
    db:      SupabaseDB = Depends(db_dependency),
    current: AuthenticatedUser = Depends(get_current_user),
) -> MeResponse:
    user = await db.get_user_by_id(current.user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    return MeResponse(
        user_id=user["id"],
        email=user["email"],
        role=user["role"],
        institution_id=user["institution_id"],
        email_verified=user["email_verified"],
        mfa_enabled=user["mfa_enabled"],
    )


# ── Password: forgot ──────────────────────────────────────────
@router.post("/password/forgot", response_model=ForgotPasswordResponse)
async def forgot_password(
    body:    ForgotPasswordRequest,
    request: Request,
    db:      SupabaseDB = Depends(db_dependency),
) -> ForgotPasswordResponse:
    ip = get_client_ip(request)
    allowed, _ = await check_rate_limit(f"forgot:{ip}", limit=3, window=3600)
    if not allowed:
        raise HTTPException(429, "Too many requests.")

    # Resolve user by username (primary) or email (fallback)
    user = None
    if body.username:
        user = await db.get_user_by_username(body.username)
    if not user and body.email:
        user = await db.get_user_by_email(body.email)
    msg = ForgotPasswordResponse(message="If that account exists, a reset link has been sent.")

    if not user:
        return msg

    raw_token  = generate_secure_token()
    token_hash = hash_token(raw_token)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=settings.password_reset_ttl)).isoformat()

    await db.create_password_reset_token({
        "user_id":    user["id"],
        "token_hash": token_hash,
        "expires_at": expires_at,
        "ip_address": ip,
    })

    reset_url = f"{settings.portal_public_url}/reset-password?token={raw_token}"
    try:
        await send_password_reset_email(user["email"], reset_url)
    except Exception as e:
        log.error("reset_email_failed", error=str(e))

    return msg


# ── Password: reset ───────────────────────────────────────────
@router.post("/password/reset", response_model=PasswordActionResponse)
async def reset_password(
    body: ResetPasswordRequest,
    db:   SupabaseDB = Depends(db_dependency),
) -> PasswordActionResponse:
    token_hash = hash_token(body.token)
    token      = await db.get_password_reset_token(token_hash)

    if not token:
        raise HTTPException(400, "Invalid or expired reset token.")

    expires_at = datetime.fromisoformat(token["expires_at"].replace("Z", "+00:00"))
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(400, "Reset token has expired.")

    try:
        validate_password_policy(body.new_password)
    except PasswordPolicyError as e:
        raise HTTPException(400, str(e))

    new_hash = hash_password(body.new_password)
    await db.update_user(token["user_id"], {
        "password_hash":        new_hash,
        "password_changed_at":  datetime.now(timezone.utc).isoformat(),
        "force_password_reset": False,
    })
    await db.mark_reset_token_used(token["id"])

    return PasswordActionResponse(message="Password reset successfully.")


# ── Password: change ──────────────────────────────────────────
@router.post("/password/change", response_model=PasswordActionResponse)
async def change_password(
    body:    ChangePasswordRequest,
    db:      SupabaseDB = Depends(db_dependency),
    current: AuthenticatedUser = Depends(get_current_user),
) -> PasswordActionResponse:
    user = await db.get_user_by_id(current.user_id)
    if not user:
        raise HTTPException(404, "User not found.")

    if not verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(401, "Current password is incorrect.")

    try:
        validate_password_policy(body.new_password)
    except PasswordPolicyError as e:
        raise HTTPException(400, str(e))

    await db.update_user(user["id"], {
        "password_hash":       hash_password(body.new_password),
        "password_changed_at": datetime.now(timezone.utc).isoformat(),
    })

    return PasswordActionResponse(message="Password changed successfully.")


# ── Email: verify ─────────────────────────────────────────────
@router.post("/email/verify")
async def verify_email(
    body: VerifyEmailRequest,
    db:   SupabaseDB = Depends(db_dependency),
) -> dict:
    token_hash = hash_token(body.token)
    token      = await db.get_email_verification_token(token_hash)

    if not token:
        raise HTTPException(400, "Invalid or expired verification token.")

    expires_at = datetime.fromisoformat(token["expires_at"].replace("Z", "+00:00"))
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(400, "Verification token has expired.")

    await db.mark_email_verified(token["id"], token["user_id"])
    return {"message": "Email verified successfully."}


# ── Sessions ──────────────────────────────────────────────────
@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    db:      SupabaseDB = Depends(db_dependency),
    current: AuthenticatedUser = Depends(get_current_user),
) -> SessionListResponse:
    sessions = await db.get_sessions_by_user(current.user_id)
    return SessionListResponse(sessions=[
        SessionInfo(
            id=s["id"],
            ip_address=s.get("ip_address"),
            user_agent=s.get("user_agent"),
            created_at=s["created_at"],
            last_used_at=s["last_used_at"],
            is_current=(s["id"] == current.session_id),
        )
        for s in sessions
    ])


@router.delete("/sessions")
async def revoke_all_sessions(
    db:      SupabaseDB = Depends(db_dependency),
    current: AuthenticatedUser = Depends(get_current_user),
) -> dict:
    await db.revoke_all_user_sessions(current.user_id, except_id=current.session_id)
    return {"message": "All other sessions revoked."}

# =============================================================
# ficium-auth — Auth API router (Supabase REST DB backend)
# =============================================================

import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie

from ..core.database import db_dependency, SupabaseDB
from ..core.config import settings
from ..core.security import (
    hash_password, verify_password, validate_password_policy,
    PasswordPolicyError, issue_access_token, generate_secure_token,
    hash_token, generate_refresh_token,
)
from ..core.redis import (
    check_rate_limit, is_locked_out, record_failed_login,
    clear_failed_logins, add_user_session,
    remove_user_session, get_user_session_ids, cache_set, cache_get,
    RedisKeys,
)
from ..schemas.auth import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    ForgotPasswordRequest, ForgotPasswordResponse,
    ResetPasswordRequest, ChangePasswordRequest, PasswordActionResponse,
    VerifyEmailRequest, ResendVerificationRequest,
    SessionListResponse, SessionInfo, MeResponse,
)
from ..services.email import (
    send_verification_email, send_password_reset_email,
    send_suspicious_login_alert, send_lockout_alert,
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
        samesite=settings.session_cookie_samesite,
        domain=settings.session_cookie_domain if settings.is_production else None,
        max_age=settings.jwt_refresh_ttl,
        path="/auth/refresh",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/auth/refresh",
    )


# ── Register ──────────────────────────────────────────────────
@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
    body:    RegisterRequest,
    request: Request,
    db:      SupabaseDB = Depends(db_dependency),
) -> RegisterResponse:
    ip = get_client_ip(request)

    allowed, _ = await check_rate_limit(f"register:{ip}", limit=3, window=3600)
    if not allowed:
        raise HTTPException(429, "Too many registration attempts.")

    try:
        validate_password_policy(body.password)
    except PasswordPolicyError as e:
        raise HTTPException(400, str(e))

    existing = await db.get_user_by_email(body.email)
    if existing:
        return RegisterResponse(
            user_id=str(uuid.uuid4()),
            needs_email_verification=True,
            message="If that email is not registered, you'll receive a verification email.",
        )

    pw_hash        = hash_password(body.password)
    institution_id = await _create_institution(body)

    user = await db.create_user({
        "institution_id": str(institution_id),
        "email":          body.email,
        "email_verified": False,
        "password_hash":  pw_hash,
        "role":           "admin",
        "is_active":      True,
    })

    raw_token  = generate_secure_token()
    token_hash = hash_token(raw_token)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=settings.email_verify_ttl)).isoformat()

    await db.create_email_verification_token({
        "user_id":    user["id"],
        "token_hash": token_hash,
        "expires_at": expires_at,
    })

    verify_url = f"https://{settings.session_cookie_domain}/verify-email?token={raw_token}"
    try:
        await send_verification_email(body.email, verify_url)
    except Exception as e:
        log.error("verification_email_failed", error=str(e))

    await db.log_audit({
        "user_id":        user["id"],
        "institution_id": str(institution_id),
        "event_type":     "register.success",
        "outcome":        "success",
        "ip_address":     ip,
    })

    return RegisterResponse(
        user_id=str(user["id"]),
        needs_email_verification=True,
        message="Account created. Check your email to verify.",
    )


async def _create_institution(body: RegisterRequest) -> uuid.UUID:
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{settings.supabase_url}/rest/v1/institutions",
            headers={
                "apikey":          settings.supabase_service_key,
                "Authorization":   f"Bearer {settings.supabase_service_key}",
                "Content-Type":    "application/json",
                "Accept":          "application/json",
                "Prefer":          "return=representation",
                "Accept-Profile":  "institution",
                "Content-Profile": "institution",
            },
            json={
                "name":                  body.institution_name,
                "legal_name":            body.institution_name,
                "institution_type":      body.institution_type,
                "reg_number":            body.reg_number,
                "regulator":             body.regulatory_body,
                "country":               body.country,
                "website":               body.website,
                "deployment_model":      "saas",
                "onboarding_stage":      "registered",
                "compliance_status":     "not_submitted",
                "approved":              False,
                "primary_contact_email": body.email,
                "primary_contact_name":  f"{body.first_name} {body.last_name}",
                "primary_contact_phone": body.phone,
            },
        )
        resp.raise_for_status()
        return uuid.UUID(resp.json()[0]["id"])


# ── Login ─────────────────────────────────────────────────────
@router.post("/login", response_model=LoginResponse)
async def login(
    body:     LoginRequest,
    request:  Request,
    response: Response,
    db:       SupabaseDB = Depends(db_dependency),
) -> LoginResponse:
    ip         = get_client_ip(request)
    user_agent = get_user_agent(request)

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

    session_id         = str(uuid.uuid4())
    raw_rt, rt_hash    = generate_refresh_token()
    access_token, exp  = issue_access_token(
        user_id=user["id"],
        institution_id=user["institution_id"],
        role=user["role"],
        session_id=session_id,
        extra_claims={"email": user["email"]},
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
        "event_metadata": {"session_id": session_id},
    })

    return LoginResponse(
        access_token=access_token,
        expires_in=settings.jwt_access_ttl,
        must_change_password=bool(user.get("must_change_password", False)),
    )


# ── Forced password change (after admin reset) ────────────────
@router.post("/password/force-change", response_model=PasswordActionResponse)
async def force_change_password(
    body:    ChangePasswordRequest,
    request: Request,
    db:      SupabaseDB = Depends(db_dependency),
    current: AuthenticatedUser = Depends(get_current_user),
) -> PasswordActionResponse:
    """
    Used when must_change_password=true. Verifies current (temp) password,
    sets the new one, and clears the must_change_password flag.
    """
    user = await db.get_user_by_id(current.user_id)
    if not user:
        raise HTTPException(404, "User not found.")

    ph = PasswordHasher()
    try:
        ph.verify(user["password_hash"], body.current_password)
    except Exception:
        raise HTTPException(401, "Current password is incorrect.")

    new_hash = ph.hash(body.new_password)
    await db.update_user(current.user_id, {
        "password_hash":        new_hash,
        "must_change_password": False,
        "updated_at":           datetime.now(timezone.utc).isoformat(),
    })

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
    current:  AuthenticatedUser = Depends(get_current_user),
) -> dict:
    ip = get_client_ip(request)

    await db.update_session(current.session_id, {
        "is_active":    False,
        "revoked_at":   datetime.now(timezone.utc).isoformat(),
        "revoke_reason": "logout",
    })
    await remove_user_session(current.user_id, current.session_id)
    _clear_refresh_cookie(response)

    await db.log_audit({
        "user_id":    current.user_id,
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

    await db.create_session({
        "id":                 new_session_id,
        "user_id":            user["id"],
        "refresh_token_hash": new_rt_hash,
        "ip_address":         get_client_ip(request),
        "is_active":          True,
        "expires_at":         new_expires,
    })
    await add_user_session(user["id"], new_session_id)

    access_token, exp = issue_access_token(
        user_id=user["id"],
        institution_id=user["institution_id"],
        role=user["role"],
        session_id=new_session_id,
        extra_claims={"email": user["email"]},
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

    reset_url = f"https://{settings.session_cookie_domain}/reset-password?token={raw_token}"
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

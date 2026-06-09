# =============================================================
# ficium-auth — Auth API router
# All endpoints: register, login, logout, refresh,
# MFA, password management, email verification, sessions
# =============================================================

import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from ..core.database import db_dependency
from ..core.config import settings
from ..core.security import (
    hash_password, verify_password, validate_password_policy,
    PasswordPolicyError, issue_access_token, generate_secure_token,
    hash_token, verify_token_hash, generate_refresh_token,
)
from ..core.redis import (
    check_rate_limit, is_locked_out, record_failed_login,
    clear_failed_logins, blacklist_token, add_user_session,
    remove_user_session, get_user_session_ids, cache_set, cache_get, cache_delete,
    RedisKeys,
)
from ..models.auth import (
    AuthUser, AuthSession, MFABackupCode,
    PasswordResetToken, EmailVerificationToken,
)
from ..schemas.auth import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    MFAEnrolResponse, MFAVerifyEnrolRequest,
    MFAVerifyRequest, MFAVerifyResponse, MFADisableRequest,
    ForgotPasswordRequest, ForgotPasswordResponse,
    ResetPasswordRequest, ChangePasswordRequest, PasswordActionResponse,
    VerifyEmailRequest, ResendVerificationRequest,
    SessionListResponse, SessionInfo, MeResponse,
    ErrorResponse,
)
from ..services.audit import AuditService, AuditEvent
from ..services.email import (
    send_verification_email, send_password_reset_email,
    send_suspicious_login_alert, send_lockout_alert,
)
from ..services.mfa import (
    generate_totp_secret, generate_qr_uri,
    verify_totp, generate_fresh_backup_codes, verify_backup_code,
)
from ..middleware.auth_middleware import get_current_user, AuthenticatedUser, get_client_ip, get_user_agent

log = structlog.get_logger()
router = APIRouter(prefix="/auth", tags=["Authentication"])


# ── Helpers ───────────────────────────────────────────────────

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


async def _get_user_by_email(db: AsyncSession, email: str) -> Optional[AuthUser]:
    result = await db.execute(select(AuthUser).where(AuthUser.email == email))
    return result.scalar_one_or_none()


async def _get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> Optional[AuthUser]:
    result = await db.execute(select(AuthUser).where(AuthUser.id == user_id))
    return result.scalar_one_or_none()


# ── Register ──────────────────────────────────────────────────
@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
    body:     RegisterRequest,
    request:  Request,
    db:       AsyncSession = Depends(db_dependency),
) -> RegisterResponse:
    ip      = get_client_ip(request)
    audit   = AuditService(db)

    # Rate limit registration per IP
    allowed, _ = await check_rate_limit(f"register:{ip}", limit=3, window=3600)
    if not allowed:
        raise HTTPException(429, "Too many registration attempts. Try again later.")

    # Validate password policy
    try:
        validate_password_policy(body.password)
    except PasswordPolicyError as e:
        raise HTTPException(400, str(e))

    # Check email uniqueness
    existing = await _get_user_by_email(db, body.email)
    if existing:
        # No user enumeration — return success either way
        # But don't create duplicate
        await audit.log(AuditEvent.REGISTER_FAILED, "failed", ip_address=ip,
                        metadata={"reason": "duplicate_email"})
        return RegisterResponse(
            user_id=str(uuid.uuid4()),  # fake ID
            needs_email_verification=True,
            message="If that email is not registered, you'll receive a verification email.",
        )

    # Hash password
    pw_hash = hash_password(body.password)

    # Create institution row in institution schema (via Supabase service key)
    # This calls Supabase directly since institution data lives there
    institution_id = await _create_institution(body)

    # Create auth user
    user = AuthUser(
        institution_id=institution_id,
        email=body.email,
        password_hash=pw_hash,
        role="admin",
        email_verified=False,
    )
    db.add(user)
    await db.flush()

    # Create email verification token
    raw_token = generate_secure_token()
    token_hash = hash_token(raw_token)

    verify_token = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.email_verify_ttl),
    )
    db.add(verify_token)
    await db.flush()

    # Send verification email
    verify_url = f"https://{settings.session_cookie_domain}/verify-email?token={raw_token}"
    try:
        await send_verification_email(body.email, verify_url)
    except Exception as e:
        log.error("verification_email_failed", error=str(e), user_id=str(user.id))

    await audit.log(
        AuditEvent.REGISTER_SUCCESS, "success",
        user_id=user.id, institution_id=institution_id,
        ip_address=ip,
    )

    return RegisterResponse(
        user_id=str(user.id),
        needs_email_verification=True,
        message="Account created. Check your email to verify.",
    )


async def _create_institution(body: RegisterRequest) -> uuid.UUID:
    """Create institution row in Supabase institution schema."""
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{settings.supabase_url}/rest/v1/institutions",
            headers={
                "apikey": settings.supabase_service_key,
                "Authorization": f"Bearer {settings.supabase_service_key}",
                "Content-Type": "application/json",
                "Prefer": "return=representation",
                "Accept-Profile": "institution",
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
                "modules":               ["marketplace"],
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
    db:       AsyncSession = Depends(db_dependency),
) -> LoginResponse:
    ip         = get_client_ip(request)
    user_agent = get_user_agent(request)
    audit      = AuditService(db)

    # Rate limit
    allowed, remaining = await check_rate_limit(
        f"login:{ip}", settings.rate_limit_login, settings.rate_limit_login_window
    )
    if not allowed:
        raise HTTPException(429, "Too many login attempts. Try again later.")

    # Check lockout
    if await is_locked_out(ip):
        await audit.log(AuditEvent.LOGIN_LOCKED, "blocked", ip_address=ip,
                        metadata={"email": body.email})
        raise HTTPException(429, "Account temporarily locked due to repeated failed attempts.")

    # Fetch user — constant time regardless of existence
    user = await _get_user_by_email(db, body.email)

    # Verify password — always run hash to prevent timing attacks
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$dummy"
    pw_ok = verify_password(body.password, user.password_hash if user else dummy_hash)

    if not user or not pw_ok:
        await record_failed_login(ip, str(user.id) if user else None)
        await audit.log(AuditEvent.LOGIN_FAILED, "failed", ip_address=ip,
                        user_id=user.id if user else None,
                        metadata={"email": body.email})

        # Send lockout alert if threshold reached
        if user:
            fail_count = int(await record_failed_login(ip))
            if fail_count >= settings.lockout_threshold:
                try:
                    await send_lockout_alert(user.email, ip, fail_count)
                except Exception:
                    pass

        raise HTTPException(401, "Incorrect email or password.")

    if not user.is_active:
        raise HTTPException(403, "Account is deactivated. Contact your administrator.")

    # Clear failed attempts on success
    await clear_failed_logins(ip, str(user.id))

    # Check if MFA required
    if user.mfa_enabled:
        # Issue short-lived MFA challenge token
        challenge_id = generate_secure_token(16)
        await cache_set(
            RedisKeys.mfa_challenge(challenge_id),
            {"user_id": str(user.id), "ip": ip},
            settings.mfa_challenge_ttl,
        )
        await audit.log(AuditEvent.LOGIN_SUCCESS, "mfa_required",
                        user_id=user.id, institution_id=user.institution_id,
                        ip_address=ip)
        return LoginResponse(mfa_required=True, mfa_token=challenge_id)

    # Issue tokens
    session_id = str(uuid.uuid4())
    raw_rt, rt_hash = generate_refresh_token()

    access_token, expires_at = issue_access_token(
        user_id=str(user.id),
        institution_id=str(user.institution_id),
        role=user.role,
        session_id=session_id,
    )

    # Check concurrent session limit
    session_ids = await get_user_session_ids(str(user.id))
    if len(session_ids) >= settings.session_max_concurrent:
        # Evict oldest session
        oldest = next(iter(session_ids))
        await remove_user_session(str(user.id), oldest)
        await db.execute(
            update(AuthSession)
            .where(AuthSession.id == uuid.UUID(oldest))
            .values(is_active=False, revoked_at=datetime.now(timezone.utc), revoke_reason="session_limit")
        )

    # Detect suspicious login (new IP)
    if user.last_login_ip and user.last_login_ip != ip:
        try:
            await send_suspicious_login_alert(
                to=user.email,
                ip=ip,
                device=user_agent[:100],
                time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                revoke_url=f"https://{settings.session_cookie_domain}/settings/sessions",
            )
        except Exception:
            pass
        await audit.log(AuditEvent.SUSPICIOUS_LOGIN, "logged",
                        user_id=user.id, ip_address=ip)

    # Store session
    expires = datetime.now(timezone.utc) + timedelta(seconds=settings.jwt_refresh_ttl)
    session = AuthSession(
        id=uuid.UUID(session_id),
        user_id=user.id,
        refresh_token_hash=rt_hash,
        ip_address=ip,
        user_agent=user_agent,
        expires_at=expires,
    )
    db.add(session)

    # Update user last login
    await db.execute(
        update(AuthUser)
        .where(AuthUser.id == user.id)
        .values(last_login_at=datetime.now(timezone.utc), last_login_ip=ip)
    )

    await add_user_session(str(user.id), session_id)

    # Set refresh token cookie
    _set_refresh_cookie(response, raw_rt)

    await audit.log(AuditEvent.LOGIN_SUCCESS, "success",
                    user_id=user.id, institution_id=user.institution_id,
                    ip_address=ip, metadata={"session_id": session_id})

    return LoginResponse(
        access_token=access_token,
        expires_in=settings.jwt_access_ttl,
    )


# ── Token refresh ─────────────────────────────────────────────
@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(
    request:  Request,
    response: Response,
    db:       AsyncSession = Depends(db_dependency),
    refresh_cookie: Optional[str] = Cookie(None, alias=settings.session_cookie_name),
) -> LoginResponse:
    ip    = get_client_ip(request)
    audit = AuditService(db)

    if not refresh_cookie:
        raise HTTPException(401, "No refresh token.")

    token_hash = hash_token(refresh_cookie)
    result = await db.execute(
        select(AuthSession).where(
            AuthSession.refresh_token_hash == token_hash,
            AuthSession.is_active == True,
        )
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(401, "Invalid or expired session.")

    if session.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        await db.execute(
            update(AuthSession).where(AuthSession.id == session.id)
            .values(is_active=False, revoke_reason="expired")
        )
        _clear_refresh_cookie(response)
        raise HTTPException(401, "Session expired.")

    user = await _get_user_by_id(db, session.user_id)
    if not user or not user.is_active:
        raise HTTPException(401, "Account inactive.")

    # Rotate refresh token
    new_raw_rt, new_rt_hash = generate_refresh_token()
    await db.execute(
        update(AuthSession).where(AuthSession.id == session.id)
        .values(
            refresh_token_hash=new_rt_hash,
            last_used_at=datetime.now(timezone.utc),
        )
    )

    access_token, _ = issue_access_token(
        user_id=str(user.id),
        institution_id=str(user.institution_id),
        role=user.role,
        session_id=str(session.id),
    )

    _set_refresh_cookie(response, new_raw_rt)

    await audit.log(AuditEvent.TOKEN_REFRESH, "success",
                    user_id=user.id, ip_address=ip)

    return LoginResponse(access_token=access_token, expires_in=settings.jwt_access_ttl)


# ── Logout ────────────────────────────────────────────────────
@router.post("/logout")
async def logout(
    request:  Request,
    response: Response,
    db:       AsyncSession = Depends(db_dependency),
    current_user: AuthenticatedUser = Depends(get_current_user),
    refresh_cookie: Optional[str] = Cookie(None, alias=settings.session_cookie_name),
) -> dict:
    ip    = get_client_ip(request)
    audit = AuditService(db)

    # Blacklist current access token
    await blacklist_token(current_user.jti, settings.jwt_access_ttl)

    # Revoke session
    if refresh_cookie:
        token_hash = hash_token(refresh_cookie)
        await db.execute(
            update(AuthSession)
            .where(AuthSession.refresh_token_hash == token_hash)
            .values(is_active=False, revoked_at=datetime.now(timezone.utc), revoke_reason="logout")
        )

    await remove_user_session(current_user.user_id, current_user.session_id)
    _clear_refresh_cookie(response)

    await audit.log(AuditEvent.LOGOUT, "success",
                    user_id=uuid.UUID(current_user.user_id), ip_address=ip)

    return {"message": "Signed out successfully."}


# ── MFA enrol ─────────────────────────────────────────────────
@router.post("/mfa/enrol", response_model=MFAEnrolResponse)
async def mfa_enrol(
    db: AsyncSession = Depends(db_dependency),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> MFAEnrolResponse:
    user = await _get_user_by_id(db, uuid.UUID(current_user.user_id))
    if not user:
        raise HTTPException(404, "User not found.")
    if user.mfa_enabled:
        raise HTTPException(400, "MFA is already enabled.")

    secret = generate_totp_secret()
    qr_uri = generate_qr_uri(secret, user.email)
    plain_codes, hashed_codes = generate_fresh_backup_codes()

    # Store secret temporarily (not active until verified)
    await cache_set(
        f"mfa_pending:{user.id}",
        {"secret": secret, "backup_hashes": hashed_codes},
        ttl=600,  # 10 min to complete enrolment
    )

    return MFAEnrolResponse(
        secret=secret,
        qr_code_uri=qr_uri,
        backup_codes=plain_codes,
    )


@router.post("/mfa/verify-enrolment")
async def mfa_verify_enrolment(
    body: MFAVerifyEnrolRequest,
    db:   AsyncSession = Depends(db_dependency),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict:
    user = await _get_user_by_id(db, uuid.UUID(current_user.user_id))
    if not user:
        raise HTTPException(404, "User not found.")

    pending = await cache_get(f"mfa_pending:{user.id}")
    if not pending:
        raise HTTPException(400, "No pending MFA enrolment. Start enrolment again.")

    if not verify_totp(pending["secret"], body.totp_code):
        raise HTTPException(400, "Invalid TOTP code.")

    # Activate MFA
    await db.execute(
        update(AuthUser).where(AuthUser.id == user.id)
        .values(mfa_enabled=True, mfa_secret=pending["secret"])
    )

    # Store backup codes
    for hashed in pending["backup_hashes"]:
        db.add(MFABackupCode(user_id=user.id, code_hash=hashed))

    await cache_delete(f"mfa_pending:{user.id}")

    audit = AuditService(db)
    await audit.log(AuditEvent.MFA_ENROLLED, "success", user_id=user.id)

    return {"message": "MFA enabled successfully."}


@router.post("/mfa/verify", response_model=MFAVerifyResponse)
async def mfa_verify(
    body:     MFAVerifyRequest,
    request:  Request,
    response: Response,
    db:       AsyncSession = Depends(db_dependency),
) -> MFAVerifyResponse:
    ip    = get_client_ip(request)
    audit = AuditService(db)

    challenge = await cache_get(RedisKeys.mfa_challenge(body.mfa_token))
    if not challenge:
        raise HTTPException(401, "MFA challenge expired or invalid.")

    user = await _get_user_by_id(db, uuid.UUID(challenge["user_id"]))
    if not user:
        raise HTTPException(401, "User not found.")

    verified = False

    if body.totp_code:
        verified = verify_totp(user.mfa_secret, body.totp_code)
        if not verified:
            await audit.log(AuditEvent.MFA_FAILED, "failed", user_id=user.id, ip_address=ip)
            raise HTTPException(401, "Invalid TOTP code.")

    elif body.backup_code:
        result = await db.execute(
            select(MFABackupCode)
            .where(MFABackupCode.user_id == user.id, MFABackupCode.used_at == None)
        )
        codes = result.scalars().all()
        hashes = [c.code_hash for c in codes]
        idx = verify_backup_code(body.backup_code, hashes)

        if idx is None:
            await audit.log(AuditEvent.MFA_FAILED, "failed", user_id=user.id, ip_address=ip)
            raise HTTPException(401, "Invalid backup code.")

        # Mark backup code as used
        await db.execute(
            update(MFABackupCode)
            .where(MFABackupCode.id == codes[idx].id)
            .values(used_at=datetime.now(timezone.utc))
        )
        await audit.log(AuditEvent.MFA_BACKUP_USED, "success", user_id=user.id, ip_address=ip)
        verified = True
    else:
        raise HTTPException(400, "Provide totp_code or backup_code.")

    await cache_delete(RedisKeys.mfa_challenge(body.mfa_token))

    session_id = str(uuid.uuid4())
    access_token, _ = issue_access_token(
        user_id=str(user.id),
        institution_id=str(user.institution_id),
        role=user.role,
        session_id=session_id,
    )

    await audit.log(AuditEvent.MFA_VERIFIED, "success",
                    user_id=user.id, institution_id=user.institution_id, ip_address=ip)

    return MFAVerifyResponse(access_token=access_token, expires_in=settings.jwt_access_ttl)


# ── Password: forgot ──────────────────────────────────────────
@router.post("/password/forgot", response_model=ForgotPasswordResponse)
async def forgot_password(
    body:    ForgotPasswordRequest,
    request: Request,
    db:      AsyncSession = Depends(db_dependency),
) -> ForgotPasswordResponse:
    ip    = get_client_ip(request)

    # Rate limit
    allowed, _ = await check_rate_limit(f"forgot:{ip}", limit=3, window=3600)
    if not allowed:
        raise HTTPException(429, "Too many requests.")

    user = await _get_user_by_email(db, body.email)

    # Always return same response — no user enumeration
    if user:
        raw_token  = generate_secure_token()
        token_hash = hash_token(raw_token)
        expires    = datetime.now(timezone.utc) + timedelta(seconds=settings.password_reset_ttl)

        db.add(PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            ip_address=ip,
            expires_at=expires,
        ))
        await db.flush()

        reset_url = f"https://{settings.session_cookie_domain}/reset-password?token={raw_token}"
        try:
            await send_password_reset_email(user.email, reset_url)
        except Exception as e:
            log.error("reset_email_failed", error=str(e))

        audit = AuditService(db)
        await audit.log(AuditEvent.PASSWORD_RESET_REQUESTED, "success",
                        user_id=user.id, ip_address=ip)

    return ForgotPasswordResponse()


# ── Password: reset ───────────────────────────────────────────
@router.post("/password/reset", response_model=PasswordActionResponse)
async def reset_password(
    body:    ResetPasswordRequest,
    request: Request,
    db:      AsyncSession = Depends(db_dependency),
) -> PasswordActionResponse:
    ip    = get_client_ip(request)
    audit = AuditService(db)

    token_hash = hash_token(body.token)
    result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used == False,
        )
    )
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(400, "Invalid or expired reset link.")
    if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(400, "Reset link has expired. Request a new one.")

    try:
        validate_password_policy(body.new_password)
    except PasswordPolicyError as e:
        raise HTTPException(400, str(e))

    new_hash = hash_password(body.new_password)

    # Update password + invalidate all sessions
    await db.execute(
        update(AuthUser).where(AuthUser.id == token_record.user_id)
        .values(password_hash=new_hash, password_changed_at=datetime.now(timezone.utc))
    )
    await db.execute(
        update(AuthSession).where(AuthSession.user_id == token_record.user_id)
        .values(is_active=False, revoke_reason="password_reset")
    )
    await db.execute(
        update(PasswordResetToken).where(PasswordResetToken.id == token_record.id)
        .values(used=True, used_at=datetime.now(timezone.utc))
    )

    await audit.log(AuditEvent.PASSWORD_RESET_COMPLETED, "success",
                    user_id=token_record.user_id, ip_address=ip)

    return PasswordActionResponse(message="Password updated. Please sign in with your new password.")


# ── Password: change (authenticated) ─────────────────────────
@router.post("/password/change", response_model=PasswordActionResponse)
async def change_password(
    body:    ChangePasswordRequest,
    request: Request,
    db:      AsyncSession = Depends(db_dependency),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> PasswordActionResponse:
    ip    = get_client_ip(request)
    audit = AuditService(db)
    user  = await _get_user_by_id(db, uuid.UUID(current_user.user_id))

    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(401, "Current password is incorrect.")

    if user.mfa_enabled:
        if not body.totp_code or not verify_totp(user.mfa_secret, body.totp_code):
            raise HTTPException(401, "Valid TOTP code required to change password.")

    try:
        validate_password_policy(body.new_password)
    except PasswordPolicyError as e:
        raise HTTPException(400, str(e))

    new_hash = hash_password(body.new_password)
    await db.execute(
        update(AuthUser).where(AuthUser.id == user.id)
        .values(password_hash=new_hash, password_changed_at=datetime.now(timezone.utc))
    )
    # Revoke all other sessions
    await db.execute(
        update(AuthSession).where(
            AuthSession.user_id == user.id,
            AuthSession.id != uuid.UUID(current_user.session_id),
        ).values(is_active=False, revoke_reason="password_changed")
    )

    await audit.log(AuditEvent.PASSWORD_CHANGED, "success", user_id=user.id, ip_address=ip)
    return PasswordActionResponse(message="Password updated. Other sessions have been signed out.")


# ── Email verification ────────────────────────────────────────
@router.post("/email/verify")
async def verify_email(
    body: VerifyEmailRequest,
    db:   AsyncSession = Depends(db_dependency),
) -> dict:
    token_hash = hash_token(body.token)
    result = await db.execute(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token_hash == token_hash,
            EmailVerificationToken.used == False,
        )
    )
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(400, "Invalid or expired verification link.")
    if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(400, "Verification link expired. Request a new one.")

    await db.execute(
        update(AuthUser).where(AuthUser.id == token_record.user_id)
        .values(email_verified=True)
    )
    await db.execute(
        update(EmailVerificationToken).where(EmailVerificationToken.id == token_record.id)
        .values(used=True)
    )

    audit = AuditService(db)
    await audit.log(AuditEvent.EMAIL_VERIFIED, "success", user_id=token_record.user_id)
    return {"message": "Email verified successfully."}


# ── Sessions ──────────────────────────────────────────────────
@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    db: AsyncSession = Depends(db_dependency),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> SessionListResponse:
    result = await db.execute(
        select(AuthSession).where(
            AuthSession.user_id == uuid.UUID(current_user.user_id),
            AuthSession.is_active == True,
        ).order_by(AuthSession.last_used_at.desc())
    )
    sessions = result.scalars().all()

    return SessionListResponse(
        sessions=[
            SessionInfo(
                session_id=str(s.id),
                ip_address=s.ip_address,
                user_agent=s.user_agent,
                created_at=s.created_at,
                last_used_at=s.last_used_at,
                expires_at=s.expires_at,
                is_current=(str(s.id) == current_user.session_id),
            )
            for s in sessions
        ],
        total=len(sessions),
    )


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    db: AsyncSession = Depends(db_dependency),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict:
    await db.execute(
        update(AuthSession).where(
            AuthSession.id == uuid.UUID(session_id),
            AuthSession.user_id == uuid.UUID(current_user.user_id),
        ).values(is_active=False, revoked_at=datetime.now(timezone.utc), revoke_reason="user_revoked")
    )
    await remove_user_session(current_user.user_id, session_id)

    audit = AuditService(db)
    await audit.log(AuditEvent.SESSION_REVOKED, "success",
                    user_id=uuid.UUID(current_user.user_id),
                    metadata={"session_id": session_id})
    return {"message": "Session revoked."}


@router.delete("/sessions")
async def revoke_all_sessions(
    db: AsyncSession = Depends(db_dependency),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict:
    """Revoke all sessions except current."""
    await db.execute(
        update(AuthSession).where(
            AuthSession.user_id == uuid.UUID(current_user.user_id),
            AuthSession.id != uuid.UUID(current_user.session_id),
        ).values(is_active=False, revoked_at=datetime.now(timezone.utc), revoke_reason="security_logout")
    )
    return {"message": "All other sessions revoked."}


# ── Current user ──────────────────────────────────────────────
@router.get("/me", response_model=MeResponse)
async def me(
    db: AsyncSession = Depends(db_dependency),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> MeResponse:
    user = await _get_user_by_id(db, uuid.UUID(current_user.user_id))
    if not user:
        raise HTTPException(404, "User not found.")

    return MeResponse(
        user_id=str(user.id),
        email=user.email,
        email_verified=user.email_verified,
        role=user.role,
        institution_id=str(user.institution_id),
        mfa_enabled=user.mfa_enabled,
        last_login_at=user.last_login_at,
        last_login_ip=user.last_login_ip,
    )

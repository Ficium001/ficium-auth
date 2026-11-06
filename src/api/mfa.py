# =============================================================
# ficium-auth — MFA (TOTP + backup codes)
#
#   POST /auth/mfa/enrol            (signed in)  -> secret + QR; pending 10 min, nothing stored yet
#   POST /auth/mfa/verify-enrolment (signed in)  -> code proves the app works; MFA on; backup codes once
#   POST /auth/mfa/verify           (mfa_token)  -> completes a login; token amr = ["pwd","otp","mfa"]
#   POST /auth/mfa/disable          (signed in WITH mfa) -> password + current code
#
# Secrets are Fernet-encrypted at rest (MFA_ENCRYPTION_KEY); without the key
# every endpoint here answers 503 and password-only login is unchanged.
# A code can be used once (replay window), a challenge allows 5 attempts,
# failures count toward the normal login lockout.
# =============================================================
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError as JWTError

from ..core.config import settings
from ..core.crypto import MFAUnavailable, decrypt_secret, encrypt_secret
from ..core.database import SupabaseDB, db_dependency
from ..core.redis import (
    RedisKeys,
    cache_delete,
    cache_get,
    cache_set,
    check_rate_limit,
    clear_failed_logins,
    is_locked_out,
    record_failed_login,
)
from ..core.security import verify_access_token, verify_password
from ..middleware.auth_middleware import (
    AuthenticatedUser,
    get_client_ip,
    get_current_user,
)
from ..schemas.auth import (
    LoginResponse,
    MFADisableRequest,
    MFAEnrolConfirmResponse,
    MFAEnrolResponse,
    MFAVerifyEnrolRequest,
    MFAVerifyRequest,
    PasswordActionResponse,
)
from ..services.mfa import (
    generate_fresh_backup_codes,
    generate_qr_code_svg,
    generate_qr_uri,
    generate_totp_secret,
    verify_backup_code,
    verify_totp,
)
from .auth import start_session

log = structlog.get_logger()
router = APIRouter(prefix="/auth/mfa", tags=["MFA"])
_bearer = HTTPBearer(auto_error=False)

ENROL_TTL = 600            # seconds to confirm a new authenticator
CHALLENGE_ATTEMPTS = 5     # codes per login challenge
REPLAY_TTL = 90            # a TOTP code is valid ±30 s; remember it a little longer


def _unavailable(exc: MFAUnavailable) -> HTTPException:
    log.error("mfa_unavailable", error=str(exc))
    return HTTPException(503, "Two-factor authentication is not available right now.")


async def _claims(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> dict[str, Any]:
    if not credentials:
        raise HTTPException(401, "Authentication required.")
    try:
        return verify_access_token(credentials.credentials)
    except JWTError as exc:
        raise HTTPException(401, "Invalid or expired token.") from exc


async def _code_ok(user_id: str, secret: str, code: str) -> bool:
    """TOTP check with single use: the same code cannot be replayed within its window."""
    if not verify_totp(secret, code):
        return False
    key = RedisKeys.mfa_used_code(user_id, code)
    if await cache_get(key):
        return False
    await cache_set(key, 1, REPLAY_TTL)
    return True


@router.post("/enrol", response_model=MFAEnrolResponse)
async def enrol(
    current: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseDB = Depends(db_dependency),
) -> MFAEnrolResponse:
    user = await db.get_user_by_id(current.user_id)
    if not user or not user["is_active"]:
        raise HTTPException(403, "Account deactivated.")
    if user.get("mfa_enabled"):
        raise HTTPException(409, "Two-factor authentication is already on. Turn it off first to change device.")
    secret = generate_totp_secret()
    try:
        await cache_set(RedisKeys.mfa_pending(current.user_id), {"secret": encrypt_secret(secret)}, ENROL_TTL)
    except MFAUnavailable as exc:
        raise _unavailable(exc)
    uri = generate_qr_uri(secret, user["email"])
    return MFAEnrolResponse(secret=secret, qr_code_uri=uri, qr_code_svg=generate_qr_code_svg(uri), expires_in=ENROL_TTL)


@router.post("/verify-enrolment", response_model=MFAEnrolConfirmResponse)
async def verify_enrolment(
    body: MFAVerifyEnrolRequest,
    request: Request,
    current: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseDB = Depends(db_dependency),
) -> MFAEnrolConfirmResponse:
    allowed, _ = await check_rate_limit(f"mfa_enrol:{current.user_id}", CHALLENGE_ATTEMPTS, ENROL_TTL)
    if not allowed:
        raise HTTPException(429, "Too many attempts. Start the setup again later.")
    pending = await cache_get(RedisKeys.mfa_pending(current.user_id))
    if not pending:
        raise HTTPException(410, "Setup expired. Start again.")
    try:
        secret = decrypt_secret(pending["secret"])
    except MFAUnavailable as exc:
        raise _unavailable(exc)
    if not await _code_ok(current.user_id, secret, body.totp_code):
        await db.log_audit({"user_id": current.user_id, "event_type": "mfa.failed", "outcome": "failed",
                            "ip_address": get_client_ip(request), "event_metadata": {"stage": "enrolment"}})
        raise HTTPException(400, "That code didn't match. Check the time on your phone and try again.")

    plain, hashed = generate_fresh_backup_codes()
    await db.update_user(current.user_id, {"mfa_enabled": True, "mfa_secret": pending["secret"]})
    await db.replace_backup_codes(current.user_id, hashed)
    await cache_delete(RedisKeys.mfa_pending(current.user_id))
    # Sessions opened before MFA existed must not carry on: sign in again with MFA.
    await db.revoke_all_user_sessions(current.user_id)
    await db.log_audit({"user_id": current.user_id, "institution_id": current.institution_id,
                        "event_type": "mfa.enrolled", "outcome": "success", "ip_address": get_client_ip(request)})
    return MFAEnrolConfirmResponse(backup_codes=plain)


@router.post("/verify", response_model=LoginResponse)
async def verify(
    body: MFAVerifyRequest,
    request: Request,
    response: Response,
    db: SupabaseDB = Depends(db_dependency),
) -> LoginResponse:
    ip = get_client_ip(request)
    if bool(body.totp_code) == bool(body.backup_code):
        raise HTTPException(422, "Send either an authenticator code or a backup code.")
    if await is_locked_out(ip):
        raise HTTPException(429, "Account temporarily locked due to repeated failed attempts.")

    key = RedisKeys.mfa_challenge(body.mfa_token)
    challenge = await cache_get(key)
    if not challenge:
        raise HTTPException(401, "Sign-in expired. Enter your password again.")
    allowed, _ = await check_rate_limit(f"mfa_verify:{body.mfa_token}", CHALLENGE_ATTEMPTS, settings.mfa_challenge_ttl)
    if not allowed:
        await cache_delete(key)
        raise HTTPException(429, "Too many codes tried. Enter your password again.")

    user = await db.get_user_by_id(challenge["user_id"])
    if not user or not user["is_active"] or not user.get("mfa_enabled") or not user.get("mfa_secret"):
        await cache_delete(key)
        raise HTTPException(401, "Sign-in expired. Enter your password again.")

    ok, method = False, "otp"
    if body.totp_code:
        try:
            ok = await _code_ok(user["id"], decrypt_secret(user["mfa_secret"]), body.totp_code)
        except MFAUnavailable as exc:
            raise _unavailable(exc)
    else:
        method = "backup"
        rows = await db.get_unused_backup_codes(user["id"])
        idx = verify_backup_code(body.backup_code or "", [r["code_hash"] for r in rows])
        ok = idx is not None and await db.consume_backup_code(rows[idx]["id"])

    if not ok:
        await record_failed_login(ip, user["id"])
        await db.log_audit({"user_id": user["id"], "institution_id": user["institution_id"], "event_type": "mfa.failed",
                            "outcome": "failed", "ip_address": ip, "event_metadata": {"method": method}})
        raise HTTPException(401, "That code didn't work.")

    await cache_delete(key)   # one challenge, one session
    await clear_failed_logins(ip, user["id"])
    await db.log_audit({"user_id": user["id"], "institution_id": user["institution_id"],
                        "event_type": "mfa.backup_used" if method == "backup" else "mfa.verified",
                        "outcome": "success", "ip_address": ip})
    return await start_session(db, user, request, response, mfa_verified=True, method=method)


@router.post("/disable", response_model=PasswordActionResponse)
async def disable(
    body: MFADisableRequest,
    request: Request,
    claims: dict[str, Any] = Depends(_claims),
    db: SupabaseDB = Depends(db_dependency),
) -> PasswordActionResponse:
    if "mfa" not in (claims.get("amr") or []):
        raise HTTPException(403, "Sign in with two-factor authentication to turn it off.")
    user = await db.get_user_by_id(claims["sub"])
    if not user or not user.get("mfa_enabled") or not user.get("mfa_secret"):
        raise HTTPException(409, "Two-factor authentication is not on.")
    try:
        code_ok = await _code_ok(user["id"], decrypt_secret(user["mfa_secret"]), body.totp_code)
    except MFAUnavailable as exc:
        raise _unavailable(exc)
    if not verify_password(body.password, user["password_hash"]) or not code_ok:
        await record_failed_login(get_client_ip(request), user["id"])
        raise HTTPException(401, "Password or code is wrong.")
    await db.update_user(user["id"], {"mfa_enabled": False, "mfa_secret": None})
    await db.delete_backup_codes(user["id"])
    await db.revoke_all_user_sessions(user["id"], except_id=claims.get("session_id", ""))
    await db.log_audit({"user_id": user["id"], "institution_id": user["institution_id"], "event_type": "mfa.disabled",
                        "outcome": "success", "ip_address": get_client_ip(request)})
    return PasswordActionResponse(message="Two-factor authentication is off. Other sessions were signed out.")

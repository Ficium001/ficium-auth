# =============================================================
# ficium-auth — Security core
# Password hashing (Argon2id), JWT (RS256 or HS256), token utilities
# =============================================================

import hashlib
import hmac
import secrets
import time
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from jose import jwt

from .config import settings

# kid embedded in every RS256 token header — must match JWKS endpoint
RS256_KID = "ficium-auth-rs256-v1"

# ── Argon2id hasher ───────────────────────────────────────────
_hasher = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
    hash_len=settings.argon2_hash_length,
    salt_len=16,
)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)


# ── Password policy ───────────────────────────────────────────

class PasswordPolicyError(ValueError):
    pass


def validate_password_policy(password: str) -> None:
    if len(password) < settings.password_min_length:
        raise PasswordPolicyError(
            f"Password must be at least {settings.password_min_length} characters."
        )
    if settings.password_require_upper and not any(c.isupper() for c in password):
        raise PasswordPolicyError("Password must contain at least one uppercase letter.")
    if settings.password_require_lower and not any(c.islower() for c in password):
        raise PasswordPolicyError("Password must contain at least one lowercase letter.")
    if settings.password_require_digit and not any(c.isdigit() for c in password):
        raise PasswordPolicyError("Password must contain at least one number.")
    if settings.password_require_symbol and not any(
        c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password
    ):
        raise PasswordPolicyError("Password must contain at least one symbol.")


# ── JWT signing mode ──────────────────────────────────────────
# RS256: jwt_private_key set AND supabase_jwt_secret absent/empty  -> JWKS-verifiable
# HS256: supabase_jwt_secret set                                   -> Supabase native trust
#
# To switch to RS256: remove SUPABASE_JWT_SECRET from Railway env vars.

def _use_rs256() -> bool:
    return bool(settings.jwt_private_key) and not bool(settings.supabase_jwt_secret)


def _jwt_sign_key() -> str:
    return settings.jwt_private_key if _use_rs256() else settings.supabase_jwt_secret


def _jwt_verify_key() -> str:
    return settings.jwt_public_key if _use_rs256() else settings.supabase_jwt_secret


def _jwt_algorithm() -> str:
    return "RS256" if _use_rs256() else "HS256"


def issue_access_token(
    user_id: str,
    institution_id: str,
    role: str,
    session_id: str,
    deployment: str = "saas",
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, int]:
    """
    Issue a signed JWT. RS256 when supabase_jwt_secret is absent (preferred).
    HS256 fallback when supabase_jwt_secret is set (Supabase free plan).
    Returns (token, expires_at_unix_timestamp).
    """
    now = int(time.time())
    exp = now + settings.jwt_access_ttl

    payload: dict[str, Any] = {
        "iss":  settings.jwt_issuer,
        "role": "authenticated",
        "aud":  settings.jwt_audience,
        "sub":  user_id,
        "iat":  now,
        "exp":  exp,
        "jti":  secrets.token_hex(16),
        "institution_id": institution_id,
        "user_role":      role,
        "session_id":     session_id,
        "deployment":     deployment,
    }

    if extra_claims:
        payload.update(extra_claims)

    headers = {"kid": RS256_KID} if _use_rs256() else {}
    token = jwt.encode(payload, _jwt_sign_key(), algorithm=_jwt_algorithm(), headers=headers)
    return token, exp


def verify_access_token(token: str, ignore_exp: bool = False) -> dict[str, Any]:
    """
    Decode and verify an access token's signature/audience.
    ignore_exp=True still requires a valid signature but tolerates an
    expired `exp` claim — used by /logout so an expired-but-genuine
    token can still identify the session to revoke.
    """
    options = {"verify_iss": False}
    if ignore_exp:
        options["verify_exp"] = False
    return jwt.decode(
        token,
        _jwt_verify_key(),
        algorithms=[_jwt_algorithm()],
        audience=settings.jwt_audience,
        options=options,
    )


def get_token_from_header(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# ── Secure tokens ─────────────────────────────────────────────

def generate_secure_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token_hash(token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), stored_hash)


def generate_refresh_token() -> tuple[str, str]:
    raw = generate_secure_token(48)
    return raw, hash_token(raw)


def generate_backup_codes(count: int = 10) -> tuple[list[str], list[str]]:
    codes = [
        f"{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        for _ in range(count)
    ]
    hashed = [hash_token(c) for c in codes]
    return codes, hashed


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

# =============================================================
# ficium-auth — Security core
# Password hashing (Argon2id), JWT (RS256), token utilities
# =============================================================

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from jose import jwt, JWTError

from .config import settings


# ── Argon2id hasher ───────────────────────────────────────────
_hasher = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
    hash_len=settings.argon2_hash_length,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return _hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its Argon2id hash. Constant-time."""
    try:
        return _hasher.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(hashed: str) -> bool:
    """Check if hash needs upgrading (params changed)."""
    return _hasher.check_needs_rehash(hashed)


# ── Password policy ───────────────────────────────────────────

class PasswordPolicyError(ValueError):
    pass


def validate_password_policy(password: str) -> None:
    """
    Enforce bank-grade password policy.
    Raises PasswordPolicyError with specific message on failure.
    """
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
        c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password
    ):
        raise PasswordPolicyError("Password must contain at least one symbol.")


# ── JWT signing ───────────────────────────────────────────────
# Deterministic mode via settings.auth_signing_mode (default "rs256").
# RS256: ficium-auth signs with its RSA keypair; ficium-portal-api verifies
# via the published JWKS. Portable across SaaS / client-cloud / on-prem.

def _use_supabase_hs256() -> bool:
    return settings.auth_signing_mode == "supabase_hs256" and bool(settings.supabase_jwt_secret)


def _jwt_sign_key() -> str:
    """Return the key to sign JWTs with."""
    if _use_supabase_hs256():
        return settings.supabase_jwt_secret
    return settings.jwt_private_key

def _jwt_verify_key() -> str:
    """Return the key to verify JWTs with."""
    if _use_supabase_hs256():
        return settings.supabase_jwt_secret
    return settings.jwt_public_key

def _jwt_algorithm() -> str:
    if _use_supabase_hs256():
        return "HS256"
    return settings.jwt_algorithm


def issue_access_token(
    user_id:        str,
    institution_id: str,
    role:           str,
    session_id:     str,
    deployment:     str = "saas",
    extra_claims:   dict[str, Any] | None = None,
) -> tuple[str, int]:
    """
    Issue a signed JWT access token.
    Uses HS256 with Supabase JWT secret when available (free plan).
    Falls back to RS256 with RSA key pair (Pro plan / on-prem).
    Returns (token, expires_at_unix_timestamp).
    """
    now = int(time.time())
    exp = now + settings.jwt_access_ttl

    payload: dict[str, Any] = {
        # Issuer is ficium-auth's own identity now (portal-api validates it).
        # role/aud kept as "authenticated" so the Postgres auth.role() shim and
        # any role-based policies resolve exactly as before.
        "iss":  settings.jwt_issuer,
        "ref":  settings.supabase_url.split("//")[-1].split(".")[0] if settings.supabase_url else "",
        "role": "authenticated",
        "aud":  "authenticated",
        "sub":  user_id,
        "iat":  now,
        "exp":  exp,
        "jti":  secrets.token_hex(16),
        # ficium custom claims
        "institution_id": institution_id,
        "user_role":      role,      # avoid clash with the reserved 'role'
        "session_id":     session_id,
        "deployment":     deployment,
    }

    if extra_claims:
        payload.update(extra_claims)

    # Set kid in RS256 mode so verifiers can select the key from JWKS.
    headers = None if _use_supabase_hs256() else {"kid": settings.jwt_key_id}
    token = jwt.encode(payload, _jwt_sign_key(), algorithm=_jwt_algorithm(), headers=headers)
    return token, exp


def verify_access_token(token: str) -> dict[str, Any]:
    """Verify and decode a JWT access token."""
    return jwt.decode(
        token,
        _jwt_verify_key(),
        algorithms=[_jwt_algorithm()],
        audience="authenticated",
        options={"verify_iss": False},  # iss varies between modes
    )


def get_token_from_header(authorization: str | None) -> str | None:
    """Extract Bearer token from Authorization header."""
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# ── Secure tokens (reset, verify, MFA challenge) ──────────────

def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure URL-safe token."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """SHA-256 hash a token for storage. Never store tokens in plaintext."""
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token_hash(token: str, stored_hash: str) -> bool:
    """Constant-time comparison of token hash."""
    return hmac.compare_digest(
        hash_token(token),
        stored_hash,
    )


# ── Refresh token ─────────────────────────────────────────────

def generate_refresh_token() -> tuple[str, str]:
    """
    Generate a refresh token pair.
    Returns (raw_token, hashed_token).
    Raw goes to cookie, hashed goes to DB.
    """
    raw = generate_secure_token(48)
    return raw, hash_token(raw)


# ── MFA backup codes ──────────────────────────────────────────

def generate_backup_codes(count: int = 10) -> tuple[list[str], list[str]]:
    """
    Generate backup codes for MFA recovery.
    Returns (plaintext_codes, hashed_codes).
    Plaintext shown to user once. Hashed stored in DB.
    """
    codes = [
        f"{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        for _ in range(count)
    ]
    hashed = [hash_token(c) for c in codes]
    return codes, hashed


# ── Timing-safe comparison ────────────────────────────────────

def constant_time_compare(a: str, b: str) -> bool:
    """Timing-safe string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())

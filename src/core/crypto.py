# =============================================================
# ficium-auth — encryption at rest for TOTP secrets (Fernet: AES-128-CBC + HMAC-SHA256)
# =============================================================
from cryptography.fernet import Fernet, InvalidToken

from .config import settings


class MFAUnavailable(RuntimeError):
    """MFA_ENCRYPTION_KEY missing or invalid: MFA endpoints must fail closed."""


def _fernet() -> Fernet:
    key = settings.mfa_encryption_key.strip()
    if not key:
        raise MFAUnavailable("MFA_ENCRYPTION_KEY is not configured")
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise MFAUnavailable("MFA_ENCRYPTION_KEY is not a valid Fernet key") from exc


def encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise MFAUnavailable("stored MFA secret cannot be decrypted with the current key") from exc

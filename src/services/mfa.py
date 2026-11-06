# =============================================================
# ficium-auth — MFA service (TOTP + backup codes)
# RFC 6238 compliant, pyotp
# =============================================================

import base64
from io import BytesIO

import pyotp
import qrcode
import qrcode.image.svg

from ..core.config import settings
from ..core.security import generate_backup_codes, verify_token_hash


def generate_totp_secret() -> str:
    """Generate a new TOTP secret (base32)."""
    return pyotp.random_base32()


def generate_qr_uri(secret: str, email: str) -> str:
    """Generate the otpauth:// URI for QR code display."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=email,
        issuer_name=settings.mfa_issuer,
    )


def generate_qr_code_svg(uri: str) -> str:
    """Generate QR code as base64-encoded SVG."""
    img = qrcode.make(
        uri,
        image_factory=qrcode.image.svg.SvgImage,
        box_size=10,
        border=4,
    )
    buffer = BytesIO()
    img.save(buffer)
    return base64.b64encode(buffer.getvalue()).decode()


def verify_totp(secret: str, code: str, window: int | None = None) -> bool:
    """
    Verify a TOTP code.
    window: number of time steps to allow on each side (default from config).
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=window or settings.mfa_totp_window)


def generate_fresh_backup_codes() -> tuple[list[str], list[str]]:
    """Generate new backup codes. Returns (plaintext, hashed)."""
    return generate_backup_codes(settings.mfa_backup_codes)


def verify_backup_code(code: str, hashed_codes: list[str]) -> int | None:
    """
    Verify a backup code against stored hashes.
    Returns index of matched code (for marking as used), or None.
    """
    clean = code.upper().replace("-", "").replace(" ", "")
    formatted = f"{clean[:8]}-{clean[8:]}" if len(clean) == 16 else code.upper()

    for i, stored in enumerate(hashed_codes):
        if verify_token_hash(formatted, stored):
            return i
    return None

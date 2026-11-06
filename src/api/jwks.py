# =============================================================
# ficium-auth — JWKS endpoint
# GET /.well-known/jwks.json
# =============================================================

import base64

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import APIRouter, HTTPException

from ..core.config import settings

router = APIRouter(tags=["JWKS"])

_KID = "ficium-auth-rs256-v1"
_jwks_cache: dict | None = None


def _normalize_pem(pem: str) -> bytes:
    """
    Ensure the PEM has real newlines, not escaped \\n.
    Railway stores multiline env vars as a single line with literal \\n.
    """
    normalized = pem.replace("\\n", "\n").strip()
    if not normalized.endswith("\n"):
        normalized += "\n"
    return normalized.encode()


def _b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    raw = n.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _build_jwks() -> dict:
    pem = settings.jwt_public_key
    if not pem:
        raise ValueError("JWT_PUBLIC_KEY is not set")
    pem_bytes = _normalize_pem(pem)
    pub = load_pem_public_key(pem_bytes)
    if not isinstance(pub, RSAPublicKey):
        raise TypeError("JWT_PUBLIC_KEY is not an RSA public key")
    nums = pub.public_numbers()
    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": _KID,
            "n":   _b64url(nums.n),
            "e":   _b64url(nums.e),
        }]
    }


@router.get("/.well-known/jwks.json", include_in_schema=False)
async def jwks() -> dict:
    """Return the RS256 public JWKS for token verification."""
    global _jwks_cache
    if not settings.jwt_public_key:
        raise HTTPException(status_code=404, detail="RS256 not configured.")
    if _jwks_cache is None:
        try:
            _jwks_cache = _build_jwks()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"JWKS build failed: {exc}") from exc
    return _jwks_cache

# =============================================================
# ficium-auth — JWKS endpoint
# GET /.well-known/jwks.json
#
# Publishes the RS256 public key so that ficium-portal-api (and
# any other consumer) can verify tokens without a shared secret.
# Only exposed when signing in RS256 mode (jwt_private_key set).
# =============================================================

import json
from fastapi import APIRouter, HTTPException
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends import default_backend
from jose.utils import base64url_encode
from .._compat import int_to_bytes
from ..core.config import settings

router = APIRouter(tags=["JWKS"])


def _public_key_to_jwk() -> dict:
    """Convert the RSA public key PEM to JWK format."""
    pem = settings.jwt_public_key.encode()
    pub = load_pem_public_key(pem, backend=default_backend())
    if not isinstance(pub, RSAPublicKey):
        raise ValueError("JWT_PUBLIC_KEY is not an RSA key")

    pub_numbers = pub.public_key().public_numbers() if hasattr(pub, "public_key") else pub.public_numbers()
    e = pub_numbers.e
    n = pub_numbers.n

    def _to_base64url(i: int) -> str:
        length = (i.bit_length() + 7) // 8
        return base64url_encode(i.to_bytes(length, "big")).decode()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "ficium-auth-rs256-v1",
        "n":   _to_base64url(n),
        "e":   _to_base64url(e),
    }


_jwks_cache: dict | None = None


@router.get("/.well-known/jwks.json", include_in_schema=False)
async def jwks() -> dict:
    """
    Return the public JWKS. Cached in memory after first call.
    ficium-portal-api fetches this on startup and on unknown-kid
    to verify RS256 access tokens.
    """
    global _jwks_cache
    if settings.jwt_public_key:
        if _jwks_cache is None:
            try:
                _jwks_cache = {"keys": [_public_key_to_jwk()]}
            except Exception as exc:
                raise HTTPException(500, f"JWKS build failed: {exc}") from exc
        return _jwks_cache
    raise HTTPException(404, "RS256 not configured.")


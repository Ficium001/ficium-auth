# =============================================================
# ficium-auth — JWKS endpoint
# Publishes the RS256 public key so ficium-portal-api (and any
# internal verifier) can validate ficium-auth tokens without a
# shared secret. Standard /.well-known/jwks.json discovery.
# =============================================================

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from jose import jwk

from ..core.config import settings

router = APIRouter(tags=["jwks"])

# Build once at import: the public key is static for the process lifetime.
_jwk_cache: dict | None = None


def _build_jwks() -> dict:
    global _jwk_cache
    if _jwk_cache is None:
        key = jwk.construct(settings.jwt_public_key, settings.jwt_algorithm)
        data = key.to_dict()  # {kty, n, e}
        data.update({
            "kid": settings.jwt_key_id,
            "use": "sig",
            "alg": settings.jwt_algorithm,
        })
        _jwk_cache = {"keys": [data]}
    return _jwk_cache


@router.get("/.well-known/jwks.json")
def jwks() -> JSONResponse:
    """RFC 7517 JSON Web Key Set for ficium-auth's signing key(s)."""
    return JSONResponse(
        _build_jwks(),
        headers={"Cache-Control": "public, max-age=3600"},
    )

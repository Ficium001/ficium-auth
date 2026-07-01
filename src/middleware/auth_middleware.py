# =============================================================
# ficium-auth — Auth middleware
# JWT verification, session validation, IP allowlist check
# =============================================================

from typing import Optional
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError

from ..core.security import verify_access_token, get_token_from_header
from ..core.redis import is_token_blacklisted
from ..core.config import settings

security = HTTPBearer(auto_error=False)


class AuthenticatedUser:
    def __init__(self, claims: dict):
        self.user_id:        str = claims["sub"]
        self.institution_id: str = claims["institution_id"]
        self.role:           str = claims["role"]
        self.session_id:     str = claims["session_id"]
        self.jti:            str = claims["jti"]


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> AuthenticatedUser:
    """
    FastAPI dependency — validates JWT, checks blacklist.
    Use in any protected endpoint: current_user: AuthenticatedUser = Depends(get_current_user)
    """
    token = None

    if credentials:
        token = credentials.credentials
    else:
        # Fallback: check Authorization header manually
        token = get_token_from_header(request.headers.get("Authorization"))

    if not token:
        raise HTTPException(status_code=401, detail="Authentication required.")

    try:
        claims = verify_access_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    # Check token blacklist (revoked tokens)
    jti = claims.get("jti")
    if jti and await is_token_blacklisted(jti):
        raise HTTPException(status_code=401, detail="Token has been revoked.")

    return AuthenticatedUser(claims)


async def require_role(*roles: str):
    """
    Role-based access control dependency factory.
    Usage: Depends(require_role("admin", "compliance"))
    """
    async def _check(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied. Required role: {' or '.join(roles)}.",
            )
        return user
    return _check


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP for rate-limiting and lockout.

    SECURITY: X-Forwarded-For / X-Real-IP are client-supplied and trivially
    spoofable. An attacker who can set these headers could rotate a fake IP
    on every request to bypass per-IP rate limiting and account lockout
    entirely. We therefore only trust the LAST hop appended by our own
    trusted proxy (Railway's edge), not the first value in the chain.

    Railway/Caddy appends the genuine peer IP as the rightmost entry of
    X-Forwarded-For. We take that, and only fall back to the raw socket
    peer (request.client.host) — never the client-controlled first entry.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        # Rightmost entry is the one appended by our trusted edge proxy.
        # Everything to the left is attacker-controllable and ignored.
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        if hops:
            return hops[-1]
    return (request.client.host if request.client else None) or "unknown"


def get_user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "unknown")[:500]

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
    """Extract real client IP, respecting X-Real-IP from Caddy."""
    return (
        request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.client.host
        or "unknown"
    )


def get_user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "unknown")[:500]

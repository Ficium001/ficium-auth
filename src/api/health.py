# =============================================================
# ficium-auth — Health endpoints
# /health, /health/ready, /health/live
# =============================================================

from fastapi import APIRouter
from ..core.database import check_db_health
from ..core.redis import check_redis_health
from ..core.config import settings
from ..schemas.auth import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    db_ok    = await check_db_health()
    redis_ok = await check_redis_health()

    checks = {"database": db_ok, "redis": redis_ok}
    status = "healthy" if all(checks.values()) else "degraded"

    return HealthResponse(status=status, version=settings.version, checks=checks)


@router.get("/health/live")
async def liveness() -> dict:
    """Kubernetes liveness probe — is the process alive?"""
    return {"status": "alive"}


@router.get("/health/ready")
async def readiness() -> dict:
    """Kubernetes readiness probe — can we serve traffic?"""
    db_ok    = await check_db_health()
    redis_ok = await check_redis_health()
    if not db_ok or not redis_ok:
        from fastapi import Response as FastAPIResponse
        return FastAPIResponse(status_code=503, content={"status": "not ready"})
    return {"status": "ready"}

# =============================================================
# ficium-auth — FastAPI application entry point
# =============================================================

import structlog
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from .core.config import settings
from .core.redis import get_redis, close_redis
from .api.auth import router as auth_router
from .api.health import router as health_router
from .api.jwks import router as jwks_router

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer() if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer(),
    ],
)

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("ficium_auth_starting", env=settings.env, version=settings.version)
    await get_redis()
    log.info("ficium_auth_ready")
    yield
    await close_redis()
    log.info("ficium_auth_stopped")


app = FastAPI(
    title="Ficium Auth",
    version=settings.version,
    docs_url="/docs" if settings.is_development else None,
    redoc_url="/redoc" if settings.is_development else None,
    openapi_url="/openapi.json" if settings.is_development else None,
    lifespan=lifespan,
)

_allowed_origins = [o.strip() for o in getattr(settings, "allowed_origins", "").split(",") if o.strip()]
if not _allowed_origins:
    _allowed_origins = [f"https://{settings.session_cookie_domain}"]

_origin_regex = getattr(settings, "allowed_origin_regex", "") or None

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_origin_regex=_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    import uuid
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "message": "An unexpected error occurred."},
    )


if settings.metrics_enabled:
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(jwks_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
        access_log=True,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )

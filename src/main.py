# =============================================================
# ficium-auth — FastAPI application entry point
# =============================================================

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from redis.exceptions import RedisError

from .api.auth import router as auth_router
from .api.health import router as health_router
from .api.jwks import router as jwks_router
from .core.config import settings
from .core.redis import close_redis, get_redis

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


@app.middleware("http")
async def default_response_headers_middleware(request: Request, call_next):
    """Auth responses (tokens, sessions, JWKS) must never be cached by an
    intermediary or the browser unless a route explicitly opts in. Also
    ensures JSON responses declare charset — closes DevTools Issues panel
    warnings for missing cache-control / content-type charset."""
    response = await call_next(request)

    if not response.headers.get("cache-control"):
        response.headers["Cache-Control"] = "no-store"

    # Prevent MIME sniffing on all auth responses.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")

    content_type = response.headers.get("content-type", "")
    if content_type.startswith("application/json") and "charset" not in content_type:
        response.headers["Content-Type"] = f"{content_type}; charset=utf-8"

    return response


@app.exception_handler(RedisError)
async def redis_unavailable_handler(request: Request, exc: RedisError):
    # Specific handlers run INSIDE the CORS middleware, so the browser gets a
    # readable 503 instead of a misleading "blocked by CORS" (the catch-all
    # Exception handler below runs outside it). Login itself degrades
    # gracefully (core/redis.py); this covers MFA, revocation, refresh.
    log.error("redis_unavailable", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=503,
        content={"error": "temporarily_unavailable",
                 "message": "Sign-in is temporarily unavailable. Please try again in a minute."},
        headers={"Retry-After": "30"},
    )


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

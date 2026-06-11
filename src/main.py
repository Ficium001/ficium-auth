# =============================================================
# ficium-auth — FastAPI application entry point
# Bank-grade auth service for Ficium institution portal
# =============================================================

import structlog
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from .core.config import settings
from .core.redis import get_redis, close_redis
from .api.auth import router as auth_router
from .api.health import router as health_router

# ── Structured logging ────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer() if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer(),
    ],
)

log = structlog.get_logger()


# ── Lifespan ──────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("ficium_auth_starting", env=settings.env, version=settings.version)
    await get_redis()                           # warm Redis connection pool
    log.info("ficium_auth_ready")
    yield
    await close_redis()
    log.info("ficium_auth_stopped")


# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title="Ficium Auth",
    version=settings.version,
    docs_url="/docs" if settings.is_development else None,    # no Swagger in prod
    redoc_url="/redoc" if settings.is_development else None,
    openapi_url="/openapi.json" if settings.is_development else None,
    lifespan=lifespan,
)

# ── Security middleware ───────────────────────────────────────
# Only accept requests from Caddy proxy (TrustedHost)
if settings.is_production:
    _trusted = [settings.session_cookie_domain, "*.railway.app", "*.up.railway.app", "localhost"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_trusted)

# CORS — portal domain + Vercel deployments
_allowed_origins = [o.strip() for o in getattr(settings, "allowed_origins", "").split(",") if o.strip()]
if not _allowed_origins:
    _allowed_origins = [f"https://{settings.session_cookie_domain}"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)

# ── Request ID middleware ─────────────────────────────────────
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    import uuid
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response   = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

# ── Global exception handler ──────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "message": "An unexpected error occurred."},
    )

# ── Metrics ───────────────────────────────────────────────────
if settings.metrics_enabled:
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# ── Routers ───────────────────────────────────────────────────
app.include_router(health_router)
app.include_router(auth_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
        access_log=True,
        proxy_headers=True,         # trust X-Real-IP from Caddy
        forwarded_allow_ips="*",
    )

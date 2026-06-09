# =============================================================
# ficium-auth — Database (async SQLAlchemy + asyncpg)
# Connection pool, session factory, health check
# =============================================================

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

from .config import settings


# ── Engine ────────────────────────────────────────────────────
engine = create_async_engine(
    settings.db_url,
    pool_size=settings.db_pool_min,
    max_overflow=settings.db_pool_max - settings.db_pool_min,
    pool_pre_ping=True,           # verify connections before use
    pool_recycle=3600,            # recycle connections every hour
    echo=settings.is_development, # SQL logging in dev only
)

# ── Session factory ───────────────────────────────────────────
AsyncSessionFactory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ── Base model ────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Dependency ────────────────────────────────────────────────
@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# FastAPI dependency
async def db_dependency() -> AsyncGenerator[AsyncSession, None]:
    async with get_db() as session:
        yield session


# ── Health check ──────────────────────────────────────────────
async def check_db_health() -> bool:
    try:
        async with get_db() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

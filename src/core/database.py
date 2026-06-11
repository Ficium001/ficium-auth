# =============================================================
# ficium-auth — Database (SQLAlchemy + psycopg2)
# Uses psycopg2 driver which works reliably with Supabase
# transaction pooler from Railway.
# Async interface maintained via SQLAlchemy's thread pool.
# =============================================================

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from sqlalchemy.pool import NullPool
import asyncio

from .config import settings


# ── Determine driver ──────────────────────────────────────────
# Use psycopg2 (sync) wrapped in async via asyncio thread pool
_db_url = settings.db_url

# If URL still has asyncpg (not yet normalised), fix it
if "asyncpg" in _db_url:
    _db_url = _db_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")

# Fix ssl param for psycopg2 (uses sslmode= not ssl=)
if "ssl=require" in _db_url and "sslmode=" not in _db_url:
    _db_url = _db_url.replace("ssl=require", "sslmode=require")

# ── Sync engine (psycopg2) ────────────────────────────────────
sync_engine = create_engine(
    _db_url,
    pool_size=2,
    max_overflow=3,
    pool_pre_ping=True,
    pool_recycle=1800,
    echo=settings.is_development,
    connect_args={"sslmode": "require", "connect_timeout": 10},
)

SyncSessionFactory = sessionmaker(
    sync_engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


# ── Async wrapper ─────────────────────────────────────────────
# Wrap sync session in async interface using run_in_executor
class AsyncSyncSession:
    """Minimal async wrapper around a sync SQLAlchemy session."""

    def __init__(self, session: Session):
        self._session = session
        self._loop = asyncio.get_event_loop()

    async def execute(self, stmt, *args, **kwargs):
        return await self._loop.run_in_executor(
            None, lambda: self._session.execute(stmt, *args, **kwargs)
        )

    async def flush(self):
        await self._loop.run_in_executor(None, self._session.flush)

    async def commit(self):
        await self._loop.run_in_executor(None, self._session.commit)

    async def rollback(self):
        await self._loop.run_in_executor(None, self._session.rollback)

    async def close(self):
        await self._loop.run_in_executor(None, self._session.close)

    def add(self, obj):
        self._session.add(obj)

    async def scalar(self, stmt):
        result = await self.execute(stmt)
        return result.scalar()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._session.close()


# ── Base model ────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Dependency ────────────────────────────────────────────────
async def db_dependency() -> AsyncGenerator[AsyncSyncSession, None]:
    session = SyncSessionFactory()
    wrapped = AsyncSyncSession(session)
    try:
        yield wrapped
        await wrapped.commit()
    except Exception:
        await wrapped.rollback()
        raise
    finally:
        await wrapped.close()


# ── Health check ──────────────────────────────────────────────
async def check_db_health() -> bool:
    loop = asyncio.get_event_loop()
    try:
        def _check():
            with sync_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        await loop.run_in_executor(None, _check)
        return True
    except Exception:
        return False

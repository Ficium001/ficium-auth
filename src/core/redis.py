# =============================================================
# ficium-auth — Redis client
# Sessions, rate limiting, lockouts, token blacklist, cache
# =============================================================

import json
import time
from typing import Any, cast

import redis.asyncio as aioredis
import structlog
from redis.exceptions import RedisError

from .config import settings

# ── Connection pool ───────────────────────────────────────────
_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _pool
    if _pool is None:
        _pool = aioredis.from_url(
            settings.redis_url,
            password=settings.redis_password or None,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )
    return _pool


async def close_redis() -> None:
    global _pool
    if _pool:
        await _pool.aclose()
        _pool = None


# ── Health check ──────────────────────────────────────────────
async def check_redis_health() -> bool:
    try:
        r = await get_redis()
        return await r.ping()
    except Exception:
        return False


# ── Key namespaces ────────────────────────────────────────────
class RedisKeys:
    @staticmethod
    def session(session_id: str) -> str:
        return f"session:{session_id}"

    @staticmethod
    def refresh_token(token_hash: str) -> str:
        return f"rt:{token_hash}"

    @staticmethod
    def login_attempts(ip: str) -> str:
        return f"login_attempts:{ip}"

    @staticmethod
    def lockout(ip: str) -> str:
        return f"lockout:{ip}"

    @staticmethod
    def user_lockout(user_id: str) -> str:
        return f"user_lockout:{user_id}"

    @staticmethod
    def mfa_challenge(challenge_id: str) -> str:
        return f"mfa_challenge:{challenge_id}"

    @staticmethod
    def mfa_pending(user_id: str) -> str:
        return f"mfa_pending:{user_id}"

    @staticmethod
    def mfa_used_code(user_id: str, code: str) -> str:
        return f"mfa_used:{user_id}:{code}"

    @staticmethod
    def token_blacklist(jti: str) -> str:
        return f"blacklist:{jti}"

    @staticmethod
    def password_reset(token_hash: str) -> str:
        return f"pwd_reset:{token_hash}"

    @staticmethod
    def email_verify(token_hash: str) -> str:
        return f"email_verify:{token_hash}"

    @staticmethod
    def user_sessions(user_id: str) -> str:
        return f"user_sessions:{user_id}"

    @staticmethod
    def rate_limit(key: str) -> str:
        return f"rl:{key}"


# ── Degraded mode (Redis unreachable) ─────────────────────────
# Rate limiting and lockouts must not take login down when Redis is
# unreachable (2026-10-23: after a Railway outage every sign-in failed). They
# fall back to a per-instance in-memory counter, so brute-force protection
# stays ON (per instance instead of shared) and each degraded call is logged.
# Token revocation checks do NOT degrade: they keep failing closed.
# Sessions are stored in Postgres, not here.
log = structlog.get_logger()
_MEM: dict[str, tuple[int, float]] = {}   # key -> (count, expires_at)
_MEM_MAX_KEYS = 50_000


def _degraded(op: str, exc: Exception) -> None:
    log.warning("redis_degraded", op=op, error=str(exc))


def _mem_incr(key: str, window: int) -> int:
    now = time.monotonic()
    if len(_MEM) > _MEM_MAX_KEYS:            # bound memory: drop expired, then oldest
        for k in [k for k, (_, exp) in _MEM.items() if exp <= now]:
            _MEM.pop(k, None)
        while len(_MEM) > _MEM_MAX_KEYS:
            _MEM.pop(next(iter(_MEM)))
    count, exp = _MEM.get(key, (0, now + window))
    if exp <= now:
        count, exp = 0, now + window
    _MEM[key] = (count + 1, exp)
    return count + 1


def _mem_get(key: str) -> int:
    count, exp = _MEM.get(key, (0, 0.0))
    return count if exp > time.monotonic() else 0


# ── Rate limiting ─────────────────────────────────────────────
async def check_rate_limit(
    key: str,
    limit: int,
    window: int,
) -> tuple[bool, int]:
    """
    Fixed-window rate limiter. Returns (allowed, remaining_attempts).
    Falls back to a per-instance counter if Redis is unreachable.
    """
    redis_key = RedisKeys.rate_limit(key)
    try:
        r = await get_redis()
        count = int(await r.incr(redis_key))
        if count == 1:
            await r.expire(redis_key, window)
    except RedisError as exc:
        _degraded("check_rate_limit", exc)
        count = _mem_incr(redis_key, window)
    allowed = count <= limit
    remaining = max(0, limit - count)
    return allowed, remaining


# ── Login attempt tracking ────────────────────────────────────
async def record_failed_login(ip: str, user_id: str | None = None) -> int:
    """Record a failed login. Returns the per-IP failure count."""
    ip_key = RedisKeys.login_attempts(ip)
    window = settings.rate_limit_login_window * 10
    try:
        r = await get_redis()
        ip_count = int(await r.incr(ip_key))
        if ip_count == 1:
            await r.expire(ip_key, window)
        if user_id:
            user_key = f"user_login_fails:{user_id}"
            await r.incr(user_key)
            await r.expire(user_key, window)
    except RedisError as exc:
        _degraded("record_failed_login", exc)
        ip_count = _mem_incr(ip_key, window)
    return ip_count


async def is_locked_out(ip: str, user_id: str | None = None) -> bool:
    """Check if IP or user is currently locked out."""
    try:
        r = await get_redis()
        if await r.exists(RedisKeys.lockout(ip)):
            return True
        if user_id and await r.exists(RedisKeys.user_lockout(user_id)):
            return True
        ip_count = int(await r.get(RedisKeys.login_attempts(ip)) or 0)
        if ip_count >= settings.lockout_threshold:
            await r.setex(RedisKeys.lockout(ip), settings.lockout_duration, "1")
            return True
        return False
    except RedisError as exc:
        _degraded("is_locked_out", exc)
        return _mem_get(RedisKeys.login_attempts(ip)) >= settings.lockout_threshold


async def clear_failed_logins(ip: str, user_id: str | None = None) -> None:
    """Clear failed login counters on successful login."""
    _MEM.pop(RedisKeys.login_attempts(ip), None)
    try:
        r = await get_redis()
        await r.delete(RedisKeys.login_attempts(ip))
        await r.delete(RedisKeys.lockout(ip))
        if user_id:
            await r.delete(f"user_login_fails:{user_id}")
            await r.delete(RedisKeys.user_lockout(user_id))
    except RedisError as exc:
        _degraded("clear_failed_logins", exc)


# ── Token blacklist ───────────────────────────────────────────
async def blacklist_token(jti: str, ttl: int) -> None:
    """Add a JWT to the blacklist (for logout/revocation)."""
    r = await get_redis()
    await r.setex(RedisKeys.token_blacklist(jti), ttl, "1")


async def is_token_blacklisted(jti: str) -> bool:
    """Check if a JWT has been revoked."""
    r = await get_redis()
    return bool(await r.exists(RedisKeys.token_blacklist(jti)))


# ── Session tracking (user → session list) ───────────────────
async def add_user_session(user_id: str, session_id: str) -> None:
    """Index a session for 'sign out everywhere'. Best effort: the session
    itself is in Postgres, so an unreachable Redis must not block sign-in."""
    try:
        r = await get_redis()
        await r.sadd(RedisKeys.user_sessions(user_id), session_id)
    except RedisError as exc:
        _degraded("add_user_session", exc)


async def remove_user_session(user_id: str, session_id: str) -> None:
    r = await get_redis()
    await r.srem(RedisKeys.user_sessions(user_id), session_id)


async def get_user_session_ids(user_id: str) -> set[str]:
    r = await get_redis()
    return cast("set[str]", await r.smembers(RedisKeys.user_sessions(user_id)))


# ── Generic cache ─────────────────────────────────────────────
async def cache_set(key: str, value: Any, ttl: int) -> None:
    r = await get_redis()
    await r.setex(key, ttl, json.dumps(value))


async def cache_get(key: str) -> Any | None:
    r = await get_redis()
    data = await r.get(key)
    return json.loads(data) if data else None


async def cache_delete(key: str) -> None:
    r = await get_redis()
    await r.delete(key)

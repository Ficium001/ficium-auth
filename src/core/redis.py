# =============================================================
# ficium-auth — Redis client
# Sessions, rate limiting, lockouts, token blacklist, cache
# =============================================================

from typing import Any, cast
import json

import redis.asyncio as aioredis

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


# ── Rate limiting ─────────────────────────────────────────────
async def check_rate_limit(
    key: str,
    limit: int,
    window: int,
) -> tuple[bool, int]:
    """
    Sliding window rate limiter.
    Returns (allowed, remaining_attempts).
    """
    r = await get_redis()
    redis_key = RedisKeys.rate_limit(key)

    count = await r.incr(redis_key)
    if count == 1:
        await r.expire(redis_key, window)

    allowed = count <= limit
    remaining = max(0, limit - count)
    return allowed, remaining


# ── Login attempt tracking ────────────────────────────────────
async def record_failed_login(ip: str, user_id: str | None = None) -> int:
    """Record a failed login. Returns total failure count."""
    r = await get_redis()

    # Per-IP counter
    ip_key = RedisKeys.login_attempts(ip)
    ip_count = await r.incr(ip_key)
    if ip_count == 1:
        await r.expire(ip_key, settings.rate_limit_login_window * 10)

    # Per-user counter (if we know the user)
    if user_id:
        user_key = f"user_login_fails:{user_id}"
        await r.incr(user_key)
        await r.expire(user_key, settings.rate_limit_login_window * 10)

    return ip_count


async def is_locked_out(ip: str, user_id: str | None = None) -> bool:
    """Check if IP or user is currently locked out."""
    r = await get_redis()

    if await r.exists(RedisKeys.lockout(ip)):
        return True

    if user_id and await r.exists(RedisKeys.user_lockout(user_id)):
        return True

    # Check attempt count
    ip_count = int(await r.get(RedisKeys.login_attempts(ip)) or 0)
    if ip_count >= settings.lockout_threshold:
        await r.setex(RedisKeys.lockout(ip), settings.lockout_duration, "1")
        return True

    return False


async def clear_failed_logins(ip: str, user_id: str | None = None) -> None:
    """Clear failed login counters on successful login."""
    r = await get_redis()
    await r.delete(RedisKeys.login_attempts(ip))
    await r.delete(RedisKeys.lockout(ip))
    if user_id:
        await r.delete(f"user_login_fails:{user_id}")
        await r.delete(RedisKeys.user_lockout(user_id))


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
    r = await get_redis()
    await r.sadd(RedisKeys.user_sessions(user_id), session_id)


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

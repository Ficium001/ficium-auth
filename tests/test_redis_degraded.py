"""Login must survive an unreachable Redis (2026-10-23: a Railway outage reset
the Redis proxy and every sign-in failed with a misleading CORS error).
Rate limiting and lockouts degrade to a per-instance counter and STAY ON;
other Redis errors become a 503 inside CORS, never a bare 500."""
from __future__ import annotations

import asyncio
from typing import Any

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from src.core import redis as r


class _Down:
    """A Redis client whose every command fails like the production incident."""

    def __getattr__(self, name: str) -> Any:
        async def fail(*_: Any, **__: Any) -> Any:
            raise RedisConnectionError("Connection reset by peer")
        return fail


@pytest.fixture(autouse=True)
def redis_down(monkeypatch: pytest.MonkeyPatch) -> None:
    async def get_down() -> Any:
        return _Down()
    monkeypatch.setattr(r, "get_redis", get_down)
    r._MEM.clear()


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_rate_limit_still_limits_when_redis_is_down() -> None:
    results = [run(r.check_rate_limit("login:1.2.3.4", limit=3, window=60))[0] for _ in range(5)]
    assert results == [True, True, True, False, False]


def test_lockout_still_applies_when_redis_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r.settings, "lockout_threshold", 3)
    for _ in range(3):
        run(r.record_failed_login("5.6.7.8"))
    assert run(r.is_locked_out("5.6.7.8")) is True
    assert run(r.is_locked_out("9.9.9.9")) is False


def test_successful_login_clears_the_fallback_counter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r.settings, "lockout_threshold", 2)
    run(r.record_failed_login("1.1.1.1"))
    run(r.clear_failed_logins("1.1.1.1", "u1"))
    run(r.record_failed_login("1.1.1.1"))
    assert run(r.is_locked_out("1.1.1.1")) is False


def test_session_index_is_best_effort() -> None:
    run(r.add_user_session("u1", "s1"))  # must not raise


def test_revocation_check_still_fails_closed() -> None:
    with pytest.raises(RedisConnectionError):
        run(r.is_token_blacklisted("jti-1"))


def test_other_redis_errors_are_a_503_with_cors() -> None:
    from fastapi.testclient import TestClient

    from src.main import app

    @app.get("/__redis_boom")
    async def boom() -> None:
        raise RedisConnectionError("down")

    origin = "https://ficium-portal.vercel.app"
    res = TestClient(app, raise_server_exceptions=False).get(
        "/__redis_boom", headers={"Origin": origin})
    assert res.status_code == 503
    assert res.json()["error"] == "temporarily_unavailable"
    assert res.headers.get("access-control-allow-origin") == origin

"""Per-account lockout (2026-10-30). Before, lockout was per IP only: one account
could be guessed from many IPs (5 tries each, unlimited IPs), and the per-user
counter was incremented but never acted on. Now the account NAME locks after
lockout_threshold failures from any IPs, unknown names behave identically (no
account enumeration), and the owner gets one alert email when the lock starts.
Runs on the in-memory fallback (Redis down), the same rules as with Redis."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from src.api import auth as auth_api
from src.core import redis as r
from src.core.database import db_dependency
from src.main import app
from tests.test_mfa import PW, FakeDB


class _Down:
    def __getattr__(self, name: str) -> Any:
        async def fail(*_: Any, **__: Any) -> Any:
            raise RedisConnectionError("down")
        return fail


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch):
    async def get_down() -> Any:
        return _Down()
    monkeypatch.setattr(r, "get_redis", get_down)
    r._MEM.clear()
    monkeypatch.setattr(r.settings, "lockout_threshold", 3)
    monkeypatch.setattr(auth_api.settings, "rate_limit_login", 1000)
    alerts: list[tuple[str, str, int]] = []

    async def alert(to: str, ip: str, attempts: int) -> None:
        alerts.append((to, ip, attempts))
    monkeypatch.setattr(auth_api, "send_lockout_alert", alert)
    db = FakeDB(); db.add_user()
    app.dependency_overrides[db_dependency] = lambda: db
    yield TestClient(app), alerts
    app.dependency_overrides.clear()
    r._MEM.clear()


def _login(c: TestClient, user: str, pw: str, ip: str) -> int:
    return c.post("/auth/login", json={"username": user, "password": pw},
                  headers={"X-Forwarded-For": ip}).status_code


def test_guessing_one_account_from_many_ips_locks_it(env) -> None:
    c, alerts = env
    codes = [_login(c, "kj", "wrong-password-1", f"10.0.0.{i}") for i in range(1, 4)]
    assert codes == [401, 401, 401]
    # The right password from a fresh IP is refused while locked.
    assert _login(c, "kj", PW, "10.0.0.99") == 429
    assert alerts == [("kj@ficium.net", "10.0.0.3", 3)]  # once, when the lock started


def test_an_unknown_username_behaves_exactly_the_same(env) -> None:
    c, alerts = env
    codes = [_login(c, "nobody", "x-password-123", f"10.1.0.{i}") for i in range(1, 5)]
    assert codes == [401, 401, 401, 429]  # same sequence as a real account
    assert alerts == []


def test_a_good_login_resets_the_count(env) -> None:
    import asyncio
    run = asyncio.run
    assert run(r.record_account_failure("kj")) is False
    assert run(r.record_account_failure("kj")) is False
    run(r.clear_account_failures("kj"))           # what a successful login calls
    assert run(r.record_account_failure("kj")) is False
    assert run(r.is_account_locked("kj")) is False  # the count restarted
    assert run(r.is_account_locked("KJ ")) is False  # same account, any case/space
    assert run(r.record_account_failure("KJ ")) is False
    assert run(r.record_account_failure("kj")) is True   # third failure locks
    assert run(r.is_account_locked("kj")) is True

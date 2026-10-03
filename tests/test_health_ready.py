"""The readiness probe must answer 503 JSON when a dependency is down (it used to raise and return 500)."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api import health


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(health.router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize(("db_ok", "redis_ok"), [(False, True), (True, False), (False, False)])
def test_not_ready_is_a_clean_503(monkeypatch, db_ok: bool, redis_ok: bool) -> None:
    async def _db() -> bool:
        return db_ok

    async def _redis() -> bool:
        return redis_ok

    monkeypatch.setattr(health, "check_db_health", _db)
    monkeypatch.setattr(health, "check_redis_health", _redis)
    r = _client().get("/health/ready")
    assert r.status_code == 503
    assert r.json() == {"status": "not ready"}


def test_ready_when_both_dependencies_are_up(monkeypatch) -> None:
    async def _ok() -> bool:
        return True

    monkeypatch.setattr(health, "check_db_health", _ok)
    monkeypatch.setattr(health, "check_redis_health", _ok)
    r = _client().get("/health/ready")
    assert r.status_code == 200 and r.json() == {"status": "ready"}

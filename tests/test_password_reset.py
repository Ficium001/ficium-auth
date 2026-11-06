# Password reset: real column names, strict single use, sessions revoked.
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from src.core.database import db_dependency
from src.core.security import hash_token, verify_password
from src.main import app
from tests.test_mfa import FakeDB

NEW = "Brand-New-Passw0rd!"


class ResetDB(FakeDB):
    def __init__(self) -> None:
        super().__init__(); self.tokens: dict[str, dict] = {}
    async def get_password_reset_token(self, h: str) -> dict | None:
        return next((t for t in self.tokens.values() if t["token_hash"] == h and not t["used"]), None)
    async def mark_reset_token_used(self, tid: str) -> bool:
        t = self.tokens[tid]
        if t["used"]: return False
        t["used"] = True; return True
    async def update_user(self, uid: str, data: dict) -> None:
        assert set(data) <= set(self.users[uid]) | {"password_changed_at", "updated_at"}, f"unknown columns {set(data) - set(self.users[uid])}"
        self.users[uid].update(data)


@pytest.fixture
def env():
    db = ResetDB(); u = db.add_user(must_change_password=True)
    db.sessions["s1"] = {"id": "s1", "user_id": u["id"], "is_active": True, "refresh_token_hash": "x"}
    db.tokens["t1"] = {"id": "t1", "user_id": u["id"], "token_hash": hash_token("raw-token"), "used": False,
                       "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()}
    app.dependency_overrides[db_dependency] = lambda: db
    yield db, u, TestClient(app)
    app.dependency_overrides.clear()


def test_reset_sets_password_clears_flag_and_signs_everyone_out(env) -> None:
    db, u, c = env
    r = c.post("/auth/password/reset", json={"token": "raw-token", "new_password": NEW})
    assert r.status_code == 200, r.text
    assert verify_password(NEW, u["password_hash"]) and u["must_change_password"] is False
    assert db.sessions["s1"]["is_active"] is False
    assert any(a["event_type"] == "password.reset" for a in db.audit)


def test_token_works_once(env) -> None:
    _, _, c = env
    assert c.post("/auth/password/reset", json={"token": "raw-token", "new_password": NEW}).status_code == 200
    assert c.post("/auth/password/reset", json={"token": "raw-token", "new_password": NEW + "x"}).status_code == 400


def test_policy_is_enforced(env) -> None:
    _, _, c = env
    assert c.post("/auth/password/reset", json={"token": "raw-token", "new_password": "alllowercase123"}).status_code == 400


class ForgotDB(ResetDB):
    async def get_user_by_email(self, email: str) -> dict | None:
        return next((u for u in self.users.values() if u["email"] == email), None)
    async def create_password_reset_token(self, data: dict) -> dict:
        self.tokens[str(len(self.tokens))] = {**data, "used": False}; return data


@pytest.mark.parametrize("institution,base,product", [
    ("00000000-0000-0000-0000-000000000001", "https://ficium-admin.vercel.app", "Ficium Admin"),
    ("f192050a-dfdd-4da7-874e-c3db88f11e41", "https://ficium-portal.vercel.app", "Ficium Portal"),
])
def test_reset_link_goes_where_the_account_signs_in(monkeypatch: pytest.MonkeyPatch, institution: str, base: str, product: str) -> None:
    import src.api.auth as auth_api
    sent: list[tuple] = []
    async def capture(to: str, url: str, product: str = "") -> None: sent.append((to, url, product))
    async def allow(*a, **k): return True, 1
    monkeypatch.setattr(auth_api, "send_password_reset_email", capture)
    monkeypatch.setattr(auth_api, "check_rate_limit", allow)
    db = ForgotDB(); db.add_user(institution_id=institution)
    app.dependency_overrides[db_dependency] = lambda: db
    try:
        # A caller-supplied Origin must not influence where the link points.
        r = TestClient(app).post("/auth/password/forgot", json={"username": "kj"}, headers={"Origin": "https://evil.example"})
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200 and len(sent) == 1
    assert sent[0][1].startswith(f"{base}/reset-password?token=") and sent[0][2] == product

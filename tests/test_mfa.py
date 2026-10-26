# MFA end-to-end at the HTTP layer with in-memory DB + Redis fakes.
import uuid
from typing import Any

import pyotp
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import src.api.auth as auth_api
import src.api.mfa as mfa_api
import src.middleware.auth_middleware as mw
from src.core.config import settings
from src.core.database import db_dependency
from src.core.security import hash_password, verify_access_token
from src.main import app

PW = "Correct-Horse-9-battery"


class FakeDB:
    def __init__(self) -> None:
        self.users: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.codes: dict[str, dict] = {}
        self.audit: list[dict] = []

    def add_user(self, **kw: Any) -> dict:
        u = {"id": str(uuid.uuid4()), "username": "kj", "email": "kj@ficium.net", "password_hash": hash_password(PW),
             "institution_id": "00000000-0000-0000-0000-000000000001", "role": "super_admin", "is_active": True,
             "mfa_enabled": False, "mfa_secret": None, "must_change_password": False, **kw}
        self.users[u["id"]] = u
        return u

    async def get_user_by_username(self, username: str) -> dict | None:
        return next((u for u in self.users.values() if u["username"] == username), None)
    async def get_user_by_id(self, uid: str) -> dict | None:
        return self.users.get(uid)
    async def update_user(self, uid: str, data: dict) -> None:
        self.users[uid].update(data)
    async def create_session(self, data: dict) -> dict:
        self.sessions[data["id"]] = dict(data); return data
    async def get_session_by_token_hash(self, h: str) -> dict | None:
        return next((s for s in self.sessions.values() if s["refresh_token_hash"] == h and s["is_active"]), None)
    async def update_session(self, sid: str, data: dict) -> None:
        self.sessions.get(sid, {}).update(data)
    async def revoke_all_user_sessions(self, uid: str, except_id: str = "") -> None:
        for s in self.sessions.values():
            if s["user_id"] == uid and s["id"] != except_id: s["is_active"] = False
    async def log_audit(self, data: dict) -> None:
        self.audit.append(data)
    async def get_member_module_permissions(self, user_id: str, institution_id: str) -> list[str]:
        return []
    async def replace_backup_codes(self, uid: str, hashes: list[str]) -> None:
        await self.delete_backup_codes(uid)
        for h in hashes:
            i = str(uuid.uuid4()); self.codes[i] = {"id": i, "user_id": uid, "code_hash": h, "used_at": None}
    async def get_unused_backup_codes(self, uid: str) -> list[dict]:
        return [c for c in self.codes.values() if c["user_id"] == uid and c["used_at"] is None]
    async def consume_backup_code(self, cid: str) -> bool:
        c = self.codes.get(cid)
        if not c or c["used_at"] is not None: return False
        c["used_at"] = "now"; return True
    async def delete_backup_codes(self, uid: str) -> None:
        self.codes = {k: v for k, v in self.codes.items() if v["user_id"] != uid}


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch):
    db = FakeDB(); cache: dict[str, Any] = {}; counters: dict[str, int] = {}
    async def cache_set(k: str, v: Any, ttl: int) -> None: cache[k] = v
    async def cache_get(k: str) -> Any: return cache.get(k)
    async def cache_delete(k: str) -> None: cache.pop(k, None)
    async def rate(key: str, limit: int, window: int) -> tuple[bool, int]:
        counters[key] = counters.get(key, 0) + 1; return counters[key] <= limit, max(0, limit - counters[key])
    async def noop(*a: Any, **k: Any) -> Any: return None
    async def no(*a: Any, **k: Any) -> bool: return False
    async def empty(*a: Any, **k: Any) -> set: return set()
    for m in (auth_api, mfa_api):
        for name, fn in {"cache_set": cache_set, "cache_get": cache_get, "cache_delete": cache_delete,
                         "check_rate_limit": rate, "is_locked_out": no, "record_failed_login": noop,
                         "clear_failed_logins": noop}.items():
            if hasattr(m, name): monkeypatch.setattr(m, name, fn)
    monkeypatch.setattr(auth_api, "get_user_session_ids", empty)
    monkeypatch.setattr(auth_api, "add_user_session", noop)
    monkeypatch.setattr(auth_api, "remove_user_session", noop)
    monkeypatch.setattr(mw, "is_token_blacklisted", no)
    monkeypatch.setattr(settings, "mfa_encryption_key", Fernet.generate_key().decode())
    app.dependency_overrides[db_dependency] = lambda: db
    yield db, TestClient(app), cache
    app.dependency_overrides.clear()


def login(c: TestClient) -> dict:
    r = c.post("/auth/login", json={"username": "kj", "password": PW}); assert r.status_code == 200, r.text
    return r.json()


def enrol(db: FakeDB, c: TestClient) -> tuple[str, list[str]]:
    tok = login(c)["access_token"]
    r = c.post("/auth/mfa/enrol", headers={"Authorization": f"Bearer {tok}"}); assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    r = c.post("/auth/mfa/verify-enrolment", headers={"Authorization": f"Bearer {tok}"},
               json={"totp_code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    return secret, r.json()["backup_codes"]


def test_password_login_says_password_only(env) -> None:
    db, c, _ = env; db.add_user()
    assert verify_access_token(login(c)["access_token"])["amr"] == ["pwd"]


def test_enrolment_stores_only_an_encrypted_secret_and_signs_everyone_out(env) -> None:
    db, c, _ = env; u = db.add_user()
    secret, codes = enrol(db, c)
    assert u["mfa_enabled"] is True and secret not in u["mfa_secret"]
    assert len(codes) == settings.mfa_backup_codes
    assert all(not s["is_active"] for s in db.sessions.values())
    assert any(a["event_type"] == "mfa.enrolled" for a in db.audit)


def test_login_with_mfa_yields_mfa_amr_and_a_marked_session(env) -> None:
    db, c, cache = env; db.add_user(); secret, _ = enrol(db, c)
    first = login(c); assert first["mfa_required"] and not first["access_token"]
    r = c.post("/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "totp_code": pyotp.TOTP(secret).now()})
    # the enrolment already used now(); a fresh login must not accept the same code again
    assert r.status_code == 401
    cache.clear()  # new 30 s window in real life; here: forget the replay marker
    first = login(c)
    r = c.post("/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "totp_code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    assert "mfa" in verify_access_token(r.json()["access_token"])["amr"]
    assert any(s["mfa_verified"] for s in db.sessions.values() if s["is_active"])
    assert "ficium_rt" in r.headers.get("set-cookie", "")


def test_challenge_dies_after_five_wrong_codes(env) -> None:
    db, c, cache = env; db.add_user(); enrol(db, c); cache.clear()
    tok = login(c)["mfa_token"]
    for _ in range(5):
        assert c.post("/auth/mfa/verify", json={"mfa_token": tok, "totp_code": "000000"}).status_code == 401
    assert c.post("/auth/mfa/verify", json={"mfa_token": tok, "totp_code": "000000"}).status_code == 429
    assert c.post("/auth/mfa/verify", json={"mfa_token": tok, "totp_code": "111111"}).status_code == 401


def test_backup_code_works_once(env) -> None:
    db, c, _ = env; db.add_user(); _, codes = enrol(db, c)
    ok = c.post("/auth/mfa/verify", json={"mfa_token": login(c)["mfa_token"], "backup_code": codes[0]})
    assert ok.status_code == 200 and "mfa" in verify_access_token(ok.json()["access_token"])["amr"]
    again = c.post("/auth/mfa/verify", json={"mfa_token": login(c)["mfa_token"], "backup_code": codes[0]})
    assert again.status_code == 401


def test_requires_exactly_one_factor(env) -> None:
    db, c, _ = env; db.add_user(); enrol(db, c)
    t = login(c)["mfa_token"]
    assert c.post("/auth/mfa/verify", json={"mfa_token": t}).status_code == 422
    assert c.post("/auth/mfa/verify", json={"mfa_token": t, "totp_code": "123456", "backup_code": "ABCDEFGH-12345678"}).status_code == 422


def test_fails_closed_without_encryption_key(env, monkeypatch: pytest.MonkeyPatch) -> None:
    db, c, _ = env; db.add_user()
    tok = login(c)["access_token"]
    monkeypatch.setattr(settings, "mfa_encryption_key", "")
    assert c.post("/auth/mfa/enrol", headers={"Authorization": f"Bearer {tok}"}).status_code == 503


def test_refresh_keeps_mfa_proof_but_never_invents_it(env) -> None:
    db, c, cache = env; db.add_user(); secret, _ = enrol(db, c); cache.clear()
    r = c.post("/auth/mfa/verify", json={"mfa_token": login(c)["mfa_token"], "totp_code": pyotp.TOTP(secret).now()})
    rt = r.cookies.get("ficium_rt") or r.headers["set-cookie"].split("ficium_rt=")[1].split(";")[0]
    r2 = c.post("/auth/refresh", cookies={"ficium_rt": rt})
    assert r2.status_code == 200 and "mfa" in verify_access_token(r2.json()["access_token"])["amr"]


def test_disable_needs_an_mfa_session(env) -> None:
    db, c, cache = env; u = db.add_user()
    pwd_only = login(c)["access_token"]
    secret, _ = enrol(db, c); cache.clear()
    assert c.post("/auth/mfa/disable", headers={"Authorization": f"Bearer {pwd_only}"},
                  json={"password": PW, "totp_code": pyotp.TOTP(secret).now()}).status_code == 403
    r = c.post("/auth/mfa/verify", json={"mfa_token": login(c)["mfa_token"], "totp_code": pyotp.TOTP(secret).now()})
    cache.clear()
    d = c.post("/auth/mfa/disable", headers={"Authorization": f"Bearer {r.json()['access_token']}"},
               json={"password": PW, "totp_code": pyotp.TOTP(secret).now()})
    assert d.status_code == 200 and u["mfa_enabled"] is False and u["mfa_secret"] is None

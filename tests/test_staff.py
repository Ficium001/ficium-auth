# Staff provisioning: who may call, what gets created, and what never gets touched.
from typing import Any

import pytest
from fastapi.testclient import TestClient

import src.api.staff as staff_api
from src.core.config import settings
from src.core.database import db_dependency
from src.core.security import issue_access_token, verify_password
from src.main import app
from tests.test_password_reset import ForgotDB

PLATFORM = "00000000-0000-0000-0000-000000000001"


class StaffDB(ForgotDB):
    async def create_user(self, data: dict) -> dict:
        import uuid
        u = {"id": str(uuid.uuid4()), **data}; self.users[u["id"]] = u; return u
    async def get_users_by_emails(self, inst: str, emails: list[str]) -> list[dict]:
        return [u for u in self.users.values() if u["institution_id"] == inst and u["email"] in emails]
    async def cancel_reset_tokens(self, uid: str) -> None:
        for t in self.tokens.values():
            if t["user_id"] == uid: t["used"] = True


def tok(inst: str = PLATFORM, role: str = "super_admin", amr: list[str] | None = None) -> str:
    t, _ = issue_access_token("caller-1", inst, role, "sess-1",
                              extra_claims={"email": "kj@ficium.net", "amr": amr if amr is not None else ["pwd", "otp", "mfa"]})
    return t


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch):
    db = StaffDB(); mails: list[tuple] = []
    async def send(to: str, url: str, username: str, inviter: str) -> None: mails.append((to, url, username, inviter))
    async def allow(*a: Any, **k: Any): return True, 1
    async def no(*a: Any, **k: Any) -> bool: return False
    monkeypatch.setattr(staff_api, "send_staff_invite_email", send)
    monkeypatch.setattr(staff_api, "check_rate_limit", allow)
    monkeypatch.setattr(staff_api, "is_token_blacklisted", no)
    monkeypatch.setattr(staff_api, "is_account_locked", no)
    async def nothing(*a: Any, **k: Any) -> None: return None
    monkeypatch.setattr(staff_api, "clear_account_failures", nothing)
    app.dependency_overrides[db_dependency] = lambda: db
    yield db, mails, TestClient(app)
    app.dependency_overrides.clear()


def post(c: TestClient, t: str, **body: Any):
    return c.post("/auth/staff/provision", headers={"Authorization": f"Bearer {t}"},
                  json={"email": "Ana@Ficium.net", "username": "Ana", **body})


def test_creates_a_powerless_unusable_staff_login_and_emails_only_the_invitee(env) -> None:
    db, mails, c = env
    r = post(c, tok())
    assert r.status_code == 200 and r.json() == {"status": "created", "email_sent": True}
    u = next(iter(db.users.values()))
    assert (u["email"], u["username"], u["role"], u["institution_id"]) == ("ana@ficium.net", "ana", "ficium_staff", PLATFORM)
    assert not verify_password("anything", u["password_hash"])
    assert "token=" not in r.text                     # the link is never returned to the inviter
    assert mails[0][0] == "ana@ficium.net" and mails[0][1].startswith(f"{settings.admin_public_url}/reset-password?token=")


def test_resend_cancels_the_old_link(env) -> None:
    db, mails, c = env
    post(c, tok()); r = post(c, tok())
    assert r.json()["status"] == "resent"
    assert sum(1 for t in db.tokens.values() if not t["used"]) == 1 and len(mails) == 2


@pytest.mark.parametrize("t,status", [
    (lambda: tok(amr=["pwd"]), 403),                                   # no MFA
    (lambda: tok(inst="f192050a-dfdd-4da7-874e-c3db88f11e41"), 403),  # a bank user
    (lambda: tok(role="analyst"), 403),
    (lambda: "garbage", 401),
])
def test_only_mfa_staff_may_invite(env, t, status) -> None:
    db, mails, c = env
    assert post(c, t()).status_code == status and not db.users and not mails


def test_never_touches_an_existing_account(env) -> None:
    db, mails, c = env
    bank = db.add_user(username="ana", email="ana@ficium.net", institution_id="f192050a-dfdd-4da7-874e-c3db88f11e41")
    assert post(c, tok()).status_code == 409
    assert bank["password_hash"] != staff_api.UNUSABLE and not mails
    assert post(c, tok(), email="bob@ficium.net", username="ana").status_code == 409   # username taken


def test_an_activated_staff_login_is_reused_untouched(env) -> None:
    db, mails, c = env
    real = db.add_user(username="ana", email="ana@ficium.net", role="ficium_staff")   # invited on the other site
    before = dict(real)
    r = post(c, tok())
    assert r.status_code == 200 and r.json() == {"status": "existing", "email_sent": False}
    assert real == before and not mails and not db.tokens
    r = post(c, tok(), username="ana2")
    assert r.status_code == 409 and "'ana'" in r.json()["detail"]


def lookup(c: TestClient, t: str, emails: list[str]):
    return c.post("/auth/staff/lookup", headers={"Authorization": f"Bearer {t}"}, json={"emails": emails})


def test_lookup_returns_staff_only_and_never_secrets(env) -> None:
    db, _, c = env
    db.add_user(username="ana", email="ana@ficium.net", role="ficium_staff", mfa_enabled=True)
    post(c, tok(), email="bob@ficium.net", username="bob")                       # invited, not activated
    db.add_user(username="eve", email="eve@ficium.net", institution_id="f192050a-dfdd-4da7-874e-c3db88f11e41")
    r = lookup(c, tok(), ["ANA@ficium.net", "bob@ficium.net", "eve@ficium.net"])
    assert r.status_code == 200
    got = {a["email"]: a for a in r.json()["accounts"]}
    assert set(got) == {"ana@ficium.net", "bob@ficium.net"}
    assert got["ana@ficium.net"]["activated"] and got["ana@ficium.net"]["mfa_enabled"]
    assert not got["bob@ficium.net"]["activated"]
    assert "password" not in r.text and "secret" not in r.text
    assert lookup(c, tok(amr=["pwd"]), ["ana@ficium.net"]).status_code == 403
    assert lookup(c, tok(), ['a"),email.neq.(x@y.z']).status_code == 422     # no filter injection


def reset(c: TestClient, t: str, **body: Any):
    return c.post("/auth/staff/reset", headers={"Authorization": f"Bearer {t}"}, json={"email": "ana@ficium.net", **body})


def test_reset_locks_the_password_signs_out_and_emails_only_them(env, monkeypatch: pytest.MonkeyPatch) -> None:
    db, _, c = env
    sent: list[tuple] = []
    async def send(to: str, url: str, username: str, reset_mfa: bool) -> None: sent.append((to, url, username, reset_mfa))
    monkeypatch.setattr(staff_api, "send_staff_reset_email", send)
    u = db.add_user(username="ana", email="ana@ficium.net", role="ficium_staff", mfa_enabled=True, mfa_secret="enc")
    db.sessions["s9"] = {"id": "s9", "user_id": u["id"], "is_active": True, "refresh_token_hash": "y"}
    r = reset(c, tok())
    assert r.status_code == 200 and r.json() == {"status": "reset", "email_sent": True}
    assert u["password_hash"] == staff_api.UNUSABLE and not db.sessions["s9"]["is_active"]
    assert u["mfa_enabled"] is True                                   # authenticator kept unless asked
    assert "token=" not in r.text and sent[0][0] == "ana@ficium.net" and sent[0][3] is False
    u["password_hash"] = "x"
    assert reset(c, tok(), reset_mfa=True).status_code == 200
    assert u["mfa_enabled"] is False and u["mfa_secret"] is None and sent[-1][3] is True


def test_reset_refuses_self_bank_users_and_unactivated(env) -> None:
    db, _, c = env
    me = db.add_user(username="kj", email="kj@ficium.net")
    t, _ = issue_access_token(me["id"], PLATFORM, "super_admin", "s", extra_claims={"email": "kj@ficium.net", "amr": ["mfa"]})
    assert c.post("/auth/staff/reset", headers={"Authorization": f"Bearer {t}"}, json={"email": "kj@ficium.net"}).status_code == 403
    db.add_user(username="ana", email="ana@ficium.net", institution_id="f192050a-dfdd-4da7-874e-c3db88f11e41")
    assert reset(c, tok()).status_code == 404
    post(c, tok(), email="bob@ficium.net", username="bob")
    assert c.post("/auth/staff/reset", headers={"Authorization": f"Bearer {tok()}"}, json={"email": "bob@ficium.net"}).status_code == 409
    assert reset(c, tok(amr=["pwd"])).status_code == 403


def test_staff_must_use_a_ficium_address(env) -> None:
    _, mails, c = env
    assert post(c, tok(), email="ana@gmail.com").status_code == 400 and not mails


def test_reports_but_survives_an_email_failure(env, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, c = env
    async def boom(*a: Any, **k: Any) -> None: raise RuntimeError("domain is not verified: secret-detail")
    monkeypatch.setattr(staff_api, "send_staff_invite_email", boom)
    r = post(c, tok())
    assert r.status_code == 200 and r.json()["email_sent"] is False and "secret-detail" not in r.text


def test_resend_by_email_alone_and_create_needs_a_username(env) -> None:
    _, mails, c = env
    assert c.post("/auth/staff/provision", headers={"Authorization": f"Bearer {tok()}"}, json={"email": "ana@ficium.net"}).status_code == 422
    post(c, tok())
    r = c.post("/auth/staff/provision", headers={"Authorization": f"Bearer {tok()}"}, json={"email": "ana@ficium.net"})
    assert r.json()["status"] == "resent" and mails[-1][2] == "ana"

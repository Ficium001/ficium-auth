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
    real = db.add_user(username="ana", email="ana@ficium.net")         # an activated account
    assert post(c, tok()).status_code == 409
    assert real["password_hash"] != staff_api.UNUSABLE and not mails
    assert post(c, tok(), email="bob@ficium.net", username="ana").status_code == 409   # username taken


def test_staff_must_use_a_ficium_address(env) -> None:
    _, mails, c = env
    assert post(c, tok(), email="ana@gmail.com").status_code == 400 and not mails


def test_reports_but_survives_an_email_failure(env, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, c = env
    async def boom(*a: Any, **k: Any) -> None: raise RuntimeError("domain is not verified: secret-detail")
    monkeypatch.setattr(staff_api, "send_staff_invite_email", boom)
    r = post(c, tok())
    assert r.status_code == 200 and r.json()["email_sent"] is False and "secret-detail" not in r.text

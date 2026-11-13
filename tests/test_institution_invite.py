# Institution first-admin invite: who may call, which accounts it may touch, where the link goes.
from typing import Any

import pytest
from fastapi.testclient import TestClient

import src.api.institution_invite as inv
from src.api.staff import UNUSABLE
from src.core.config import settings
from src.core.database import db_dependency
from src.main import app
from tests.test_staff import PLATFORM, StaffDB, tok

BANK = "f192050a-dfdd-4da7-874e-c3db88f11e41"


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch):
    db = StaffDB(); mails: list[tuple] = []
    async def send(to: str, url: str, username: str) -> None: mails.append((to, url, username))
    async def allow(*a: Any, **k: Any): return True, 1
    async def no(*a: Any, **k: Any) -> bool: return False
    monkeypatch.setattr(inv, "send_institution_invite_email", send)
    monkeypatch.setattr(inv, "check_rate_limit", allow)
    monkeypatch.setattr("src.api.staff.is_token_blacklisted", no)
    app.dependency_overrides[db_dependency] = lambda: db
    yield db, mails, TestClient(app)
    app.dependency_overrides.clear()


def provisioned(db: StaffDB, **over: Any) -> dict:
    # What portal-api's institution.provision creates: unusable password, bank institution.
    fields = {"username": "ada@zzbank.mu", "email": "ada@zzbank.mu", "institution_id": BANK,
              "role": "institution_admin", "password_hash": UNUSABLE, "is_active": True}
    return db.add_user(**{**fields, **over})


def post(c: TestClient, t: str, email: str = "Ada@ZZBank.mu"):
    return c.post("/auth/institution/invite", headers={"Authorization": f"Bearer {t}"}, json={"email": email})


def test_emails_a_portal_link_only_to_the_invitee_and_never_returns_it(env) -> None:
    db, mails, c = env
    provisioned(db)
    r = post(c, tok())
    assert r.status_code == 200 and r.json() == {"status": "sent", "email_sent": True}
    assert "token=" not in r.text
    assert mails[0][0] == "ada@zzbank.mu"
    assert mails[0][1].startswith(f"{settings.portal_public_url}/reset-password?token=")
    assert sum(1 for t in db.tokens.values() if not t["used"]) == 1


def test_resend_cancels_the_old_link(env) -> None:
    db, mails, c = env
    provisioned(db)
    post(c, tok()); post(c, tok())
    assert sum(1 for t in db.tokens.values() if not t["used"]) == 1 and len(mails) == 2


@pytest.mark.parametrize("t,status", [
    (lambda: tok(amr=["pwd"]), 403),        # no MFA
    (lambda: tok(inst=BANK), 403),          # a bank user cannot invite
    (lambda: tok(role="analyst"), 403),
    (lambda: "garbage", 401),
])
def test_only_mfa_staff_may_invite(env, t, status) -> None:
    db, mails, c = env
    provisioned(db)
    assert post(c, t()).status_code == status and not mails and not db.tokens


@pytest.mark.parametrize("over,status", [
    ({"password_hash": "$argon2id$v=19$m=65536,t=3,p=4$real$hash"}, 409),   # already active
    ({"is_active": False}, 409),                                            # deactivated
    ({"institution_id": PLATFORM}, 409),                                    # Ficium staff
])
def test_never_touches_an_active_deactivated_or_staff_account(env, over, status) -> None:
    db, mails, c = env
    provisioned(db, **over)
    assert post(c, tok()).status_code == status and not mails and not db.tokens


def test_unknown_email_is_refused(env) -> None:
    _, mails, c = env
    assert post(c, tok(), email="nobody@zzbank.mu").status_code == 404 and not mails


def test_reports_but_survives_an_email_failure(env, monkeypatch: pytest.MonkeyPatch) -> None:
    db, _, c = env
    provisioned(db)
    async def boom(*a: Any, **k: Any) -> None: raise RuntimeError("provider said: secret-detail")
    monkeypatch.setattr(inv, "send_institution_invite_email", boom)
    r = post(c, tok())
    assert r.status_code == 200 and r.json()["email_sent"] is False and "secret-detail" not in r.text

# =============================================================
# ficium-auth — Database via Supabase REST API
# Direct TCP connections to Supabase fail on free plan from Railway.
# All DB operations go through Supabase PostgREST REST API
# using the service role key (bypasses RLS).
# =============================================================

import httpx
from typing import Any, Optional
from .config import settings

SCHEMA = "auth_portal"
BASE   = f"{settings.supabase_url}/rest/v1"

def _headers(prefer: str = "") -> dict:
    h = {
        "apikey":          settings.supabase_service_key,
        "Authorization":   f"Bearer {settings.supabase_service_key}",
        "Content-Type":    "application/json",
        "Accept":          "application/json",
        "Accept-Profile":  SCHEMA,
        "Content-Profile": SCHEMA,
    }
    if prefer:
        h["Prefer"] = prefer
    return h


class SupabaseDB:
    """Minimal async DB client over Supabase REST API."""

    def __init__(self):
        self._client = httpx.AsyncClient(timeout=10)

    # ── auth_users ────────────────────────────────────────────

    async def get_user_by_email(self, email: str) -> Optional[dict]:
        r = await self._client.get(
            f"{BASE}/auth_users",
            headers=_headers(),
            params={"email": f"eq.{email}", "limit": "1"},
        )
        r.raise_for_status()
        rows = r.json()
        return rows[0] if rows else None

    async def get_user_by_username(self, username: str) -> Optional[dict]:
        r = await self._client.get(
            f"{BASE}/auth_users",
            headers=_headers(),
            params={"username": f"eq.{username}", "limit": "1"},
        )
        r.raise_for_status()
        rows = r.json()
        return rows[0] if rows else None

    async def get_user_by_id(self, user_id: str) -> Optional[dict]:
        r = await self._client.get(
            f"{BASE}/auth_users",
            headers=_headers(),
            params={"id": f"eq.{user_id}", "limit": "1"},
        )
        r.raise_for_status()
        rows = r.json()
        return rows[0] if rows else None

    async def create_user(self, data: dict) -> dict:
        r = await self._client.post(
            f"{BASE}/auth_users",
            headers=_headers("return=representation"),
            json=data,
        )
        r.raise_for_status()
        return r.json()[0]

    async def update_user(self, user_id: str, data: dict) -> None:
        r = await self._client.patch(
            f"{BASE}/auth_users",
            headers=_headers(),
            params={"id": f"eq.{user_id}"},
            json=data,
        )
        r.raise_for_status()

    # ── auth_sessions ─────────────────────────────────────────

    async def create_session(self, data: dict) -> dict:
        r = await self._client.post(
            f"{BASE}/auth_sessions",
            headers=_headers("return=representation"),
            json=data,
        )
        r.raise_for_status()
        return r.json()[0]

    async def get_session_by_token_hash(self, token_hash: str) -> Optional[dict]:
        r = await self._client.get(
            f"{BASE}/auth_sessions",
            headers=_headers(),
            params={"refresh_token_hash": f"eq.{token_hash}", "is_active": "eq.true", "limit": "1"},
        )
        r.raise_for_status()
        rows = r.json()
        return rows[0] if rows else None

    async def get_sessions_by_user(self, user_id: str) -> list[dict]:
        r = await self._client.get(
            f"{BASE}/auth_sessions",
            headers=_headers(),
            params={"user_id": f"eq.{user_id}", "is_active": "eq.true"},
        )
        r.raise_for_status()
        return r.json()

    async def update_session(self, session_id: str, data: dict) -> None:
        r = await self._client.patch(
            f"{BASE}/auth_sessions",
            headers=_headers(),
            params={"id": f"eq.{session_id}"},
            json=data,
        )
        r.raise_for_status()

    async def revoke_all_user_sessions(self, user_id: str, except_id: str = "") -> None:
        params: dict = {"user_id": f"eq.{user_id}", "is_active": "eq.true"}
        if except_id:
            params["id"] = f"neq.{except_id}"
        r = await self._client.patch(
            f"{BASE}/auth_sessions",
            headers=_headers(),
            params=params,
            json={"is_active": False, "revoke_reason": "logout_all"},
        )
        r.raise_for_status()

    # ── audit events ──────────────────────────────────────────

    async def log_audit(self, data: dict) -> None:
        try:
            r = await self._client.post(
                f"{BASE}/auth_audit_events",
                headers=_headers(),
                json=data,
            )
            r.raise_for_status()
        except Exception:
            pass  # audit failure must never break auth flow

    # ── password reset tokens ─────────────────────────────────

    async def create_password_reset_token(self, data: dict) -> dict:
        r = await self._client.post(
            f"{BASE}/password_reset_tokens",
            headers=_headers("return=representation"),
            json=data,
        )
        r.raise_for_status()
        return r.json()[0]

    async def get_password_reset_token(self, token_hash: str) -> Optional[dict]:
        r = await self._client.get(
            f"{BASE}/password_reset_tokens",
            headers=_headers(),
            params={"token_hash": f"eq.{token_hash}", "used": "eq.false", "limit": "1"},
        )
        r.raise_for_status()
        rows = r.json()
        return rows[0] if rows else None

    async def mark_reset_token_used(self, token_id: str) -> None:
        r = await self._client.patch(
            f"{BASE}/password_reset_tokens",
            headers=_headers(),
            params={"id": f"eq.{token_id}"},
            json={"used": True},
        )
        r.raise_for_status()

    # ── email verification tokens ─────────────────────────────

    async def create_email_verification_token(self, data: dict) -> dict:
        r = await self._client.post(
            f"{BASE}/email_verification_tokens",
            headers=_headers("return=representation"),
            json=data,
        )
        r.raise_for_status()
        return r.json()[0]

    async def get_email_verification_token(self, token_hash: str) -> Optional[dict]:
        r = await self._client.get(
            f"{BASE}/email_verification_tokens",
            headers=_headers(),
            params={"token_hash": f"eq.{token_hash}", "used": "eq.false", "limit": "1"},
        )
        r.raise_for_status()
        rows = r.json()
        return rows[0] if rows else None

    async def mark_email_verified(self, token_id: str, user_id: str) -> None:
        # Mark token used
        await self._client.patch(
            f"{BASE}/email_verification_tokens",
            headers=_headers(),
            params={"id": f"eq.{token_id}"},
            json={"used": True},
        )
        # Mark user verified
        await self.update_user(user_id, {"email_verified": True})

    # ── health ────────────────────────────────────────────────

    async def health(self) -> bool:
        try:
            r = await self._client.get(
                f"{BASE}/auth_users",
                headers=_headers(),
                params={"limit": "0"},
            )
            return r.status_code < 500
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()

    async def get_member_module_permissions(
        self, user_id: str, institution_id: str
    ) -> list[str]:
        """
        Fetch module_permissions from institution.group via
        institution.member.custom_group_id.
        Returns [] if the member has no group or no permissions assigned.
        Uses the institution schema (not auth_portal), so overrides Accept-Profile.
        """
        # Override schema header to hit institution.* tables
        inst_headers = {
            "apikey":          settings.supabase_service_key,
            "Authorization":   f"Bearer {settings.supabase_service_key}",
            "Content-Type":    "application/json",
            "Accept":          "application/json",
            "Accept-Profile":  "institution",
        }
        r = await self._client.get(
            f"{settings.supabase_url}/rest/v1/member",
            headers=inst_headers,
            params={
                "select":         "institution_group:custom_group_id(module_permissions)",
                "id":             f"eq.{user_id}",
                "institution_id": f"eq.{institution_id}",
                "limit":          "1",
            },
        )
        if r.status_code != 200:
            return []
        rows = r.json()
        if not rows:
            return []
        group = (rows[0].get("institution_group") or {})
        perms = group.get("module_permissions") or []
        return perms if isinstance(perms, list) else []


# ── Singleton ─────────────────────────────────────────────────
_db: Optional[SupabaseDB] = None


def get_db_client() -> SupabaseDB:
    global _db
    if _db is None:
        _db = SupabaseDB()
    return _db


async def check_db_health() -> bool:
    return await get_db_client().health()


# ── FastAPI dependency ────────────────────────────────────────
async def db_dependency():
    yield get_db_client()


# ── Legacy Base for model imports (no-op) ────────────────────
from sqlalchemy.orm import DeclarativeBase
class Base(DeclarativeBase):
    pass

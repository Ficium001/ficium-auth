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
        Fetch module_permissions via a single RPC call to
        auth_portal.get_member_module_permissions(email, institution_id).

        Rationale: auth_portal.auth_users.id != institution.member.id —
        different UUIDs. We need to resolve via email. Rather than two
        fragile REST hops (auth_users → member → group), we call an
        auth_portal-schema SQL function that does the join server-side
        in one round-trip, executed as service_role.
        """
        # Step 1: get email from auth_portal.auth_users
        r = await self._client.get(
            f"{BASE}/auth_users",
            headers=_headers(),
            params={"id": f"eq.{user_id}", "select": "email,institution_id", "limit": "1"},
        )
        if r.status_code != 200 or not r.json():
            return []
        row = r.json()[0]
        email = row.get("email", "")
        # Use institution_id from the user record if caller didn't pass one
        resolved_institution_id = institution_id or row.get("institution_id", "")
        if not email or not resolved_institution_id:
            return []

        # Step 2: single RPC call — auth_portal.get_member_module_permissions
        rpc_headers = {
            "apikey":          settings.supabase_service_key,
            "Authorization":   f"Bearer {settings.supabase_service_key}",
            "Content-Type":    "application/json",
            "Accept":          "application/json",
            "Accept-Profile":  "auth_portal",
            "Content-Profile": "auth_portal",
        }
        r2 = await self._client.post(
            f"{settings.supabase_url}/rest/v1/rpc/get_member_module_permissions",
            headers=rpc_headers,
            json={
                "p_email":          email,
                "p_institution_id": resolved_institution_id,
            },
        )
        if r2.status_code != 200:
            return []
        result = r2.json()
        if isinstance(result, list):
            return result
        return []


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

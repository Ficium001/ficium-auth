# =============================================================
# ficium-auth — Postgres data layer (least privilege)
#
# Same interface as SupabaseDB (database.py), but connects straight to the
# Portal DB's transaction pooler as role `ficium_auth`, which can touch only
# auth_portal (migrations/003). No service_role key is needed or held.
#
# TLS is always verify-full against Supabase's CA (DB_SSL_ROOT_CERT): this
# backend refuses to start without it.
#
# Rows come back as to_jsonb(...) so callers get exactly what PostgREST gave
# them (ISO timestamps as strings, uuids as strings). Writes go through
# jsonb_populate_record so Postgres does the type conversion, and only column
# names from the fixed list below can ever reach the SQL text.
# =============================================================

from __future__ import annotations

import asyncio
import json
import os
import ssl
import tempfile
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import asyncpg
import structlog

from .config import settings
from .database import SupabaseDB

log = structlog.get_logger()

S = "auth_portal"

COLUMNS: dict[str, frozenset[str]] = {
    "auth_users": frozenset({
        "id", "institution_id", "email", "email_verified", "password_hash", "role", "is_active",
        "mfa_enabled", "mfa_secret", "last_login_at", "last_login_ip", "failed_attempts",
        "locked_until", "password_changed_at", "created_at", "updated_at", "username",
        "must_change_password"}),
    "auth_sessions": frozenset({
        "id", "user_id", "refresh_token_hash", "ip_address", "user_agent", "device_fingerprint",
        "is_active", "created_at", "last_used_at", "expires_at", "revoked_at", "revoke_reason",
        "mfa_verified"}),
    "mfa_backup_codes": frozenset({"id", "user_id", "code_hash", "used_at", "created_at"}),
    "password_reset_tokens": frozenset({
        "id", "user_id", "token_hash", "used", "ip_address", "created_at", "expires_at", "used_at"}),
    "email_verification_tokens": frozenset({
        "id", "user_id", "token_hash", "used", "created_at", "expires_at"}),
    "auth_audit_events": frozenset({
        "id", "user_id", "institution_id", "event_type", "outcome", "ip_address", "user_agent",
        "event_metadata", "created_at"}),
}


def columns_for(table: str, data: dict[str, Any]) -> str:
    """Quoted column list for a write. Refuses any table or key not in COLUMNS."""
    allowed = COLUMNS.get(table)
    if allowed is None:
        raise ValueError(f"unknown table {table!r}")
    if not data:
        raise ValueError("nothing to write")
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(f"unknown column(s) for {table}: {unknown}")
    return ", ".join(f'"{c}"' for c in sorted(data))


def insert_sql(table: str, data: dict[str, Any]) -> str:
    cols = columns_for(table, data)
    return (f"INSERT INTO {S}.{table} AS t ({cols}) "
            f"SELECT {cols} FROM jsonb_populate_record(NULL::{S}.{table}, $1::jsonb) "
            "RETURNING to_jsonb(t)")


def update_sql(table: str, data: dict[str, Any], where: str) -> str:
    """UPDATE … SET (cols) = (values from $1) WHERE <where>. `where` is fixed text from this
    module, never caller input; its parameters start at $2."""
    cols = columns_for(table, data)
    return (f"UPDATE {S}.{table} AS t SET ({cols}) = "
            f"(SELECT {cols} FROM jsonb_populate_record(NULL::{S}.{table}, $1::jsonb)) "
            f"WHERE {where} RETURNING to_jsonb(t)")


def _dumps(data: Any) -> str:
    return json.dumps(data, default=str)


def plain_dsn(url: str) -> str:
    """asyncpg wants postgresql://…; drop driver suffixes and any sslmode in the URL
    (TLS is configured explicitly below and must not be weakened by the URL)."""
    url = url.replace("postgresql+asyncpg://", "postgresql://")
    url = url.replace("postgresql+psycopg2://", "postgresql://")
    url = url.replace("postgres://", "postgresql://", 1)
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k.lower() not in ("sslmode", "ssl")]
    return urlunsplit(parts._replace(query=urlencode(query)))


def verified_ssl_context(root_cert: str) -> ssl.SSLContext:
    """verify-full: chain to Supabase's CA and hostname checked. PEM text or a path."""
    cert = (root_cert or "").strip()
    if not cert:
        raise RuntimeError("AUTH_DB_BACKEND=postgres needs DB_SSL_ROOT_CERT (Supabase's CA)")
    if "BEGIN CERTIFICATE" in cert:
        fd, path = tempfile.mkstemp(prefix="auth-db-ca-", suffix=".crt")
        with os.fdopen(fd, "w") as f:
            f.write(cert if cert.endswith("\n") else cert + "\n")
        os.chmod(path, 0o600)
    elif os.path.isfile(cert):
        path = cert
    else:
        raise RuntimeError("DB_SSL_ROOT_CERT is neither PEM text nor an existing file")
    ctx = ssl.create_default_context(cafile=path)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class PostgresDB(SupabaseDB):
    """auth_portal over the transaction pooler as role ficium_auth (no service key)."""

    def __init__(self) -> None:
        # Deliberately not calling SupabaseDB.__init__: no PostgREST client, no service key.
        if not settings.db_url:
            raise RuntimeError("AUTH_DB_BACKEND=postgres needs DB_URL (role ficium_auth)")
        self._dsn = plain_dsn(settings.db_url)
        self._ssl = verified_ssl_context(settings.db_ssl_root_cert)
        self._pool: asyncpg.Pool | None = None
        self._lock = asyncio.Lock()

    async def _p(self) -> asyncpg.Pool:
        if self._pool is None:
            async with self._lock:
                if self._pool is None:
                    self._pool = await asyncpg.create_pool(
                        self._dsn, ssl=self._ssl,
                        min_size=1, max_size=settings.db_pool_max,
                        statement_cache_size=0,      # transaction pooler: no prepared statements
                        command_timeout=10, timeout=8,
                    )
                    log.info("auth_db_pool_ready", backend="postgres", tls="verify-full")
        return self._pool

    async def _rows(self, sql: str, *args: Any) -> list[dict]:
        pool = await self._p()
        return [json.loads(r[0]) for r in await pool.fetch(sql, *args)]

    async def _row(self, sql: str, *args: Any) -> dict | None:
        rows = await self._rows(sql, *args)
        return rows[0] if rows else None

    async def _select_one(self, table: str, where: str, *args: Any) -> dict | None:
        return await self._row(f"SELECT to_jsonb(t) FROM {S}.{table} t WHERE {where} LIMIT 1", *args)

    async def _insert(self, table: str, data: dict) -> dict:
        row = await self._row(insert_sql(table, data), _dumps(data))
        if row is None:  # pragma: no cover - INSERT … RETURNING always returns the row
            raise RuntimeError(f"insert into {table} returned nothing")
        return row

    async def _update(self, table: str, data: dict, where: str, *args: Any) -> list[dict]:
        return await self._rows(update_sql(table, data, where), _dumps(data), *args)

    # ── auth_users ────────────────────────────────────────────

    async def get_user_by_email(self, email: str) -> dict | None:
        return await self._select_one("auth_users", "t.email = $1", email)

    async def get_user_by_username(self, username: str) -> dict | None:
        return await self._select_one("auth_users", "t.username = $1", username)

    async def get_users_by_emails(self, institution_id: str, emails: list[str]) -> list[dict]:
        if not emails:
            return []
        return await self._rows(
            "SELECT jsonb_build_object('id', t.id, 'email', t.email, 'username', t.username,"
            " 'password_hash', t.password_hash, 'mfa_enabled', t.mfa_enabled,"
            " 'is_active', t.is_active, 'last_login_at', t.last_login_at)"
            " FROM auth_portal.auth_users t WHERE t.institution_id = $1::uuid AND t.email = ANY($2::text[])"
            " LIMIT $3",
            institution_id, list(emails), len(emails))

    async def get_user_by_id(self, user_id: str) -> dict | None:
        return await self._select_one("auth_users", "t.id = $1::uuid", user_id)

    async def create_user(self, data: dict) -> dict:
        return await self._insert("auth_users", data)

    async def update_user(self, user_id: str, data: dict) -> None:
        await self._update("auth_users", data, "t.id = $2::uuid", user_id)

    # ── auth_sessions ─────────────────────────────────────────

    async def create_session(self, data: dict) -> dict:
        return await self._insert("auth_sessions", data)

    async def get_session_by_token_hash(self, token_hash: str) -> dict | None:
        return await self._select_one("auth_sessions", "t.refresh_token_hash = $1 AND t.is_active",
                                      token_hash)

    async def get_sessions_by_user(self, user_id: str) -> list[dict]:
        return await self._rows(
            "SELECT to_jsonb(t) FROM auth_portal.auth_sessions t WHERE t.user_id = $1::uuid AND t.is_active",
            user_id)

    async def update_session(self, session_id: str, data: dict) -> None:
        await self._update("auth_sessions", data, "t.id = $2::uuid", session_id)

    async def revoke_all_user_sessions(self, user_id: str, except_id: str = "") -> None:
        pool = await self._p()
        await pool.execute(
            "UPDATE auth_portal.auth_sessions SET is_active = false, revoke_reason = 'logout_all'"
            " WHERE user_id = $1::uuid AND is_active AND ($2 = '' OR id::text <> $2)",
            user_id, except_id or "")

    # ── mfa_backup_codes ──────────────────────────────────────

    async def replace_backup_codes(self, user_id: str, hashes: list[str]) -> None:
        pool = await self._p()
        async with pool.acquire() as conn, conn.transaction():  # one step: never half-replaced
            await conn.execute("DELETE FROM auth_portal.mfa_backup_codes WHERE user_id = $1::uuid", user_id)
            if hashes:
                await conn.execute(
                    "INSERT INTO auth_portal.mfa_backup_codes (user_id, code_hash)"
                    " SELECT $1::uuid, h FROM unnest($2::text[]) AS h",
                    user_id, list(hashes))

    async def get_unused_backup_codes(self, user_id: str) -> list[dict]:
        return await self._rows(
            "SELECT jsonb_build_object('id', t.id, 'code_hash', t.code_hash)"
            " FROM auth_portal.mfa_backup_codes t WHERE t.user_id = $1::uuid AND t.used_at IS NULL",
            user_id)

    async def consume_backup_code(self, code_id: str) -> bool:
        """Mark a code used; True only for the caller that actually flipped it (no double use)."""
        pool = await self._p()
        hit = await pool.fetchval(
            "UPDATE auth_portal.mfa_backup_codes SET used_at = now()"
            " WHERE id = $1::uuid AND used_at IS NULL RETURNING id", code_id)
        return hit is not None

    async def delete_backup_codes(self, user_id: str) -> None:
        pool = await self._p()
        await pool.execute("DELETE FROM auth_portal.mfa_backup_codes WHERE user_id = $1::uuid", user_id)

    # ── audit events ──────────────────────────────────────────

    async def log_audit(self, data: dict) -> None:
        try:
            await self._insert("auth_audit_events", data)
        except Exception as e:  # noqa: BLE001 - audit failure must never break auth, but must be seen
            log.error("audit_write_failed", error_type=type(e).__name__, error=str(e),
                      event_type=data.get("event_type"))

    # ── password reset tokens ─────────────────────────────────

    async def create_password_reset_token(self, data: dict) -> dict:
        return await self._insert("password_reset_tokens", data)

    async def cancel_reset_tokens(self, user_id: str) -> None:
        pool = await self._p()
        await pool.execute(
            "UPDATE auth_portal.password_reset_tokens SET used = true, used_at = now()"
            " WHERE user_id = $1::uuid AND NOT used", user_id)

    async def get_password_reset_token(self, token_hash: str) -> dict | None:
        return await self._select_one("password_reset_tokens", "t.token_hash = $1 AND NOT t.used",
                                      token_hash)

    async def mark_reset_token_used(self, token_id: str) -> bool:
        pool = await self._p()
        hit = await pool.fetchval(
            "UPDATE auth_portal.password_reset_tokens SET used = true, used_at = now()"
            " WHERE id = $1::uuid AND NOT used RETURNING id", token_id)
        return hit is not None

    # ── email verification tokens ─────────────────────────────

    async def create_email_verification_token(self, data: dict) -> dict:
        return await self._insert("email_verification_tokens", data)

    async def get_email_verification_token(self, token_hash: str) -> dict | None:
        return await self._select_one("email_verification_tokens",
                                      "t.token_hash = $1 AND NOT t.used", token_hash)

    async def mark_email_verified(self, token_id: str, user_id: str) -> None:
        pool = await self._p()
        async with pool.acquire() as conn, conn.transaction():
            await conn.execute(
                "UPDATE auth_portal.email_verification_tokens SET used = true WHERE id = $1::uuid", token_id)
            await conn.execute(
                "UPDATE auth_portal.auth_users SET email_verified = true WHERE id = $1::uuid", user_id)

    # ── module permissions ────────────────────────────────────

    async def get_member_module_permissions(self, user_id: str, institution_id: str) -> list[str]:
        user = await self._row(
            "SELECT jsonb_build_object('email', t.email, 'institution_id', t.institution_id)"
            " FROM auth_portal.auth_users t WHERE t.id = $1::uuid LIMIT 1", user_id)
        if not user:
            return []
        email = user.get("email") or ""
        inst = institution_id or user.get("institution_id") or ""
        if not email or not inst:
            return []
        pool = await self._p()
        perms = await pool.fetchval(
            "SELECT auth_portal.get_member_module_permissions($1, $2::uuid)", email, inst)
        return list(perms or [])

    # ── health ────────────────────────────────────────────────

    async def health(self) -> bool:
        try:
            pool = await self._p()
            await pool.fetchval("SELECT count(*) FROM (SELECT 1 FROM auth_portal.auth_users LIMIT 1) x")
            return True
        except Exception:  # noqa: BLE001 - health probe: any failure means unhealthy
            return False

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

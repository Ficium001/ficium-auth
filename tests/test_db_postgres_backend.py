"""Least-privilege Postgres backend: safe SQL building, verify-full TLS, backend selection."""
import os

import pytest

from src.core import database as dbmod
from src.core.database_pg import (
    columns_for,
    insert_sql,
    plain_dsn,
    update_sql,
    verified_ssl_context,
)


def test_columns_are_allow_listed_and_quoted():
    assert columns_for("auth_users", {"email": 1, "is_active": 1}) == '"email", "is_active"'


@pytest.mark.parametrize("table,data", [
    ("auth_users", {"email; drop table x": 1}),
    ("auth_users", {"nope": 1}),
    ("pg_authid", {"rolname": 1}),
    ("auth_users", {}),
])
def test_refuses_unknown_tables_columns_and_empty_writes(table, data):
    with pytest.raises(ValueError):
        columns_for(table, data)


def test_insert_and_update_take_values_only_as_one_json_parameter():
    sql = insert_sql("auth_sessions", {"user_id": "u", "is_active": True})
    assert "jsonb_populate_record(NULL::auth_portal.auth_sessions, $1::jsonb)" in sql
    assert sql.endswith("RETURNING to_jsonb(t)")
    up = update_sql("auth_users", {"failed_attempts": 3}, "t.id = $2::uuid")
    assert up.startswith('UPDATE auth_portal.auth_users AS t SET ("failed_attempts") =')
    assert "WHERE t.id = $2::uuid" in up


def test_dsn_loses_driver_and_any_weaker_sslmode():
    d = plain_dsn("postgresql+asyncpg://ficium_auth.ref:pw@h:6543/postgres?sslmode=disable&x=1")
    assert d == "postgresql://ficium_auth.ref:pw@h:6543/postgres?x=1"


def test_tls_needs_the_ca():
    with pytest.raises(RuntimeError):
        verified_ssl_context("")
    with pytest.raises(RuntimeError):
        verified_ssl_context("/no/such/ca.crt")


def test_tls_is_verify_full_with_a_real_ca():
    import certifi  # a real CA bundle stands in for Supabase's CA
    ctx = verified_ssl_context(certifi.where())
    assert ctx.check_hostname is True
    assert ctx.verify_mode.name == "CERT_REQUIRED"


def test_backend_selection(monkeypatch):
    monkeypatch.setattr(dbmod, "_db", None)
    monkeypatch.setattr(dbmod.settings, "auth_db_backend", "postgres")
    monkeypatch.setattr(dbmod.settings, "db_url", "")
    with pytest.raises(RuntimeError, match="DB_URL"):
        dbmod.get_db_client()
    monkeypatch.setattr(dbmod.settings, "auth_db_backend", "rest")
    assert type(dbmod.get_db_client()).__name__ == "SupabaseDB"
    monkeypatch.setattr(dbmod, "_db", None)


def test_backend_value_is_validated():
    from src.core.config import Settings
    with pytest.raises(ValueError):
        Settings(auth_db_backend="mysql", _env_file=None, **{k.lower(): v for k, v in os.environ.items()
                 if k in ("JWT_PRIVATE_KEY", "JWT_PUBLIC_KEY", "REDIS_URL", "REDIS_PASSWORD")})

-- =============================================================
-- ficium-auth — Migration 001
-- Creates auth_portal schema and all tables in Supabase Postgres
-- Run once in Supabase SQL editor (project: egwobcajdlragubtkpqp)
-- =============================================================

-- ── Schema ────────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS auth_portal;

-- ── Grants ────────────────────────────────────────────────────
-- service_role writes (ficium-auth FastAPI service)
-- authenticated reads nothing directly — auth is via ficium-auth JWT
GRANT USAGE ON SCHEMA auth_portal TO service_role;
GRANT ALL   ON ALL TABLES    IN SCHEMA auth_portal TO service_role;
GRANT ALL   ON ALL SEQUENCES IN SCHEMA auth_portal TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth_portal
  GRANT ALL ON TABLES    TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth_portal
  GRANT ALL ON SEQUENCES TO service_role;

-- ── Extensions ────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── auth_users ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_portal.auth_users (
  id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  institution_id       UUID        NOT NULL,
  email                VARCHAR(255) NOT NULL,
  email_verified       BOOLEAN     NOT NULL DEFAULT FALSE,
  password_hash        TEXT        NOT NULL,
  role                 VARCHAR(50) NOT NULL DEFAULT 'analyst',
  is_active            BOOLEAN     NOT NULL DEFAULT TRUE,
  mfa_enabled          BOOLEAN     NOT NULL DEFAULT FALSE,
  mfa_secret           TEXT,
  last_login_at        TIMESTAMPTZ,
  last_login_ip        VARCHAR(45),
  failed_attempts      INTEGER     NOT NULL DEFAULT 0,
  locked_until         TIMESTAMPTZ,
  password_changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  force_password_reset BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_auth_users_email UNIQUE (email)
);

CREATE INDEX IF NOT EXISTS ix_auth_users_email          ON auth_portal.auth_users (email);
CREATE INDEX IF NOT EXISTS ix_auth_users_institution_id ON auth_portal.auth_users (institution_id);

-- auto-update updated_at
CREATE OR REPLACE FUNCTION auth_portal.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

CREATE TRIGGER trg_auth_users_updated_at
  BEFORE UPDATE ON auth_portal.auth_users
  FOR EACH ROW EXECUTE FUNCTION auth_portal.set_updated_at();

-- ── auth_sessions ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_portal.auth_sessions (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID        NOT NULL REFERENCES auth_portal.auth_users(id) ON DELETE CASCADE,
  refresh_token_hash  VARCHAR(64) NOT NULL UNIQUE,
  ip_address          VARCHAR(45),
  user_agent          TEXT,
  device_fingerprint  VARCHAR(64),
  is_active           BOOLEAN     NOT NULL DEFAULT TRUE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at          TIMESTAMPTZ NOT NULL,
  revoked_at          TIMESTAMPTZ,
  revoke_reason       VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_id            ON auth_portal.auth_sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_refresh_token_hash ON auth_portal.auth_sessions (refresh_token_hash);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_expires_at         ON auth_portal.auth_sessions (expires_at);

-- ── mfa_backup_codes ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_portal.mfa_backup_codes (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL REFERENCES auth_portal.auth_users(id) ON DELETE CASCADE,
  code_hash   VARCHAR(64) NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_mfa_backup_codes_user_id ON auth_portal.mfa_backup_codes (user_id);

-- ── password_reset_tokens ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_portal.password_reset_tokens (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL REFERENCES auth_portal.auth_users(id) ON DELETE CASCADE,
  token_hash  VARCHAR(64) NOT NULL UNIQUE,
  used        BOOLEAN     NOT NULL DEFAULT FALSE,
  ip_address  VARCHAR(45),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_pwd_reset_token_hash ON auth_portal.password_reset_tokens (token_hash);
CREATE INDEX IF NOT EXISTS ix_pwd_reset_user_id    ON auth_portal.password_reset_tokens (user_id);

-- ── email_verification_tokens ─────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_portal.email_verification_tokens (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL REFERENCES auth_portal.auth_users(id) ON DELETE CASCADE,
  token_hash  VARCHAR(64) NOT NULL UNIQUE,
  used        BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_email_verify_token_hash ON auth_portal.email_verification_tokens (token_hash);

-- ── ip_allowlist ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_portal.ip_allowlist (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  institution_id UUID        NOT NULL,
  cidr           VARCHAR(50) NOT NULL,
  label          VARCHAR(100),
  created_by     UUID        NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_ip_allowlist_institution_id ON auth_portal.ip_allowlist (institution_id);

-- ── auth_audit_events ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_portal.auth_audit_events (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID        REFERENCES auth_portal.auth_users(id) ON DELETE SET NULL,
  institution_id UUID,
  event_type     VARCHAR(50) NOT NULL,
  outcome        VARCHAR(20) NOT NULL,  -- success | failed | blocked
  ip_address     VARCHAR(45),
  user_agent     TEXT,
  event_metadata JSONB,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_auth_audit_user_id        ON auth_portal.auth_audit_events (user_id);
CREATE INDEX IF NOT EXISTS ix_auth_audit_institution_id ON auth_portal.auth_audit_events (institution_id);
CREATE INDEX IF NOT EXISTS ix_auth_audit_created_at     ON auth_portal.auth_audit_events (created_at DESC);
CREATE INDEX IF NOT EXISTS ix_auth_audit_event_type     ON auth_portal.auth_audit_events (event_type);

-- ── Cleanup function (cron) ───────────────────────────────────
-- Call periodically to purge expired sessions and tokens
CREATE OR REPLACE FUNCTION auth_portal.cleanup_expired()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  DELETE FROM auth_portal.auth_sessions          WHERE expires_at < NOW();
  DELETE FROM auth_portal.password_reset_tokens  WHERE expires_at < NOW();
  DELETE FROM auth_portal.email_verification_tokens WHERE expires_at < NOW();
END;
$$;

GRANT EXECUTE ON FUNCTION auth_portal.cleanup_expired() TO service_role;

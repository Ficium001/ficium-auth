-- =============================================================================
-- 003 — ficium-auth gets its own least-privilege database role
--
-- Before: ficium-auth reached auth_portal through PostgREST with the Portal DB's
-- service_role key, which bypasses row-level security on EVERY schema (all bank
-- data, billing, audit). A leak of ficium-auth's secrets was a leak of the bank.
--
-- After: role `ficium_auth` can read and write the auth_portal tables and run
-- auth_portal.get_member_module_permissions(), and nothing else. It does not
-- bypass RLS; each table gets an explicit policy for it alone.
--
-- Apply to the Portal DB (egwobcajdlragubtkpqp). Idempotent.
-- The password is NOT in this file. Set it by hand once, then build DB_URL:
--   ALTER ROLE ficium_auth WITH LOGIN PASSWORD '<long random>';
--   DB_URL=postgresql://ficium_auth.egwobcajdlragubtkpqp:<pw>@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres
-- Then set AUTH_DB_BACKEND=postgres and DB_SSL_ROOT_CERT on ficium-auth, and
-- remove SUPABASE_SERVICE_KEY from its Railway variables.
-- =============================================================================

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ficium_auth') THEN
    CREATE ROLE ficium_auth NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS
      CONNECTION LIMIT 20;
  END IF;
END $$;

ALTER ROLE ficium_auth SET search_path = auth_portal, pg_catalog;
ALTER ROLE ficium_auth SET statement_timeout = '10s';

REVOKE ALL ON SCHEMA public FROM ficium_auth;
GRANT USAGE ON SCHEMA auth_portal TO ficium_auth;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  auth_portal.auth_users,
  auth_portal.auth_sessions,
  auth_portal.mfa_backup_codes,
  auth_portal.password_reset_tokens,
  auth_portal.email_verification_tokens
TO ficium_auth;
-- Audit is append-only for the service: it may write events, never change or delete them.
GRANT SELECT, INSERT ON auth_portal.auth_audit_events TO ficium_auth;
GRANT SELECT ON auth_portal.ip_allowlist TO ficium_auth;

REVOKE ALL ON FUNCTION auth_portal.get_member_module_permissions(text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_portal.get_member_module_permissions(text, uuid) TO ficium_auth;
-- Keep the existing callers working while ficium-auth moves over.
GRANT EXECUTE ON FUNCTION auth_portal.get_member_module_permissions(text, uuid) TO service_role;

-- RLS stays on; this role gets its own policies (it does not bypass RLS).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['auth_users','auth_sessions','mfa_backup_codes',
                           'password_reset_tokens','email_verification_tokens'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS ficium_auth_all ON auth_portal.%I', t);
    EXECUTE format('CREATE POLICY ficium_auth_all ON auth_portal.%I TO ficium_auth '
                   'USING (true) WITH CHECK (true)', t);
  END LOOP;
END $$;

DROP POLICY IF EXISTS ficium_auth_read ON auth_portal.auth_audit_events;
DROP POLICY IF EXISTS ficium_auth_append ON auth_portal.auth_audit_events;
CREATE POLICY ficium_auth_read   ON auth_portal.auth_audit_events FOR SELECT TO ficium_auth USING (true);
CREATE POLICY ficium_auth_append ON auth_portal.auth_audit_events FOR INSERT TO ficium_auth WITH CHECK (true);

DROP POLICY IF EXISTS ficium_auth_read ON auth_portal.ip_allowlist;
CREATE POLICY ficium_auth_read ON auth_portal.ip_allowlist FOR SELECT TO ficium_auth USING (true);

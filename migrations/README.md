# ficium-auth — Migrations (Institution DB)

Target database: **Supabase Institution DB** (`egwobcajdlragubtkpqp` · `ap-southeast-1`)

ficium-auth owns the `auth_portal` schema. All migrations run in the Supabase SQL editor or against any Postgres directly (no Supabase-specific dependencies in this schema).

---

## Files

| File | Purpose |
|------|---------|
| `001_auth_portal_schema.sql` | Creates the full `auth_portal` schema — all tables, indexes, grants |
| `002_session_mfa_verified.sql` | `auth_sessions.mfa_verified` — MFA proof survives refresh rotation. **Applied** 2026-10-26; must exist before the code that writes it |
| `003_drop_duplicate_indexes.sql` | Drops 4 plain indexes that duplicate a unique constraint's index (`email`, `refresh_token_hash`, two `token_hash`). Safe in any order with the code. **Applied** 2026-11-26 |

---

## What `001_auth_portal_schema.sql` creates

### Tables

| Table | Purpose |
|---|---|
| `auth_portal.auth_users` | Institution users — email, Argon2id hash, role, `institution_id`, `must_change_password`, `is_active` |
| `auth_portal.auth_sessions` | Active sessions — `session_id`, `user_id`, `institution_id`, `expires_at`, `revoked_at` |
| `auth_portal.mfa_totp_credentials` | TOTP secrets per user |
| `auth_portal.mfa_backup_codes` | TOTP backup codes (hashed) |
| `auth_portal.password_reset_tokens` | Single-use password reset tokens (hashed, 1h TTL) |
| `auth_portal.email_verification_tokens` | Email verification tokens |
| `auth_portal.auth_audit_events` | Append-only login/logout/MFA/password event log |

### Roles / grants

- `service_role` has full access to `auth_portal.*` (ficium-auth FastAPI service uses this)
- `authenticated` role has no direct access — all auth is mediated by ficium-auth, not PostgREST

### Indexes

- Unique index on `auth_users(email)`
- Index on `auth_sessions(user_id, expires_at)` for session lookup
- Index on `auth_sessions(session_id)` for token validation
- Index on `auth_audit_events(user_id, created_at DESC)` for audit queries

---

## Run order

Only one migration currently:

```bash
# In Supabase SQL editor (project: egwobcajdlragubtkpqp)
# Paste and run:
migrations/001_auth_portal_schema.sql
```

Idempotent — uses `CREATE TABLE IF NOT EXISTS` throughout.

---

## Checking schema health

```sql
-- Confirm schema exists
SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'auth_portal';

-- List tables
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'auth_portal' ORDER BY table_name;

-- Check user count
SELECT count(*) FROM auth_portal.auth_users WHERE is_active = TRUE;

-- Check recent audit events
SELECT event_type, email, created_at FROM auth_portal.auth_audit_events
ORDER BY created_at DESC LIMIT 10;
```

---

## Relationship to other schemas

`auth_portal.auth_users.institution_id` references `institution.institution.id`. The `institution` schema is defined in `ficium-portal/supabase/migrations/` and must be applied before you can insert users with a valid `institution_id`.

Apply order for a fresh setup:
1. `ficium-portal/supabase/migrations/*.sql` — institution, marketplace, governance schemas
2. `ficium-auth/migrations/001_auth_portal_schema.sql` — auth_portal schema
3. `ficium-portal-api/db/001_workflow.sql` — workflow helpers
4. `ficium-portal-api/db/003_expiry_notify.sql` — expiry dispatch
5. `ficium-portal-api/db/004_accept_bid_reveal.sql` — accept_bid financials

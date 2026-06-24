# ficium-auth — Database (`auth_portal` schema)

_Last updated: 24 June 2026_

ficium-auth owns exactly one schema, `auth_portal`, defined in
`migrations/001_auth_portal_schema.sql`. It is the identity store for the Portal
side of the platform. No business or tenant data lives here.

---

## Tables

| Table | Purpose |
|-------|---------|
| `auth_portal.auth_users` | Principals — email, Argon2id `password_hash`, status, MFA enrolment |
| `auth_portal.auth_sessions` | Active sessions (Redis is the hot store; this is the durable record) |
| `auth_portal.mfa_backup_codes` | Hashed single-use TOTP backup codes |
| `auth_portal.password_reset_tokens` | Single-use, expiring reset tokens (hashed) |
| `auth_portal.email_verification_tokens` | Single-use, expiring verification tokens (hashed) |
| `auth_portal.ip_allowlist` | Optional per-user IP allowlisting |
| `auth_portal.auth_audit_events` | Append-only auth event trail (login, lockout, MFA, reset) |

---

## Conventions

- **Passwords:** Argon2id only — never plaintext, never a reversible form. Cost
  parameters are configurable via env.
- **Tokens:** reset/verification/backup codes are stored **hashed**; the
  plaintext is shown to the user once and never persisted.
- **Audit:** `auth_audit_events` is append-only. Treat it as WORM for
  compliance review.
- **`sub` parity:** `auth_users.id` is the value placed in the JWT `sub` claim,
  and downstream it equals `institution.member.user_id`. Keeping these identical
  is what lets RLS resolve the caller across services.

---

## The identity split-brain (open item)

`auth_portal.auth_users` is one identity space; the Portal's `identity` schema
roots `profile` on Supabase `auth.users`. Two identity spaces currently coexist,
reconciled by keeping the `sub` claim identical. ADR-002 (in `ficium-portal-api`)
tracks collapsing these to a single source of truth before broad onboarding.
**Do not run both indefinitely.**

---

## Portability

For non-Supabase Postgres the schema applies unchanged (no Supabase-specific
objects are used here — the `auth.*` helper dependency lives in the Portal SQL,
not in `auth_portal`). Point `DB_URL` at the target and apply migration 001.

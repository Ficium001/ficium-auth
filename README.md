# ficium-auth

Authentication service for the Ficium Portal. Issues RS256 JWTs, manages sessions and MFA, and owns the `auth_portal` database schema.

Built with FastAPI. Deployed on Railway (`ficium-auth-production.up.railway.app`).

---

## What it does

- **Password auth** with Argon2id hashing (configurable cost parameters)
- **RS256 JWT issuance** — asymmetric signing; consumers verify with the public key, never a shared secret
- **JWKS endpoint** (`/.well-known/jwks.json`) publishing the public key for token verification
- **Sessions** with concurrent-session limits, stored in Redis
- **MFA** (TOTP) with backup codes
- **Rate limiting** and login lockout via Redis
- **Email** flows (verification, password reset) via Resend
- **Audit logging** to `auth_portal.auth_audit_events`

---

## Endpoints

| Method | Path | Purpose |
|--------|------|---------| 
| `POST` | `/auth/login` | Authenticate → RS256 access token + refresh cookie |
| `POST` | `/auth/refresh` | Exchange refresh cookie → new access token |
| `POST` | `/auth/logout` | Revoke session |
| `POST` | `/auth/password/change` | Change password (authenticated) |
| `POST` | `/auth/password/force-change` | Clear `must_change_password` flag |
| `POST` | `/auth/password/reset/request` | Send password reset email |
| `POST` | `/auth/password/reset/confirm` | Confirm reset with token |
| `POST` | `/auth/mfa/enrol` | Start TOTP setup (signed in) → secret + QR, pending 10 min |
| `POST` | `/auth/mfa/verify-enrolment` | Confirm with a code → MFA on, 10 backup codes shown once, other sessions signed out |
| `POST` | `/auth/mfa/verify` | Complete a login that returned `mfa_required` (TOTP or one backup code) |
| `POST` | `/auth/mfa/disable` | Password + current code, from an MFA session only |
| `GET`  | `/.well-known/jwks.json` | RS256 public key (JWKS format) |
| `GET`  | `/health` | Liveness — DB + Redis checks |

See `AUTH_SPEC.md` for full request/response shapes and MFA flows.

---

## Token format

RS256-signed JWTs with `kid: ficium-auth-rs256-v1`:

```json
{
  "iss": "ficium-auth",
  "aud": "authenticated",
  "role": "authenticated",
  "sub": "<user id>",
  "user_role": "institution_admin",
  "institution_id": "<uuid>",
  "email": "user@institution.mu",
  "session_id": "<uuid>",
  "deployment": "saas",
  "amr": ["pwd"] | ["pwd", "otp", "mfa"] | ["pwd", "backup", "mfa"],
  "iat": 0,
  "exp": 0,
  "jti": "…"
}
```

`amr` (RFC 8176) says how the user signed in; a relying party that needs MFA checks for `"mfa"`. It is carried through refresh (from `auth_sessions.mfa_verified`) and never added by it.

`aud: authenticated` and `role: authenticated` are deliberate — they keep tokens Supabase-compatible so `auth.uid()` resolves inside RLS policies downstream (via `request.jwt.claims` GUC set by ficium-portal-api).

---

## Local development

```bash
# 1. Install
pip install -r requirements.txt

# 2. Generate RSA keypair
python scripts/generate_rsa_keys.py
# → prints JWT_PRIVATE_KEY and JWT_PUBLIC_KEY

# 3. Configure
cp .env.example .env
# fill in: DB_URL, REDIS_URL, JWT_PRIVATE_KEY, JWT_PUBLIC_KEY, RESEND_API_KEY

# 4. Run
uvicorn src.main:app --reload --port 8000
```

### Database

The `auth_portal` schema is created by `migrations/001_auth_portal_schema.sql`. Run once in the Supabase SQL editor or against your Postgres. Idempotent.

---

## Environment variables

| Variable | Notes |
|---|---|
| `ENV` | `production` / `development` |
| `DB_URL` | Supabase transaction pooler DSN (`postgresql+asyncpg://postgres.<ref>:...@...pooler.supabase.com:6543/postgres`) |
| `REDIS_URL` | Redis connection string |
| `REDIS_PASSWORD` | Redis auth password |
| `JWT_PRIVATE_KEY` | RS256 private key (PEM). Railway stores multiline as escaped `\n` — normalised at load |
| `JWT_PUBLIC_KEY` | RS256 public key (PEM) |
| `JWT_ALGORITHM` | `RS256` |
| `JWT_ISSUER` | `ficium-auth` |
| `JWT_AUDIENCE` | `authenticated` |
| `SUPABASE_URL` | For the REST data client |
| `SUPABASE_SERVICE_KEY` | Service role key |
| `RESEND_API_KEY` | Email delivery |
| `ALLOWED_ORIGINS` | CORS — Portal and App origins |
| `ALLOWED_ORIGIN_REGEX` | Regex for Vercel preview URLs: `^https://ficium-portal[a-z0-9.\-]*\.vercel\.app$` |

> **RS256 vs HS256:** the service signs RS256 when `JWT_PRIVATE_KEY` is set and `SUPABASE_JWT_SECRET` is **absent**. Ensure `SUPABASE_JWT_SECRET` is NOT set on Railway.

---

## Deployment (Railway)

1. Deploy from GitHub; Railway builds the `Dockerfile`.
2. Attach a Redis service.
3. Set all environment variables above. Paste PEM keys as full multiline values.
4. `GET /health` → `{"status":"healthy","checks":{"database":true,"redis":true}}` ✓
5. `GET /.well-known/jwks.json` → key with `kid: ficium-auth-rs256-v1` ✓

GitHub Actions keepalive workflow pings `/health` every 5 minutes.

---

## Project layout

```
src/
  api/          auth.py, health.py, jwks.py
  core/         config.py, database.py, redis.py, security.py (Argon2id + RS256)
  middleware/   auth_middleware.py, rate limiting
  models/       SQLAlchemy models for auth_portal.*
  schemas/      Pydantic request/response
  services/     audit.py, email.py, mfa.py
  providers/    pluggable auth backends (password / SAML / LDAP)
  main.py
migrations/     001_auth_portal_schema.sql
scripts/        generate_rsa_keys.py
```

---

## WIP: `feat/rs256-jwks`

The `feat/rs256-jwks` branch contains the client-credentials grant (service JWT issuance for machine-to-machine auth). This will replace the `APP_DATABASE_URL` direct credential used by `ficium-portal-api → App DB` with a properly scoped service JWT. Not yet merged — tracked as ADR-002.

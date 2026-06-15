# ficium-auth

Authentication service for the Ficium Portal. Issues RS256 JWTs, manages sessions and MFA, and owns the `auth_portal` database schema.

Built with FastAPI. Deployed on Railway with an attached Redis service. Backed by Supabase Postgres (the `auth_portal` schema).

---

## What it does

- **Password auth** with Argon2id hashing (configurable cost parameters).
- **RS256 JWT issuance** — asymmetric signing so consumers verify with a public key, never a shared secret.
- **JWKS endpoint** (`/.well-known/jwks.json`) publishing the public key for token verification.
- **Sessions** with concurrent‑session limits, stored in Redis.
- **MFA** (TOTP) with backup codes.
- **Rate limiting** and login lockout via Redis.
- **Email** flows (verification, password reset) via Resend.
- **Audit logging** to `auth_portal.auth_audit_events`.

---

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/auth/login` | Authenticate, return RS256 access token + refresh cookie |
| `POST` | `/auth/refresh` | Exchange refresh cookie for a new access token |
| `POST` | `/auth/logout` | Revoke the session |
| `GET`  | `/.well-known/jwks.json` | Public RS256 key (JWKS format) |
| `GET`  | `/health` | Liveness — DB + Redis checks |

See `AUTH_SPEC.md` for the full request/response contract and the MFA flows.

---

## Token format

Access tokens are RS256‑signed JWTs with a `kid` header (`ficium-auth-rs256-v1`) so consumers can select the right JWKS key. Claims:

```json
{
  "iss": "ficium-auth",
  "aud": "ficium-portal",
  "role": "authenticated",
  "sub": "<user id>",
  "user_role": "institution_admin",
  "institution_id": "<uuid>",
  "email": "user@institution.mu",
  "session_id": "<uuid>",
  "deployment": "saas",
  "iat": 0, "exp": 0, "jti": "…"
}
```

`role: authenticated` is deliberate — it keeps tokens Supabase‑compatible so `auth.uid()` resolves inside RLS policies downstream.

---

## Local development

### Prerequisites

- Python 3.12
- A Redis instance (local Docker is fine)
- Access to the Supabase project with the `auth_portal` schema applied

### Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate an RSA keypair for JWT signing
python scripts/generate_rsa_keys.py
# → prints JWT_PRIVATE_KEY and JWT_PUBLIC_KEY

# 3. Copy env template and fill it in
cp .env.example .env
# set DB_URL, REDIS_URL, JWT_PRIVATE_KEY, JWT_PUBLIC_KEY, RESEND_API_KEY, etc.

# 4. Run
uvicorn src.main:app --reload --port 8000
```

### Database

The `auth_portal` schema is created by `migrations/001_auth_portal_schema.sql`. Run it once in the Supabase SQL editor (or against your Postgres). It is idempotent.

---

## Configuration (environment variables)

| Variable | Notes |
|----------|-------|
| `ENV` | `production` / `development` |
| `DB_URL` | Supabase transaction pooler DSN, `postgresql+asyncpg://…@…pooler.supabase.com:6543/postgres` |
| `REDIS_URL` | Redis connection string |
| `REDIS_PASSWORD` | Redis auth |
| `JWT_PRIVATE_KEY` | RS256 private key (PEM). Multiline — Railway stores escaped `\n`, normalised at load |
| `JWT_PUBLIC_KEY` | RS256 public key (PEM) |
| `JWT_ALGORITHM` | `RS256` |
| `JWT_ISSUER` | `ficium-auth` |
| `JWT_AUDIENCE` | `ficium-portal` |
| `SUPABASE_URL` | For the REST data client |
| `SUPABASE_SERVICE_KEY` | Service role key |
| `RESEND_API_KEY` | Email delivery |
| `ALLOWED_ORIGINS` | CORS — the Portal's origin |

> **RS256 vs HS256:** the service signs RS256 when `JWT_PRIVATE_KEY` is set and `SUPABASE_JWT_SECRET` is **absent**. If `SUPABASE_JWT_SECRET` is present it falls back to HS256 (Supabase‑native). For the portal architecture you must run RS256 — ensure `SUPABASE_JWT_SECRET` is **not** set on Railway.

---

## Deployment (Railway)

1. Deploy from the GitHub repo; Railway builds the `Dockerfile`.
2. Attach a Redis service.
3. Set all environment variables above. Paste the PEM keys as full multiline values.
4. Confirm `GET /health` returns `{"status":"healthy","checks":{"database":true,"redis":true}}`.
5. Confirm `GET /.well-known/jwks.json` returns a key with `kid: ficium-auth-rs256-v1`.

---

## Project layout

```
src/
  api/          auth.py, health.py, jwks.py        — route handlers
  core/         config.py, database.py, redis.py,  — settings + infra
                security.py                        — Argon2 + JWT
  middleware/   auth_middleware.py
  models/       auth.py                            — DB models
  schemas/      auth.py                            — Pydantic request/response
  services/     audit.py, email.py, mfa.py
  main.py                                          — app + router wiring
migrations/     001_auth_portal_schema.sql
scripts/        generate_rsa_keys.py
```

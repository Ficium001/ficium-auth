# ficium-auth — Installation

_Last updated: 27 June 2026_

---

## Prerequisites

- Python 3.12
- Redis (local Docker or Railway)
- Supabase project with `auth_portal` schema applied (institution DB: `egwobcajdlragubtkpqp`)

---

## Local development

```bash
# 1. Clone and install
git clone https://github.com/Ficium001/ficium-auth.git
cd ficium-auth
pip install -r requirements.txt

# 2. Generate RSA keypair (one-time)
python scripts/generate_rsa_keys.py
# → prints JWT_PRIVATE_KEY and JWT_PUBLIC_KEY as PEM blocks
# Save both — paste into .env and Railway

# 3. Configure
cp .env.example .env
```

Fill in `.env`:

```bash
ENV                  = development
DB_URL               = postgresql+asyncpg://postgres.<ref>:<pw>@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres
REDIS_URL            = redis://localhost:6379
REDIS_PASSWORD       =
JWT_PRIVATE_KEY      = -----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----
JWT_PUBLIC_KEY       = -----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----
JWT_ALGORITHM        = RS256
JWT_ISSUER           = ficium-auth
JWT_AUDIENCE         = authenticated
SUPABASE_URL         = https://<ref>.supabase.co
SUPABASE_SERVICE_KEY = <service role key>
RESEND_API_KEY       = re_...
ALLOWED_ORIGINS      = http://localhost:5173,http://localhost:5174
ALLOWED_ORIGIN_REGEX = ^https://ficium-portal[a-z0-9.\-]*\.vercel\.app$
AUTH_PROVIDER        = password
```

> **Do NOT set `SUPABASE_JWT_SECRET`.** Its presence forces HS256 fallback. RS256 requires it to be absent.

```bash
# 4. Start Redis (if running locally)
docker run -d -p 6379:6379 redis:7-alpine

# 5. Run
uvicorn src.main:app --reload --port 8000

# 6. Verify
curl http://localhost:8000/health
# → {"status":"healthy","checks":{"database":true,"redis":true}}

curl http://localhost:8000/.well-known/jwks.json
# → {"keys":[{"kid":"ficium-auth-rs256-v1","kty":"RSA",...}]}
```

---

## Database setup

Apply `migrations/001_auth_portal_schema.sql` to the institution Supabase project:

1. Open the Supabase SQL editor (`egwobcajdlragubtkpqp`)
2. Paste and run `migrations/001_auth_portal_schema.sql`
3. Verify: `SELECT count(*) FROM auth_portal.auth_users;` → `0` (no error = success)

The schema creates:
- `auth_portal.auth_users` — users with Argon2id password hashes
- `auth_portal.auth_sessions` — Redis-backed session records
- `auth_portal.mfa_totp_credentials`, `auth_portal.mfa_backup_codes`
- `auth_portal.password_reset_tokens`, `auth_portal.email_verification_tokens`
- `auth_portal.auth_audit_events` — append-only login/logout/MFA audit trail

For non-Supabase Postgres, the schema has no `auth.*` dependencies — run it directly.

---

## Deployment (Railway)

### 1. Create service

New Project → Deploy from GitHub → `Ficium001/ficium-auth`. Railway builds the `Dockerfile`.

Add a **Redis service** to the same Railway project.

### 2. Set environment variables

```
ENV                   = production
DB_URL                = postgresql+asyncpg://postgres.<ref>:<pw>@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres
REDIS_URL             = <from Railway Redis — usually redis://...railway.internal:6379>
REDIS_PASSWORD        = <from Railway Redis>
JWT_PRIVATE_KEY       = <full PEM — paste as multiline, Railway normalises \n>
JWT_PUBLIC_KEY        = <full PEM>
JWT_ALGORITHM         = RS256
JWT_ISSUER            = ficium-auth
JWT_AUDIENCE          = authenticated
SUPABASE_URL          = https://<ref>.supabase.co
SUPABASE_SERVICE_KEY  = <service role key>
RESEND_API_KEY        = re_...
ALLOWED_ORIGINS       = https://ficium-portal.vercel.app,https://ficium.vercel.app
ALLOWED_ORIGIN_REGEX  = ^https://ficium-portal[a-z0-9.\-]*\.vercel\.app$
AUTH_PROVIDER         = password
```

### 3. Verify deployment

```bash
curl https://ficium-auth-production.up.railway.app/health
# → {"status":"healthy","checks":{"database":true,"redis":true}}

curl https://ficium-auth-production.up.railway.app/.well-known/jwks.json
# → {"keys":[{"kid":"ficium-auth-rs256-v1","kty":"RSA","alg":"RS256",...}]}

# Test login
curl -s -X POST https://ficium-auth-production.up.railway.app/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@institution.mu","password":"<password>"}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('access_token','ERROR')[:40]+'...')"
```

---

## Environment variable reference

| Variable | Required | Notes |
|---|---|---|
| `ENV` | Yes | `production` / `development` |
| `DB_URL` | Yes | Supabase transaction pooler DSN with `postgresql+asyncpg://` scheme |
| `REDIS_URL` | Yes | Redis connection string |
| `REDIS_PASSWORD` | If auth | Redis password |
| `JWT_PRIVATE_KEY` | Yes | RS256 private key PEM. Railway escapes `\n` — normalised at startup |
| `JWT_PUBLIC_KEY` | Yes | RS256 public key PEM |
| `JWT_ALGORITHM` | Yes | `RS256` |
| `JWT_ISSUER` | Yes | `ficium-auth` |
| `JWT_AUDIENCE` | Yes | `authenticated` |
| `SUPABASE_URL` | Yes | Institution Supabase project URL |
| `SUPABASE_SERVICE_KEY` | Yes | Service role key |
| `RESEND_API_KEY` | Yes | Email delivery |
| `ALLOWED_ORIGINS` | Yes | Comma-separated exact CORS origins |
| `ALLOWED_ORIGIN_REGEX` | Recommended | Regex for Vercel preview URLs |
| `AUTH_PROVIDER` | Yes | `password` (SaaS) / `saml` / `ldap` |
| `SUPABASE_JWT_SECRET` | **Never set** | Presence forces HS256 fallback — must be absent for RS256 |

---

## Creating institution users

Users have Argon2id password hashes (not bcrypt). To create a user directly:

```sql
-- Generate hash: use argon2-cffi with time_cost=3, memory_cost=65536, parallelism=4
-- Or POST /auth/register if institution registration is enabled

INSERT INTO auth_portal.auth_users (
  id, institution_id, email, email_verified,
  password_hash, role, is_active
) VALUES (
  gen_random_uuid(),
  '<institution id from institution.institution>',
  'maker@bank.mu',
  TRUE,
  '<argon2id hash>',
  'institution_maker',
  TRUE
);
```

Valid roles: `institution_admin`, `institution_maker`, `institution_checker`, `institution_viewer`, `institution_api_operator`, `super_admin`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `health` → `{"database":false}` | DB_URL wrong or pooler unreachable | Check URL scheme is `postgresql+asyncpg://`, username is `postgres.<ref>`, port 6543 |
| `health` → `{"redis":false}` | Redis not running or wrong URL | Check `REDIS_URL` and `REDIS_PASSWORD` match Railway Redis service |
| JWKS → empty keys array | `JWT_PUBLIC_KEY` not set or malformed | Check PEM is full block; re-run `generate_rsa_keys.py` |
| Login → 500 `JWKError: Could not deserialize` | `JWT_PUBLIC_KEY` can't be parsed | Keypair mismatch — regenerate both keys together |
| Login → 401 | Wrong password or user doesn't exist | Check `auth_portal.auth_users.email` and hash type (must be Argon2id) |
| Token rejected by portal-api → "Invalid audience" | `JWT_AUDIENCE` mismatch | Must be `authenticated` on both services |
| CORS blocked on Vercel preview | Preview origin not in regex | Set `ALLOWED_ORIGIN_REGEX` |

# ficium-auth — Installation

_Last updated: 24 June 2026_

## Prerequisites
- Python 3.12
- Redis (local Docker is fine for dev)
- A Postgres with the `auth_portal` schema (Supabase for SaaS)

## Local setup
```bash
pip install -r requirements.txt

# Generate the RS256 signing keypair
python scripts/generate_rsa_keys.py     # prints JWT_PRIVATE_KEY / JWT_PUBLIC_KEY

cp .env.example .env
# set: DB_URL, REDIS_URL, JWT_PRIVATE_KEY, JWT_PUBLIC_KEY,
#      RESEND_API_KEY, AUTH_PROVIDER, Argon2id cost params

python -m src.main                       # serves the API
```

## Database
Apply `migrations/001_auth_portal_schema.sql` to the target Postgres. On
Supabase, run it in the SQL editor. For non-Supabase targets, apply it directly
(no `auth.*` helpers are required by this schema).

## Deploy (Railway)
- Builder: Dockerfile (`railway.toml`).
- Start command: `python -m src.main`.
- Healthcheck: `GET /health/live` (30s timeout, restart on failure).
- Attach a Redis service and set `REDIS_URL`.
- Set all secrets (keys, DB, Resend) as Railway environment variables.

## Configuration reference
| Variable | Purpose |
|----------|---------|
| `DB_URL` | Postgres connection (Supabase pooler in SaaS) |
| `REDIS_URL` | Redis for sessions + rate limiting |
| `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` | RS256 signing keypair |
| `RESEND_API_KEY` | Transactional email |
| `AUTH_PROVIDER` | `password` (SaaS) / `saml` / `ldap` |

# ficium-auth — Architecture

_Last updated: 24 June 2026_

The authentication service for the Ficium Portal. It is the **only** service
that can mint tokens: it holds the RS256 private key, owns the `auth_portal`
schema, and publishes its public key via JWKS so every other service can verify
tokens without sharing a secret. This document covers the service shape, the
trust model, and the deployment topology. The full request/response contract
lives in `AUTH_SPEC.md`; the schema in `DATABASE.md`.

---

## 1. Responsibilities (and non-responsibilities)

**Owns:** password verification (Argon2id), RS256 JWT issuance, the JWKS
endpoint, sessions (Redis-backed, with concurrent-session limits), MFA (TOTP +
backup codes), rate limiting / login lockout, email flows (verification, reset)
via Resend, and the `auth_portal.auth_audit_events` trail.

**Does not own:** any business or tenant data. ficium-auth never reads
`institution.*` or `marketplace.*`. It authenticates a principal and describes
them in a token; authorisation against tenant data is enforced downstream by
RLS in `ficium-portal-api`.

---

## 2. The trust model (RS256 + JWKS)

Asymmetric signing is the load-bearing decision:

- ficium-auth holds the **private key** and signs tokens with `kid`
  `ficium-auth-rs256-v1`.
- Every consumer verifies with the **public key**, fetched once from
  `/.well-known/jwks.json` and cached. No shared secret ever leaves this service.
- Adding a new token consumer is zero-secret-distribution: it just reads the
  public JWKS.

Tokens carry `role: authenticated` deliberately, so they remain
Supabase-compatible and `auth.uid()` resolves inside downstream RLS policies.

---

## 3. Internal structure

```
src/
  api/         auth.py (login/refresh/logout), jwks.py, health.py
  core/        config.py, database.py, redis.py, security.py (Argon2id, RS256)
  services/    mfa.py (TOTP + backup codes), email.py (Resend), audit.py
  models/      SQLAlchemy models for auth_portal.*
  schemas/     Pydantic request/response contracts
  middleware/  rate limiting, request context
  providers/   pluggable auth backends (password / SAML / LDAP per deployment)
```

The `providers/` seam is what lets the same service run password auth in SaaS,
SAML in a bank's cloud, or LDAP on-prem — selected by `AUTH_PROVIDER`.

---

## 4. Deployment topology

```
                         ┌────────────────────────────┐
                         │   ficium-portal (Vercel)    │
                         │   POST /auth/login          │
                         └─────────────┬──────────────┘
                                       │  credentials → RS256 JWT
                                       ▼
        JWKS (public key)   ┌────────────────────────────┐
   ┌───────────────────────►│        ficium-auth         │
   │  GET /.well-known/     │     (FastAPI · Railway)     │
   │      jwks.json         │                            │
   │                        │  Argon2id · RS256 · MFA     │
┌──┴───────────────────┐    │  sessions · rate limit      │
│  ficium-portal-api    │   └───────┬──────────────┬─────┘
│  (verifies tokens)    │           │              │
└───────────────────────┘           ▼              ▼
                          ┌───────────────┐  ┌──────────────┐
                          │  Redis        │  │  Supabase PG │
                          │ (Railway,     │  │ auth_portal  │
                          │  sessions +   │  │   schema     │
                          │  rate limit)  │  │              │
                          └───────────────┘  └──────────────┘

  Health: GET /health/live (Railway healthcheck, 30s timeout)
  Start:  python -m src.main   (Dockerfile builder)
```

| Component | Platform | Notes |
|-----------|----------|-------|
| ficium-auth | Railway (Dockerfile) | `startCommand = python -m src.main` |
| Redis | Railway (private) | sessions, rate-limit counters, lockout |
| Postgres (`auth_portal`) | Supabase | accessed for users/sessions/tokens/audit |

---

## 5. Portability

The `providers/` abstraction plus environment-driven config (`AUTH_PROVIDER`,
`DB_URL`, `REDIS_URL`, key material) means the service ships into all three
deployment models without code change. The only hard requirements are a Postgres
with the `auth_portal` schema and a Redis instance.

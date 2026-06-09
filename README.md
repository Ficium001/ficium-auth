# ficium-auth

In-house authentication service for the Ficium institution portal.
FastAPI + Python, bank-grade security, zero Supabase Auth dependency.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /auth/register | Institution sign up |
| POST | /auth/login | Sign in (email/password) |
| POST | /auth/logout | Sign out + revoke session |
| POST | /auth/refresh | Rotate access token |
| POST | /auth/mfa/enrol | Begin TOTP enrolment |
| POST | /auth/mfa/verify-enrolment | Confirm TOTP enrolment |
| POST | /auth/mfa/verify | Verify TOTP during login |
| POST | /auth/mfa/disable | Disable MFA |
| POST | /auth/password/forgot | Request reset link |
| POST | /auth/password/reset | Reset via token |
| POST | /auth/password/change | Change (authenticated) |
| POST | /auth/email/verify | Verify email |
| POST | /auth/email/resend-verification | Resend verification |
| GET  | /auth/sessions | List active sessions |
| DELETE | /auth/sessions/:id | Revoke session |
| DELETE | /auth/sessions | Revoke all other sessions |
| GET  | /auth/me | Current user info |
| GET  | /health | Health + dependency checks |

## Security

- **Passwords**: Argon2id (64MB memory, 3 iterations, 4 threads)
- **JWT**: RS256 asymmetric — private key signs, public key shared with Supabase RLS
- **Refresh tokens**: httpOnly Secure SameSite=Strict cookie, rotated on every use
- **Sessions**: server-side revocable, max 3 concurrent per user
- **Rate limiting**: 5 login attempts/min per IP, 15-min lockout
- **MFA**: TOTP (RFC 6238) + 10 backup codes
- **Tokens**: always stored hashed (SHA-256), never plaintext
- **No user enumeration**: forgot password + register return identical responses
- **Audit**: every event logged append-only

## Dev setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Generate RSA keys
python scripts/generate_rsa_keys.py >> .env

cp .env.example .env
# Fill in DB_URL, REDIS_URL, SUPABASE credentials

uvicorn src.main:app --reload --port 8000
```

## Deploy

Docker (part of ficium-infra docker-compose):
```bash
docker build -t ficium-auth .
```

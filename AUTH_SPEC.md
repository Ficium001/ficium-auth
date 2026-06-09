# ficium-auth — Complete Auth Surface

## Endpoints

### Registration
POST /auth/register
  - Institution sign up
  - Creates auth record + institution row + member link
  - Sends verification email
  - Returns: { user_id, needs_email_verification }

### Authentication  
POST /auth/login
  - Email + password
  - Returns: { access_token, expires_in, mfa_required }
  - If MFA enrolled → returns mfa_token (short-lived), requires /auth/mfa/verify
  - Logs: IP, user_agent, success/failure, timestamp

POST /auth/logout
  - Revokes current session
  - Clears refresh token cookie

POST /auth/refresh
  - Rotates access token using httpOnly refresh cookie
  - Returns: { access_token, expires_in }

### MFA (TOTP)
POST /auth/mfa/enrol
  - Returns: { secret, qr_code_uri, backup_codes }
  - Not active until verified

POST /auth/mfa/verify-enrolment
  - Confirms TOTP code to activate MFA
  - Saves backup codes (hashed)

POST /auth/mfa/verify
  - Verifies TOTP or backup code during login
  - Returns: { access_token, expires_in }

POST /auth/mfa/disable
  - Requires current password + TOTP
  - Admin action only

### Password management
POST /auth/password/forgot
  - Sends reset link via email
  - Always returns 200 (no user enumeration)
  - Token valid 1 hour, single use

POST /auth/password/reset
  - Validates reset token
  - Updates password (Argon2)
  - Invalidates all existing sessions
  - Logs: timestamp, IP

POST /auth/password/change
  - Requires current password
  - Requires MFA if enrolled
  - Invalidates all other sessions
  - Logs: timestamp, IP

### Email verification
POST /auth/email/verify
  - Validates email verification token
  - Marks email as verified

POST /auth/email/resend-verification
  - Resends verification email

### Session management
GET  /auth/sessions
  - Lists all active sessions for current user
  - Shows: device, IP, location, last active

DELETE /auth/sessions/:session_id
  - Revokes a specific session

DELETE /auth/sessions
  - Revokes all sessions except current (security logout)

### User info
GET /auth/me
  - Returns current user profile + role + institution
  - Used by portal AuthContext on load

### IP allowlisting (institution admin)
GET  /auth/ip-allowlist
POST /auth/ip-allowlist
DELETE /auth/ip-allowlist/:id

### Enterprise SSO (Phase 2)
GET  /auth/saml/metadata
POST /auth/saml/acs          (assertion consumer service)
GET  /auth/saml/slo          (single logout)
POST /auth/ldap/test
POST /auth/ldap/sync-roles

### Health
GET /health
GET /health/ready
GET /health/live

## Security behaviours

- Argon2id password hashing (memory: 64MB, iterations: 3, parallelism: 4)
- JWT access token: 15 min, RS256 (asymmetric — public key shared with Supabase for RLS)
- Refresh token: httpOnly Secure SameSite=Strict cookie, 8 hours
- Refresh token rotation: new token issued on every refresh, old invalidated
- Brute force: 5 failed attempts → 15 min lockout, alert sent to institution admin
- Session limit: max 3 concurrent sessions per user (configurable per institution)
- Suspicious login: new IP or device → email alert
- Password requirements: min 12 chars, uppercase, lowercase, number, symbol
- Reset tokens: single use, 1 hour TTL, stored hashed
- All tokens stored hashed in DB (SHA-256)
- Every auth event logged to audit table
- No user enumeration on forgot password or login

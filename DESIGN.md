# ficium-auth — Design Document

_Last updated: 24 June 2026_

Why the auth service is shaped the way it is. The contract is in `AUTH_SPEC.md`;
this is the rationale.

---

## 1. Self-owned auth, not Supabase Auth

The platform moved off Supabase Auth onto a self-owned service so that token
issuance, session policy, MFA, and lockout are **under platform control** and
portable across SaaS / client-cloud / on-prem. The cost is operating a service;
the benefit is no lock-in on the single most security-sensitive component.

## 2. Asymmetric tokens (RS256), not shared secrets (HS256)

So that any number of verifiers can validate tokens with a public key while only
this service can mint them. New consumers need no secret provisioning. See
`ARCHITECTURE.md` §2.

## 3. Argon2id for passwords

Memory-hard hashing with tunable cost. Migrated bcrypt users are re-hashed to
Argon2id on next successful login (**open item:** complete the backfill for
dormant accounts).

## 4. Redis for session + rate-limit state

Sessions, concurrent-session limits, and login-lockout counters are hot-path and
ephemeral — Redis fits. The durable session record lives in Postgres; Redis is
the fast layer, not the source of truth.

## 5. Pluggable providers

`src/providers/` abstracts the credential backend (password / SAML / LDAP) so a
bank deployment can authenticate against its own IdP without forking the service.
Selected by `AUTH_PROVIDER`.

## 6. Supabase-compatible claims

Tokens deliberately mirror what Supabase Auth would issue (`role: authenticated`,
matching `sub`) so the entire downstream RLS layer works unchanged. This is the
single design constraint that made the auth migration non-breaking.

## Open items
- Complete the bcrypt → Argon2id backfill for dormant accounts.
- Resolve the identity split-brain with the Portal's `identity` schema (ADR-002).

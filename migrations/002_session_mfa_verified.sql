-- 002_session_mfa_verified.sql — APPLIED to the Portal DB (egwobcajdlragubtkpqp) on 2026-10-26.
-- Records whether a session was opened with a second factor, so the MFA proof (`amr`)
-- survives refresh-token rotation and is never invented by it. Additive, default false:
-- safe to apply before the code that writes it.
ALTER TABLE auth_portal.auth_sessions
  ADD COLUMN IF NOT EXISTS mfa_verified boolean NOT NULL DEFAULT false;
NOTIFY pgrst, 'reload schema';

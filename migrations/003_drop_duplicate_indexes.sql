-- 003 — drop 4 indexes that duplicate a unique constraint's own index.
--
-- Each column below has UNIQUE (which already creates an index) and also a plain
-- index on the same column, so every write maintained two identical indexes.
-- The unique ones stay; the models no longer declare the plain ones.
-- From the Ficium database audit, 2026-11-26. Idempotent.

drop index if exists auth_portal.ix_auth_users_email;                  -- = uq_auth_users_email
drop index if exists auth_portal.ix_auth_sessions_refresh_token_hash;  -- = auth_sessions_refresh_token_hash_key
drop index if exists auth_portal.ix_pwd_reset_token_hash;              -- = password_reset_tokens_token_hash_key
drop index if exists auth_portal.ix_email_verify_token_hash;           -- = email_verification_tokens_token_hash_key

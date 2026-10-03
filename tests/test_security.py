# =============================================================
# ficium-auth — security core tests
#
# Covers the pure security-critical functions: password hashing,
# password policy, RS256 JWT issue/verify round trip, tamper
# rejection, and token utilities. No DB/Redis required.
# =============================================================

import time

import pytest
from jose import jwt

from src.core import security
from src.core.security import (
    hash_password, verify_password, validate_password_policy, PasswordPolicyError,
    issue_access_token, verify_access_token, get_token_from_header,
    generate_secure_token, hash_token, verify_token_hash,
    generate_refresh_token, generate_backup_codes, constant_time_compare,
    _use_rs256, _jwt_algorithm,
)


# ── Password hashing (Argon2id) ───────────────────────────────
class TestPasswordHashing:
    def test_hash_is_argon2id(self):
        h = hash_password("Sup3rSecret!")
        assert h.startswith("$argon2id$")

    def test_hash_is_salted_unique(self):
        # Same password → different hashes (random salt)
        assert hash_password("samePass1!") != hash_password("samePass1!")

    def test_verify_correct_password(self):
        h = hash_password("Correct#123")
        assert verify_password("Correct#123", h) is True

    def test_verify_wrong_password(self):
        h = hash_password("Correct#123")
        assert verify_password("Wrong#123", h) is False

    def test_verify_malformed_hash_returns_false_not_raise(self):
        # Must never raise — login flow relies on a clean False
        assert verify_password("anything", "not-a-valid-hash") is False

    def test_verify_empty_hash_returns_false(self):
        assert verify_password("anything", "") is False


# ── Password policy ───────────────────────────────────────────
class TestPasswordPolicy:
    def test_too_short_rejected(self):
        with pytest.raises(PasswordPolicyError):
            validate_password_policy("Ab1!")

    def test_strong_password_accepted(self):
        # Should not raise
        validate_password_policy("Str0ng&Password")

    def test_missing_uppercase_rejected_if_required(self):
        if security.settings.password_require_upper:
            with pytest.raises(PasswordPolicyError):
                validate_password_policy("lowercase1!longenough")

    def test_missing_digit_rejected_if_required(self):
        if security.settings.password_require_digit:
            with pytest.raises(PasswordPolicyError):
                validate_password_policy("NoDigitsHere!!long")


# ── RS256 JWT round trip ──────────────────────────────────────
class TestJWT:
    def test_rs256_mode_active_in_tests(self):
        # conftest sets a private key and empty supabase secret
        assert _use_rs256() is True
        assert _jwt_algorithm() == "RS256"

    def test_issue_and_verify_round_trip(self):
        token, exp = issue_access_token(
            user_id="user-1", institution_id="inst-1",
            role="admin", session_id="sess-1",
        )
        claims = verify_access_token(token)
        assert claims["sub"] == "user-1"
        assert claims["institution_id"] == "inst-1"
        assert claims["user_role"] == "admin"
        assert claims["session_id"] == "sess-1"
        assert exp > int(time.time())

    def test_token_header_has_kid(self):
        token, _ = issue_access_token("u", "i", "admin", "s")
        header = jwt.get_unverified_header(token)
        assert header["kid"] == security.RS256_KID
        assert header["alg"] == "RS256"

    def test_tampered_token_rejected(self):
        token, _ = issue_access_token("u", "i", "admin", "s")
        # Flip a char in the signature segment
        head, payload, sig = token.split(".")
        tampered = f"{head}.{payload}.{sig[:-3]}xxx"
        with pytest.raises(Exception):
            verify_access_token(tampered)

    def test_extra_claims_included(self):
        token, _ = issue_access_token(
            "u", "i", "admin", "s",
            extra_claims={"module_permissions": {"audit": ["read"]}},
        )
        claims = verify_access_token(token)
        assert claims["module_permissions"] == {"audit": ["read"]}

    def test_expired_token_rejected(self):
        # Issue with a past exp by monkeypatching ttl to negative
        orig = security.settings.jwt_access_ttl
        try:
            security.settings.jwt_access_ttl = -10
            token, _ = issue_access_token("u", "i", "admin", "s")
            with pytest.raises(Exception):
                verify_access_token(token)
        finally:
            security.settings.jwt_access_ttl = orig


# ── Token utilities ───────────────────────────────────────────
class TestTokenUtils:
    def test_get_token_from_header_valid(self):
        assert get_token_from_header("Bearer abc123") == "abc123"

    def test_get_token_from_header_case_insensitive(self):
        assert get_token_from_header("bearer abc123") == "abc123"

    def test_get_token_from_header_none(self):
        assert get_token_from_header(None) is None

    def test_get_token_from_header_malformed(self):
        assert get_token_from_header("abc123") is None
        assert get_token_from_header("Bearer") is None
        assert get_token_from_header("Basic abc def") is None

    def test_hash_token_deterministic(self):
        assert hash_token("mytoken") == hash_token("mytoken")

    def test_hash_token_different_inputs(self):
        assert hash_token("a") != hash_token("b")

    def test_verify_token_hash_correct(self):
        raw, h = generate_refresh_token()
        assert verify_token_hash(raw, h) is True

    def test_verify_token_hash_wrong(self):
        _, h = generate_refresh_token()
        assert verify_token_hash("wrong-token", h) is False

    def test_generate_secure_token_urlsafe_unique(self):
        a, b = generate_secure_token(), generate_secure_token()
        assert a != b
        assert len(a) > 20

    def test_backup_codes_count_and_hashing(self):
        codes, hashes = generate_backup_codes(10)
        assert len(codes) == 10
        assert len(hashes) == 10
        # Each hash verifies against its code
        for c, h in zip(codes, hashes):
            assert verify_token_hash(c, h) is True

    def test_constant_time_compare(self):
        assert constant_time_compare("abc", "abc") is True
        assert constant_time_compare("abc", "abd") is False

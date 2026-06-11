# =============================================================
# ficium-auth — Configuration
# All settings from environment variables, validated at startup
# Fail fast — missing required config crashes immediately
# =============================================================

from pydantic_settings import BaseSettings
from pydantic import Field, computed_field, field_validator
from typing import Literal
import secrets


class Settings(BaseSettings):
    # ── Deployment ────────────────────────────────────────────
    env:               Literal["development", "staging", "production"] = "production"
    deployment_model:  Literal["saas", "paas", "on_prem"] = "saas"
    service_name:      str = "ficium-auth"
    version:           str = "1.0.1"

    # ── Server ────────────────────────────────────────────────
    host:   str = "0.0.0.0"
    port:   int = 8000
    workers: int = 2

    # ── Database ──────────────────────────────────────────────
    db_url:      str = Field(..., description="PostgreSQL async DSN")
    db_pool_min: int = 5
    db_pool_max: int = 20

    # ── Redis ─────────────────────────────────────────────────
    redis_url:      str = Field(..., description="Redis DSN")
    redis_password: str = Field(..., description="Redis password")

    # ── JWT (RS256 — asymmetric) ──────────────────────────────
    # Private key signs tokens; public key shared with Supabase for RLS
    jwt_private_key:  str = Field(..., description="RSA private key PEM")
    jwt_public_key:   str = Field(..., description="RSA public key PEM")

    @field_validator("jwt_private_key", "jwt_public_key", mode="before")
    @classmethod
    def normalise_pem(cls, v: str) -> str:
        """Replace escaped \\n with real newlines — Railway env var workaround."""
        if isinstance(v, str):
            return v.replace("\\n", "\n")
        return v
    jwt_algorithm:    str = "RS256"
    jwt_access_ttl:   int = 900        # 15 minutes
    jwt_refresh_ttl:  int = 28800      # 8 hours (bank working day)
    jwt_issuer:       str = "ficium-auth"
    jwt_audience:     str = "ficium-portal"

    # ── Password policy ───────────────────────────────────────
    password_min_length:    int  = 12
    password_require_upper: bool = True
    password_require_lower: bool = True
    password_require_digit: bool = True
    password_require_symbol: bool = True

    # Argon2id parameters (OWASP recommended)
    argon2_time_cost:    int = 3
    argon2_memory_cost:  int = 65536   # 64 MB
    argon2_parallelism:  int = 4
    argon2_hash_length:  int = 32

    # ── Session security ──────────────────────────────────────
    session_max_concurrent:    int = 3       # max sessions per user
    session_cookie_name:       str = "ficium_rt"
    session_cookie_secure:     bool = True
    session_cookie_samesite:   str = "strict"
    session_cookie_httponly:   bool = True
    session_cookie_domain:     str = "portal.ficium.net"

    # ── Rate limiting ─────────────────────────────────────────
    rate_limit_login:          int = 5       # attempts per minute per IP
    rate_limit_login_window:   int = 60      # seconds
    lockout_threshold:         int = 5       # failed attempts before lockout
    lockout_duration:          int = 900     # 15 min lockout

    # ── MFA ───────────────────────────────────────────────────
    mfa_issuer:           str  = "Ficium Portal"
    mfa_backup_codes:     int  = 10
    mfa_totp_window:      int  = 1           # ±1 time step tolerance
    mfa_required:         bool = False       # set True to enforce for all

    # ── Email ─────────────────────────────────────────────────
    smtp_provider:    str = "resend"
    resend_api_key:   str = Field(..., description="Resend API key")
    email_from:       str = "portal@ficium.net"
    email_from_name:  str = "Ficium Portal"

    # ── Tokens ────────────────────────────────────────────────
    email_verify_ttl:       int = 86400      # 24 hours
    password_reset_ttl:     int = 3600       # 1 hour
    mfa_challenge_ttl:      int = 300        # 5 min

    # ── Supabase (SaaS mode) ──────────────────────────────────
    supabase_url:         str = ""
    supabase_service_key: str = ""

    # ── SAML (PaaS — Phase 2) ─────────────────────────────────
    auth_provider:        str = "email"      # email | saml | ldap
    saml_metadata_url:    str = ""
    saml_entity_id:       str = ""
    saml_acs_url:         str = ""

    # ── CORS ──────────────────────────────────────────────────
    allowed_origins: str = ""   # comma-separated, e.g. https://portal.ficium.net,https://ficium-portal.vercel.app
    ldap_url:             str = ""
    ldap_base_dn:         str = ""
    ldap_bind_dn:         str = ""
    ldap_bind_password:   str = ""
    ldap_user_filter:     str = "(sAMAccountName={username})"

    # ── Observability ─────────────────────────────────────────
    log_level:        str  = "INFO"
    log_format:       str  = "json"         # json | text
    metrics_enabled:  bool = True

    @computed_field
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @computed_field
    @property
    def is_development(self) -> bool:
        return self.env == "development"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


# Singleton — loaded once at startup
settings = Settings()

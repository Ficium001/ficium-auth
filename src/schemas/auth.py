# =============================================================
# ficium-auth — Pydantic schemas (request/response)
# =============================================================

import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
import re


# ── Registration ──────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email:            EmailStr
    password:         str       = Field(..., min_length=12, max_length=128)
    first_name:       str       = Field(..., min_length=1, max_length=60)
    last_name:        str       = Field(..., min_length=1, max_length=60)
    institution_name: str       = Field(..., min_length=2, max_length=150)
    institution_type: str       = Field(..., pattern="^(bank|fintech|micro_credit|insurance|investment_firm|other)$")
    reg_number:       Optional[str] = Field(None, max_length=40)
    regulatory_body:  Optional[str] = Field(None, max_length=100)
    phone:            Optional[str] = Field(None, max_length=20)
    country:          str       = Field(..., min_length=2, max_length=3)
    website:          Optional[str] = Field(None, max_length=255)

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()


class RegisterResponse(BaseModel):
    user_id:                  str
    needs_email_verification: bool
    message:                  str


# ── Login ─────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username:    str  = Field(..., min_length=1, max_length=60)
    password:    str  = Field(..., min_length=1, max_length=128)
    remember_me: bool = False

    @field_validator("username")
    @classmethod
    def normalise_username(cls, v: str) -> str:
        return v.strip().lower()


class LoginResponse(BaseModel):
    access_token:         Optional[str] = None
    token_type:           str           = "bearer"
    expires_in:           Optional[int] = None
    mfa_required:         bool          = False
    mfa_token:            Optional[str] = None   # short-lived, for /auth/mfa/verify
    must_change_password: bool          = False   # true after admin password reset


# ── MFA ───────────────────────────────────────────────────────
class MFAEnrolResponse(BaseModel):
    secret:       str
    qr_code_uri:  str
    backup_codes: list[str]
    message:      str = "Save these backup codes securely. They will not be shown again."


class MFAVerifyEnrolRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6, pattern="^[0-9]{6}$")


class MFAVerifyRequest(BaseModel):
    mfa_token: str
    totp_code: Optional[str] = Field(None, min_length=6, max_length=6)
    backup_code: Optional[str] = Field(None)


class MFAVerifyResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int


class MFADisableRequest(BaseModel):
    password:  str
    totp_code: str = Field(..., min_length=6, max_length=6)


# ── Password management ───────────────────────────────────────
class ForgotPasswordRequest(BaseModel):
    # Accept either username or email — portal sends username since that's how users log in
    username: Optional[str] = Field(None, min_length=1, max_length=60)
    email:    Optional[str] = None

    @field_validator("username")
    @classmethod
    def normalise_username(cls, v: str | None) -> str | None:
        return v.strip().lower() if v else None

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str | None) -> str | None:
        return v.strip().lower() if v else None


class ForgotPasswordResponse(BaseModel):
    message: str


class ResetPasswordRequest(BaseModel):
    token:        str
    new_password: str = Field(..., min_length=12, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password:     str = Field(..., min_length=12, max_length=128)


class PasswordActionResponse(BaseModel):
    message: str


# ── Email verification ────────────────────────────────────────
class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()


# ── Sessions ──────────────────────────────────────────────────
class SessionInfo(BaseModel):
    id:           str
    ip_address:   Optional[str] = None
    user_agent:   Optional[str] = None
    created_at:   str
    last_used_at: Optional[str] = None
    is_current:   bool = False


class SessionListResponse(BaseModel):
    sessions: list[SessionInfo]


# ── Me ────────────────────────────────────────────────────────
class MeResponse(BaseModel):
    user_id:        str
    email:          str
    role:           str
    institution_id: str
    email_verified: bool
    mfa_enabled:    bool = False


# ── Health ────────────────────────────────────────────────────
class HealthResponse(BaseModel):
    status:  str
    version: str
    checks:  dict

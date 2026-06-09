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
    email:      EmailStr
    password:   str     = Field(..., min_length=1, max_length=128)
    remember_me: bool   = False

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()


class LoginResponse(BaseModel):
    access_token:  Optional[str] = None
    token_type:    str           = "bearer"
    expires_in:    Optional[int] = None
    mfa_required:  bool          = False
    mfa_token:     Optional[str] = None   # short-lived, for /auth/mfa/verify


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
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()


class ForgotPasswordResponse(BaseModel):
    message: str = "If an account exists for that email, a reset link has been sent."


class ResetPasswordRequest(BaseModel):
    token:           str
    new_password:    str = Field(..., min_length=12, max_length=128)
    confirm_password: str

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match.")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str = Field(..., min_length=12, max_length=128)
    confirm_password: str
    totp_code:        Optional[str] = None   # required if MFA enrolled

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match.")
        return v


class PasswordActionResponse(BaseModel):
    message: str


# ── Email verification ────────────────────────────────────────
class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


# ── Sessions ──────────────────────────────────────────────────
class SessionInfo(BaseModel):
    session_id:    str
    ip_address:    Optional[str]
    user_agent:    Optional[str]
    created_at:    datetime
    last_used_at:  datetime
    expires_at:    datetime
    is_current:    bool = False


class SessionListResponse(BaseModel):
    sessions: list[SessionInfo]
    total:    int


# ── Current user ──────────────────────────────────────────────
class MeResponse(BaseModel):
    user_id:        str
    email:          str
    email_verified: bool
    role:           str
    institution_id: str
    mfa_enabled:    bool
    last_login_at:  Optional[datetime]
    last_login_ip:  Optional[str]


# ── IP allowlist ──────────────────────────────────────────────
class IPAllowlistEntry(BaseModel):
    id:    str
    cidr:  str
    label: Optional[str]
    created_at: datetime


class AddIPRequest(BaseModel):
    cidr:  str = Field(..., pattern=r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
    label: Optional[str] = Field(None, max_length=100)


# ── Health ────────────────────────────────────────────────────
class HealthResponse(BaseModel):
    status:   str
    version:  str
    checks:   dict[str, bool]


# ── Error ─────────────────────────────────────────────────────
class ErrorResponse(BaseModel):
    error:   str
    message: str
    code:    Optional[str] = None

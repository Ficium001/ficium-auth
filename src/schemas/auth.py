# =============================================================
# ficium-auth — Pydantic schemas (request/response)
# =============================================================


from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Registration ──────────────────────────────────────────────
class LoginRequest(BaseModel):
    username:    str  = Field(..., min_length=1, max_length=60)
    password:    str  = Field(..., min_length=1, max_length=128)
    remember_me: bool = False

    @field_validator("username")
    @classmethod
    def normalise_username(cls, v: str) -> str:
        return v.strip().lower()


class LoginResponse(BaseModel):
    access_token:         str | None = None
    token_type:           str           = "bearer"
    expires_in:           int | None = None
    mfa_required:         bool          = False
    mfa_token:            str | None = None   # short-lived, for /auth/mfa/verify
    must_change_password: bool          = False   # true after admin password reset


# ── MFA ───────────────────────────────────────────────────────
class MFAEnrolResponse(BaseModel):
    secret:       str            # for manual entry if the QR code can't be scanned
    qr_code_uri:  str            # otpauth:// URI
    qr_code_svg:  str            # base64 SVG of the same URI
    expires_in:   int            # seconds left to confirm with a code


class MFAEnrolConfirmResponse(BaseModel):
    backup_codes: list[str]
    message:      str = "Save these backup codes securely. They will not be shown again. Sign in again to use MFA."


class MFAVerifyEnrolRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6, pattern="^[0-9]{6}$")


class MFAVerifyRequest(BaseModel):
    mfa_token:   str           = Field(..., min_length=10, max_length=128)
    totp_code:   str | None = Field(None, min_length=6, max_length=6, pattern="^[0-9]{6}$")
    backup_code: str | None = Field(None, min_length=8, max_length=20)


class MFAVerifyResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int


class MFADisableRequest(BaseModel):
    password:  str = Field(..., min_length=1, max_length=128)
    totp_code: str = Field(..., min_length=6, max_length=6, pattern="^[0-9]{6}$")


# ── Password management ───────────────────────────────────────
class ForgotPasswordRequest(BaseModel):
    # Accept either username or email — portal sends username since that's how users log in
    username: str | None = Field(None, min_length=1, max_length=60)
    email:    str | None = None

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
    ip_address:   str | None = None
    user_agent:   str | None = None
    created_at:   str
    last_used_at: str | None = None
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


class ForceChangePasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=12, max_length=128)

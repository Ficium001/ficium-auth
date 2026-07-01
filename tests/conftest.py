# =============================================================
# ficium-auth — test bootstrap
#
# security.py / config.py read settings at import time, so we must
# populate the environment with a REAL RSA keypair and the other
# required settings BEFORE any app module is imported. Generating a
# throwaway 2048-bit keypair per test session keeps the RS256
# round-trip tests fully self-contained (no fixture key files, no
# secrets in the repo).
# =============================================================

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _gen_keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


_priv, _pub = _gen_keypair()

# Required settings — set before app import. RS256 mode is selected by
# providing a private key AND leaving SUPABASE_JWT_SECRET empty.
os.environ.setdefault("JWT_PRIVATE_KEY", _priv)
os.environ.setdefault("JWT_PUBLIC_KEY", _pub)
os.environ.setdefault("SUPABASE_JWT_SECRET", "")  # force RS256 path
os.environ.setdefault("RESEND_API_KEY", "test_key")
os.environ.setdefault("DB_URL", "postgresql+asyncpg://u:p@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("REDIS_PASSWORD", "")
os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test_service_key")

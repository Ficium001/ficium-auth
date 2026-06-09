#!/usr/bin/env python3
"""
Generate RSA key pair for JWT RS256 signing.
Run once: python scripts/generate_rsa_keys.py
Add output to .env as JWT_PRIVATE_KEY and JWT_PUBLIC_KEY.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)

private_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()

public_pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

print("# Add these to your .env file")
print(f'JWT_PRIVATE_KEY="{private_pem}"')
print(f'JWT_PUBLIC_KEY="{public_pem}"')
print()
print("# Add the public key to Supabase:")
print("# Settings → Auth → JWT Settings → JWT Secret → paste public key")

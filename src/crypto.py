"""Fernet encryption for secrets stored in the policy database.

Used for MFA TOTP secrets and OAuth KV values. Requires
MCP_ENCRYPTION_KEY environment variable (Fernet key).

Generate a key with:
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import os
import sys

from cryptography.fernet import Fernet, InvalidToken

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = os.environ.get("MCP_ENCRYPTION_KEY", "").strip()
        if not key:
            raise RuntimeError(
                "MCP_ENCRYPTION_KEY is not set. "
                "Generate one with: python3 -c "
                '"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )
        _fernet = Fernet(key.encode())
    return _fernet


def validate_encryption_key() -> None:
    """Validate that MCP_ENCRYPTION_KEY is set and is a valid Fernet key.

    Call at startup to fail fast on misconfiguration.
    """
    key = os.environ.get("MCP_ENCRYPTION_KEY", "").strip()
    if not key:
        print(
            "ERROR: MCP_ENCRYPTION_KEY is not set. "
            "Generate one with: python3 -c "
            '"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"',
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        Fernet(key.encode())
    except (ValueError, Exception) as e:
        print(f"ERROR: MCP_ENCRYPTION_KEY is not a valid Fernet key: {e}", file=sys.stderr)
        sys.exit(1)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a string secret. Returns base64-encoded ciphertext."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted string. Raises ValueError on failure."""
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as e:
        raise ValueError("Decryption failed (invalid key or corrupted data)") from e

"""Cryptographically secure password generation for admin-provisioned credentials."""

import secrets
import string

_MIN_LENGTH = 12
_MAX_LENGTH = 64
_DEFAULT_LENGTH = 16

_UPPER = string.ascii_uppercase
_LOWER = string.ascii_lowercase
_DIGITS = string.digits
_SPECIAL = "!@#$%^&*()-_=+[]{}:,.?"

_ALL_CHARS = _UPPER + _LOWER + _DIGITS + _SPECIAL


def generate_hardened_password(length: int = _DEFAULT_LENGTH) -> str:
    """Return a policy-compliant random password.

    Guarantees at least one uppercase, lowercase, digit, and special character.
    Length must be between 12 and 64 (bcrypt-safe upper bound).
    """
    if length < _MIN_LENGTH or length > _MAX_LENGTH:
        raise ValueError(f"length must be between {_MIN_LENGTH} and {_MAX_LENGTH}")

    required = [
        secrets.choice(_UPPER),
        secrets.choice(_LOWER),
        secrets.choice(_DIGITS),
        secrets.choice(_SPECIAL),
    ]
    remaining = [secrets.choice(_ALL_CHARS) for _ in range(length - len(required))]
    chars = required + remaining
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

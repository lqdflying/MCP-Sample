"""TOTP and backup-code helpers for Admin UI 2FA (no route logic)."""

import base64
import hashlib
import io
import re
import secrets

import pyotp
import segno

MFA_ISSUER = "MCP Admin"
BACKUP_CODE_COUNT = 10
# 128-bit codes: eight groups of 4 hex chars (32 hex chars from token_hex(16))
BACKUP_CODE_HEX_BYTES = 16
BACKUP_CODE_PATTERN = re.compile(r"^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){7}$")
# 64-bit format from an earlier release (token_hex(8)); still accepted for verify/hash
_LEGACY_64BIT_BACKUP_CODE_PATTERN = re.compile(r"^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}$")
# 32-bit format (token_hex(2)×2); still accepted for verify/hash only
_LEGACY_32BIT_BACKUP_CODE_PATTERN = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4}$")


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_otpauth_uri(login: str, secret: str, issuer: str = MFA_ISSUER) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=login, issuer_name=issuer)


def build_qr_data_uri(otpauth_uri: str) -> str:
    qr = segno.make(otpauth_uri)
    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=4, border=2)
    b64 = base64.standard_b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def verify_totp(secret: str, code: str) -> bool:
    normalized = code.strip().replace(" ", "")
    if not normalized.isdigit() or len(normalized) != 6:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(normalized, valid_window=1)


def normalize_backup_code(code: str) -> str:
    cleaned = code.strip().upper().replace(" ", "").replace("-", "")
    if len(cleaned) == 32:
        return "-".join(cleaned[i : i + 4] for i in range(0, 32, 4))
    if len(cleaned) == 16:
        return "-".join(cleaned[i : i + 4] for i in range(0, 16, 4))
    if len(cleaned) == 8:
        return f"{cleaned[:4]}-{cleaned[4:]}"
    return code.strip().upper()


def hash_backup_code(code: str) -> str:
    normalized = normalize_backup_code(code)
    compact = normalized.replace("-", "")
    return hashlib.sha256(compact.encode()).hexdigest()


def generate_backup_codes(n: int = BACKUP_CODE_COUNT) -> list[str]:
    """Generate backup codes with 128 bits of entropy each (8×4 hex groups)."""
    codes: list[str] = []
    seen: set[str] = set()
    while len(codes) < n:
        raw = secrets.token_hex(BACKUP_CODE_HEX_BYTES).upper()
        display = "-".join(raw[i : i + 4] for i in range(0, 32, 4))
        if display not in seen:
            seen.add(display)
            codes.append(display)
    return codes

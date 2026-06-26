"""RBAC policy store backed by MySQL.

Manages user allowlists, role-based access, and audit logging.
All operations use a dedicated aiomysql pool (the policy database).

Roles (3-tier):
  admin     — super admin (full control)
  useradmin — manages users and tokens (not server config)
  user      — MCP tool access only, no admin panel
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import aiomysql
import bcrypt

from src.auth import mfa as mfa_helpers
from src.crypto import decrypt_secret, encrypt_secret

log = logging.getLogger(__name__)

_CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    github_login    VARCHAR(255) NOT NULL PRIMARY KEY,
    role            ENUM('admin', 'useradmin', 'user') NOT NULL DEFAULT 'user',
    email           VARCHAR(320) NULL,
    password_hash   VARCHAR(255) NULL,
    mfa_enabled     TINYINT NOT NULL DEFAULT 0,
    mfa_secret_enc  TEXT NULL,
    mfa_setup_expires_at DATETIME NULL,
    mfa_backup_generated_at DATETIME NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL
) ENGINE=InnoDB
"""

_CREATE_USER_BACKUP_CODES_TABLE = """
CREATE TABLE IF NOT EXISTS user_backup_codes (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    github_login    VARCHAR(255) NOT NULL,
    code_hash       CHAR(64) NOT NULL,
    used_at         DATETIME NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_backup_user_hash (github_login, code_hash),
    FOREIGN KEY (github_login) REFERENCES users(github_login) ON DELETE CASCADE
) ENGINE=InnoDB
"""

MFA_SETUP_MINUTES = 15

# Recognized roles.
ROLES = ("admin", "useradmin", "user")

# Roles that may sign into the Admin UI.
ADMIN_UI_ROLES = ("admin", "useradmin")

# Roles that manage other users (users tab, tokens, CSV).
ADMIN_ROLES = ("admin", "useradmin")

_CREATE_AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor           VARCHAR(255) NOT NULL,
    action          VARCHAR(100) NOT NULL,
    target          VARCHAR(255),
    detail          JSON,
    INDEX idx_audit_timestamp (timestamp DESC),
    INDEX idx_audit_actor (actor)
) ENGINE=InnoDB
"""

_CREATE_POLICY_SETTINGS_TABLE = """
CREATE TABLE IF NOT EXISTS policy_settings (
    setting_key   VARCHAR(64) NOT NULL PRIMARY KEY,
    setting_value VARCHAR(255) NOT NULL,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by    VARCHAR(255) NOT NULL
) ENGINE=InnoDB
"""

REQUIRE_MFA_ADMIN_ROLES_KEY = "require_mfa_admin_roles"

_CREATE_API_TOKENS_TABLE = """
CREATE TABLE IF NOT EXISTS api_tokens (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    github_login    VARCHAR(255) NOT NULL,
    token_hash      CHAR(64) NOT NULL,
    token_prefix    CHAR(8) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL,
    last_used_at    DATETIME NULL,
    expires_at      DATETIME NULL,
    revoked         TINYINT NOT NULL DEFAULT 0,
    auto_rotate     TINYINT NOT NULL DEFAULT 0,
    rotation_days   INT NULL,
    UNIQUE INDEX idx_token_hash (token_hash),
    INDEX idx_token_user (github_login),
    INDEX idx_token_auto_rotate (auto_rotate, revoked, expires_at),
    FOREIGN KEY (github_login) REFERENCES users(github_login) ON DELETE CASCADE
) ENGINE=InnoDB
"""


class PolicyStore:
    """MySQL-backed RBAC policy store."""

    def __init__(self, pool: aiomysql.Pool):
        self._pool = pool

    async def ensure_tables(self) -> None:
        """Create policy tables if they don't exist (idempotent)."""
        required = {
            "users": _CREATE_USERS_TABLE,
            "audit_log": _CREATE_AUDIT_LOG_TABLE,
            "api_tokens": _CREATE_API_TOKENS_TABLE,
            "user_backup_codes": _CREATE_USER_BACKUP_CODES_TABLE,
            "policy_settings": _CREATE_POLICY_SETTINGS_TABLE,
        }
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                placeholders = ", ".join(["%s"] * len(required))
                await cur.execute(
                    "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
                    f"WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ({placeholders})",
                    tuple(required.keys()),
                )
                existing = {row[0] for row in await cur.fetchall()}

                missing = [name for name in required if name not in existing]
                if missing:
                    for name in required:
                        if name in missing:
                            await cur.execute(required[name])
                            log.info(f"Created table: {name}")
                else:
                    log.info("All policy tables already exist — skipping creation")
        log.info(f"Policy tables ensured (created: {missing})")

    async def seed_admin(self, login: str) -> None:
        """Insert seed admin user only if users table is empty."""
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT COUNT(*) FROM users")
                row = await cur.fetchone()
                if row[0] == 0:
                    await cur.execute(
                        "INSERT INTO users (github_login, role, created_by) "
                        "VALUES (%s, 'admin', 'seed')",
                        (login.lower(),),
                    )
                    log.info(f"Seeded admin user: {login}")

    # ── Query methods ────────────────────────────────────────────────────

    async def is_allowed_user(self, login: str) -> bool:
        """Check if a GitHub login is in the users table."""
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT 1 FROM users WHERE github_login = %s",
                    (login.lower(),),
                )
                return await cur.fetchone() is not None

    async def get_role(self, login: str) -> str | None:
        """Return the user's role, or None if the user does not exist."""
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT role FROM users WHERE github_login = %s",
                    (login.lower(),),
                )
                row = await cur.fetchone()
                return row[0] if row is not None else None

    async def is_admin(self, login: str) -> bool:
        return (await self.get_role(login)) == "admin"

    async def is_user_admin(self, login: str) -> bool:
        """Check if user can manage other users (role 'admin' or 'useradmin')."""
        return (await self.get_role(login)) in ADMIN_ROLES

    async def is_admin_ui_user(self, login: str) -> bool:
        """Check if user may sign into the Admin UI."""
        return (await self.get_role(login)) in ADMIN_UI_ROLES

    async def is_mfa_enabled(self, login: str) -> bool:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT mfa_enabled FROM users WHERE github_login = %s",
                    (login.lower(),),
                )
                row = await cur.fetchone()
                return bool(row and row[0])

    async def count_admins(self) -> int:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                row = await cur.fetchone()
                return row[0]

    # ── CRUD for Admin API ───────────────────────────────────────────────

    async def list_users(self) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(
                    "SELECT github_login, role, email, mfa_enabled, "
                    "created_at, created_by "
                    "FROM users ORDER BY created_at"
                )
                rows = await cur.fetchall()
                return [
                    {
                        **row,
                        "mfa_enabled": bool(row["mfa_enabled"]),
                        "created_at": row["created_at"].isoformat(),
                    }
                    for row in rows
                ]

    async def get_email(self, login: str) -> str | None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT email FROM users WHERE github_login = %s",
                    (login.lower(),),
                )
                row = await cur.fetchone()
                return row[0] if row and row[0] else None

    async def add_user(
        self, login: str, role: str, created_by: str, email: str | None = None
    ) -> None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO users (github_login, role, email, created_by) "
                    "VALUES (%s, %s, %s, %s)",
                    (login.lower(), role, email or None, created_by),
                )
        await self._audit(created_by, "add_user", login, {"role": role, "email": email})

    async def update_user_role(self, login: str, role: str, actor: str) -> None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE users SET role = %s WHERE github_login = %s",
                    (role, login.lower()),
                )
        await self._audit(actor, "update_role", login, {"role": role})

    async def set_email(self, login: str, email: str | None, actor: str) -> None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE users SET email = %s WHERE github_login = %s",
                    (email or None, login.lower()),
                )
        await self._audit(actor, "set_email", login, {"email": email})

    async def upsert_user(
        self, login: str, role: str, email: str | None, actor: str
    ) -> str:
        """Insert or update a user (used by CSV batch import).

        Returns 'created' or 'updated'.
        """
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO users (github_login, role, email, created_by) "
                    "VALUES (%s, %s, %s, %s) "
                    "ON DUPLICATE KEY UPDATE "
                    "role = VALUES(role), "
                    "email = COALESCE(NULLIF(VALUES(email), ''), email)",
                    (login.lower(), role, email or None, actor),
                )
                action = "created" if cur.rowcount == 1 else "updated"
        await self._audit(
            actor, "import_user", login, {"role": role, "email": email, "result": action}
        )
        return action

    async def remove_user(self, login: str, actor: str) -> None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "DELETE FROM users WHERE github_login = %s",
                    (login.lower(),),
                )
        await self._audit(actor, "remove_user", login, None)

    async def get_audit_log(self, page: int = 1, size: int = 50) -> dict[str, Any]:
        """Paginated audit log."""
        offset = (max(1, page) - 1) * size
        async with self._pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute("SELECT COUNT(*) AS total FROM audit_log")
                total = (await cur.fetchone())["total"]
                await cur.execute(
                    "SELECT id, timestamp, actor, action, target, detail "
                    "FROM audit_log ORDER BY timestamp DESC LIMIT %s OFFSET %s",
                    (size, offset),
                )
                rows = await cur.fetchall()
                entries = []
                for row in rows:
                    entry = {**row, "timestamp": row["timestamp"].isoformat()}
                    if isinstance(entry.get("detail"), str):
                        entry["detail"] = json.loads(entry["detail"])
                    entries.append(entry)
                return {
                    "entries": entries,
                    "total": total,
                    "page": page,
                    "size": size,
                }

    # ── Password authentication ────────────────────────────────────────

    async def set_password(self, login: str, password: str, actor: str) -> None:
        pw_bytes = password.encode()
        if len(pw_bytes) > 72:
            raise ValueError("Password exceeds 72 bytes (bcrypt limit)")
        hashed = bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=12))
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE users SET password_hash = %s WHERE github_login = %s",
                    (hashed.decode(), login.lower()),
                )
        await self._audit(actor, "set_password", login, None)

    async def verify_password(self, login: str, password: str) -> bool:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT password_hash FROM users WHERE github_login = %s",
                    (login.lower(),),
                )
                row = await cur.fetchone()
                if row is None or row[0] is None:
                    return False
                return bcrypt.checkpw(password.encode(), row[0].encode())

    # ── Security policy settings ─────────────────────────────────────────

    async def is_require_mfa_admin_roles_enabled(self) -> bool:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT setting_value FROM policy_settings WHERE setting_key = %s",
                    (REQUIRE_MFA_ADMIN_ROLES_KEY,),
                )
                row = await cur.fetchone()
                if row is None:
                    return False
                return row[0] in ("1", "true", "True")

    async def is_mfa_required_for_role(self, role: str) -> bool:
        if role not in ADMIN_UI_ROLES:
            return False
        return await self.is_require_mfa_admin_roles_enabled()

    async def get_security_settings(self) -> dict[str, bool]:
        return {
            "require_mfa_admin_roles": await self.is_require_mfa_admin_roles_enabled(),
        }

    async def set_require_mfa_admin_roles(self, enabled: bool, actor: str) -> None:
        value = "1" if enabled else "0"
        action = "policy_mfa_required_on" if enabled else "policy_mfa_required_off"
        async with self._pool.acquire() as conn:
            await conn.begin()
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO policy_settings (setting_key, setting_value, updated_by) "
                        "VALUES (%s, %s, %s) "
                        "ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), "
                        "updated_by = VALUES(updated_by)",
                        (REQUIRE_MFA_ADMIN_ROLES_KEY, value, actor),
                    )
                    await cur.execute(
                        "INSERT INTO audit_log (actor, action, target, detail) "
                        "VALUES (%s, %s, %s, %s)",
                        (actor, action, REQUIRE_MFA_ADMIN_ROLES_KEY, None),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    # ── Admin UI MFA (TOTP + backup codes) ───────────────────────────────

    async def get_mfa_status(self, login: str) -> dict[str, Any]:
        login_l = login.lower()
        async with self._pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(
                    "SELECT mfa_enabled, mfa_secret_enc, mfa_setup_expires_at "
                    "FROM users WHERE github_login = %s",
                    (login_l,),
                )
                row = await cur.fetchone()
                if row is None:
                    return {
                        "enabled": False,
                        "backup_codes_remaining": 0,
                        "setup_pending": False,
                    }
                await cur.execute(
                    "SELECT COUNT(*) AS n FROM user_backup_codes "
                    "WHERE github_login = %s AND used_at IS NULL",
                    (login_l,),
                )
                remaining = (await cur.fetchone())["n"]
                setup_pending = False
                if (
                    row["mfa_secret_enc"]
                    and not row["mfa_enabled"]
                    and row["mfa_setup_expires_at"]
                ):
                    expires = row["mfa_setup_expires_at"]
                    if expires.tzinfo is None:
                        expires = expires.replace(tzinfo=timezone.utc)
                    setup_pending = datetime.now(timezone.utc) <= expires
                return {
                    "enabled": bool(row["mfa_enabled"]),
                    "backup_codes_remaining": remaining,
                    "setup_pending": setup_pending,
                }

    async def start_mfa_setup(self, login: str) -> dict[str, str]:
        login_l = login.lower()
        if not await self.is_mfa_enabled(login_l):
            existing = await self._get_setup_secret_if_valid(login_l)
            if existing is not None:
                uri = mfa_helpers.build_otpauth_uri(login_l, existing)
                return {
                    "secret": existing,
                    "otpauth_uri": uri,
                    "qr_data_uri": mfa_helpers.build_qr_data_uri(uri),
                }
        secret = mfa_helpers.generate_totp_secret()
        enc = encrypt_secret(secret)
        expires = datetime.now(timezone.utc) + timedelta(minutes=MFA_SETUP_MINUTES)
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE users SET mfa_secret_enc = %s, mfa_setup_expires_at = %s, "
                    "mfa_enabled = 0 WHERE github_login = %s",
                    (enc, expires.replace(tzinfo=None), login_l),
                )
        uri = mfa_helpers.build_otpauth_uri(login_l, secret)
        return {
            "secret": secret,
            "otpauth_uri": uri,
            "qr_data_uri": mfa_helpers.build_qr_data_uri(uri),
        }

    async def confirm_mfa_enable(
        self, login: str, code: str, actor: str
    ) -> list[str]:
        login_l = login.lower()
        secret = await self._get_setup_secret_if_valid(login_l)
        if secret is None:
            raise ValueError("MFA setup expired or not started")
        if not mfa_helpers.verify_totp(secret, code):
            raise ValueError("Invalid verification code")

        plaintext_codes = mfa_helpers.generate_backup_codes()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        async with self._pool.acquire() as conn:
            await conn.begin()
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "UPDATE users SET mfa_enabled = 1, mfa_setup_expires_at = NULL, "
                        "mfa_backup_generated_at = %s WHERE github_login = %s",
                        (now, login_l),
                    )
                    await cur.execute(
                        "DELETE FROM user_backup_codes WHERE github_login = %s",
                        (login_l,),
                    )
                    for display_code in plaintext_codes:
                        await cur.execute(
                            "INSERT INTO user_backup_codes (github_login, code_hash) "
                            "VALUES (%s, %s)",
                            (login_l, mfa_helpers.hash_backup_code(display_code)),
                        )
                    await cur.execute(
                        "INSERT INTO audit_log (actor, action, target, detail) "
                        "VALUES (%s, %s, %s, %s)",
                        (actor, "mfa_enable", login_l, None),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return plaintext_codes

    async def disable_mfa(self, login: str, actor: str) -> None:
        login_l = login.lower()
        role = await self.get_role(login_l)
        if role and await self.is_mfa_required_for_role(role):
            raise ValueError("2FA is required by policy and cannot be disabled")
        await self._clear_mfa_state(login_l, actor, "mfa_disable")

    async def clear_mfa_for_user(self, target: str, actor: str) -> None:
        target_l = target.lower()
        action = "mfa_disable" if actor.lower() == target_l else "mfa_admin_clear"
        await self._clear_mfa_state(target_l, actor, action)

    async def verify_mfa_code(self, login: str, code: str) -> bool:
        login_l = login.lower()
        secret = await self._get_enabled_totp_secret(login_l)
        if secret and mfa_helpers.verify_totp(secret, code):
            return True
        return await self._try_consume_backup_code(login_l, code)

    async def regenerate_backup_codes(self, login: str, actor: str) -> list[str]:
        login_l = login.lower()
        if not await self.is_mfa_enabled(login_l):
            raise ValueError("2FA is not enabled")

        plaintext_codes = mfa_helpers.generate_backup_codes()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        async with self._pool.acquire() as conn:
            await conn.begin()
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "DELETE FROM user_backup_codes WHERE github_login = %s",
                        (login_l,),
                    )
                    for display_code in plaintext_codes:
                        await cur.execute(
                            "INSERT INTO user_backup_codes (github_login, code_hash) "
                            "VALUES (%s, %s)",
                            (login_l, mfa_helpers.hash_backup_code(display_code)),
                        )
                    await cur.execute(
                        "UPDATE users SET mfa_backup_generated_at = %s "
                        "WHERE github_login = %s",
                        (now, login_l),
                    )
                    await cur.execute(
                        "INSERT INTO audit_log (actor, action, target, detail) "
                        "VALUES (%s, %s, %s, %s)",
                        (actor, "mfa_regenerate_backup", login_l, None),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return plaintext_codes

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _get_setup_secret_if_valid(self, login_l: str) -> str | None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT mfa_secret_enc, mfa_setup_expires_at FROM users "
                    "WHERE github_login = %s",
                    (login_l,),
                )
                row = await cur.fetchone()
                if row is None or row[0] is None or row[1] is None:
                    return None
                expires = row[1]
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > expires:
                    return None
                return decrypt_secret(row[0])

    async def _get_enabled_totp_secret(self, login_l: str) -> str | None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT mfa_secret_enc FROM users "
                    "WHERE github_login = %s AND mfa_enabled = 1",
                    (login_l,),
                )
                row = await cur.fetchone()
                if row is None or row[0] is None:
                    return None
                return decrypt_secret(row[0])

    async def _try_consume_backup_code(self, login_l: str, code: str) -> bool:
        code_hash = mfa_helpers.hash_backup_code(code)
        async with self._pool.acquire() as conn:
            await conn.begin()
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "UPDATE user_backup_codes SET used_at = NOW() "
                        "WHERE github_login = %s AND code_hash = %s AND used_at IS NULL",
                        (login_l, code_hash),
                    )
                    ok = cur.rowcount == 1
                await conn.commit()
                return ok
            except Exception:
                await conn.rollback()
                raise

    async def _clear_mfa_state(self, login_l: str, actor: str, action: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.begin()
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "UPDATE users SET mfa_enabled = 0, mfa_secret_enc = NULL, "
                        "mfa_setup_expires_at = NULL, mfa_backup_generated_at = NULL "
                        "WHERE github_login = %s",
                        (login_l,),
                    )
                    await cur.execute(
                        "DELETE FROM user_backup_codes WHERE github_login = %s",
                        (login_l,),
                    )
                    await cur.execute(
                        "INSERT INTO audit_log (actor, action, target, detail) "
                        "VALUES (%s, %s, %s, %s)",
                        (actor, action, login_l, None),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def _audit(
        self, actor: str, action: str, target: str | None, detail: Any
    ) -> None:
        detail_json = json.dumps(detail) if detail is not None else None
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO audit_log (actor, action, target, detail) "
                    "VALUES (%s, %s, %s, %s)",
                    (actor, action, target, detail_json),
                )

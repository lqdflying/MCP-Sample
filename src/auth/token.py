"""Per-user API token authentication.

Tokens are generated per-user, stored as SHA-256 hashes in the `api_tokens`
table, and carry the user's `login` claim for RBAC resolution.

Also supports a static fallback token (MCP_API_TOKEN) for backward
compatibility via build_static_token_verifier().
"""

import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import aiomysql
from fastmcp.server.auth.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.providers.debug import DebugTokenVerifier

from src.debug import debug_log

log = logging.getLogger("mcp")

TOKEN_PREFIX = "mcp_"


def generate_raw_token() -> tuple[str, str, str]:
    """Return (raw_token, sha256_hex_hash, 8-char prefix)."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, token_hash, raw[:8]


def expires_at_from_rotation_days(rotation_days: int) -> datetime:
    """Naive UTC datetime for MySQL expires_at after rotation."""
    return datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=rotation_days)


# ── Lazy getter (avoids circular imports) ──────────────────────────────────
_token_store_getter = None


def set_token_store_getter(getter):
    """Set a callable that returns the TokenStore instance."""
    global _token_store_getter
    _token_store_getter = getter


def _get_token_store() -> "TokenStore":
    if _token_store_getter is None:
        raise RuntimeError("TokenStore not available — server not yet initialized")
    store = _token_store_getter()
    if store is None:
        raise RuntimeError("TokenStore not available — server not yet initialized")
    return store


def _naive_utc(dt: datetime) -> datetime:
    """Normalize datetimes for MySQL DATETIME comparison."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _serialize_token_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **row,
        "revoked": bool(row["revoked"]),
        "auto_rotate": bool(row.get("auto_rotate", 0)),
        "rotation_days": row.get("rotation_days"),
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "last_used_at": row["last_used_at"].isoformat() if row["last_used_at"] else None,
        "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
    }


_TOKEN_LIST_COLUMNS = (
    "id, github_login, token_prefix, name, created_at, "
    "created_by, last_used_at, expires_at, revoked, auto_rotate, rotation_days"
)


class TokenStore:
    """Manages per-user API tokens in MySQL."""

    def __init__(self, pool: aiomysql.Pool):
        self._pool = pool

    async def create_token(
        self,
        login: str,
        name: str,
        actor: str,
        expires_at: datetime | None = None,
        *,
        auto_rotate: bool = False,
        rotation_days: int | None = None,
    ) -> str:
        """Generate a new API token. Returns the raw token (shown only once)."""
        raw, token_hash, token_prefix = generate_raw_token()
        auto_val = 1 if auto_rotate else 0
        rot_days = rotation_days if auto_rotate else None

        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO api_tokens "
                    "(github_login, token_hash, token_prefix, name, created_by, "
                    "expires_at, auto_rotate, rotation_days) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        login.lower(),
                        token_hash,
                        token_prefix,
                        name,
                        actor,
                        expires_at,
                        auto_val,
                        rot_days,
                    ),
                )
                await cur.execute(
                    "INSERT INTO audit_log (actor, action, target, detail) "
                    "VALUES (%s, %s, %s, %s)",
                    (actor, "create_token", login, json.dumps({"name": name})),
                )
        return raw

    async def verify_token(self, raw_token: str) -> str | None:
        """Verify a raw token. Returns github_login if valid, None otherwise."""
        if not raw_token or not raw_token.startswith(TOKEN_PREFIX):
            return None
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT id, github_login FROM api_tokens "
                    "WHERE token_hash = %s AND revoked = 0 "
                    "AND (expires_at IS NULL OR expires_at > NOW())",
                    (token_hash,),
                )
                row = await cur.fetchone()
                if row is None:
                    return None
                token_id, login = row
                await cur.execute(
                    "UPDATE api_tokens SET last_used_at = NOW() WHERE id = %s",
                    (token_id,),
                )
                return login.lower() if login else None

    async def list_tokens(self, login: str | None = None) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                if login:
                    await cur.execute(
                        f"SELECT {_TOKEN_LIST_COLUMNS} "
                        "FROM api_tokens WHERE github_login = %s "
                        "ORDER BY created_at DESC",
                        (login.lower(),),
                    )
                else:
                    await cur.execute(
                        f"SELECT {_TOKEN_LIST_COLUMNS} "
                        "FROM api_tokens ORDER BY created_at DESC"
                    )
                rows = await cur.fetchall()
                return [_serialize_token_row(row) for row in rows]

    async def list_due_for_rotation(
        self, lead_days: int, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Tokens due for auto-rotation (within lead_days of expires_at)."""
        async with self._pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(
                    "SELECT id, github_login, token_prefix, name, expires_at, rotation_days "
                    "FROM api_tokens "
                    "WHERE auto_rotate = 1 AND revoked = 0 "
                    "AND expires_at IS NOT NULL AND rotation_days IS NOT NULL "
                    "AND expires_at <= DATE_ADD(NOW(), INTERVAL %s DAY) "
                    "ORDER BY expires_at ASC LIMIT %s",
                    (lead_days, limit),
                )
                rows = await cur.fetchall()
                return [
                    {
                        **row,
                        "github_login": row["github_login"].lower()
                        if row["github_login"]
                        else row["github_login"],
                    }
                    for row in rows
                ]

    async def apply_rotation(
        self,
        token_id: int,
        new_hash: str,
        new_prefix: str,
        new_expires_at: datetime,
        actor: str = "system",
        *,
        token_name: str,
        expected_expires_at: datetime,
        emailed: bool = True,
    ) -> bool:
        """Update token secret and expiry in place. Returns True if row updated."""
        detail = json.dumps({"name": token_name, "emailed": emailed})
        expected = _naive_utc(expected_expires_at)
        new_expires = _naive_utc(new_expires_at)
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE api_tokens SET token_hash = %s, token_prefix = %s, "
                    "expires_at = %s "
                    "WHERE id = %s AND auto_rotate = 1 AND revoked = 0 "
                    "AND expires_at = %s",
                    (new_hash, new_prefix, new_expires, token_id, expected),
                )
                affected = cur.rowcount
                if affected:
                    await cur.execute(
                        "INSERT INTO audit_log (actor, action, target, detail) "
                        "VALUES (%s, %s, %s, %s)",
                        (actor, "rotate_token", str(token_id), detail),
                    )
                return affected > 0

    async def revoke_token(self, token_id: int, actor: str) -> bool:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE api_tokens SET revoked = 1 WHERE id = %s AND revoked = 0",
                    (token_id,),
                )
                affected = cur.rowcount
                if affected:
                    await cur.execute(
                        "INSERT INTO audit_log (actor, action, target, detail) "
                        "VALUES (%s, %s, %s, %s)",
                        (actor, "revoke_token", str(token_id), None),
                    )
                return affected > 0

    async def delete_token(self, token_id: int, actor: str) -> bool:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "DELETE FROM api_tokens WHERE id = %s AND revoked = 1",
                    (token_id,),
                )
                affected = cur.rowcount
                if affected:
                    await cur.execute(
                        "INSERT INTO audit_log (actor, action, target, detail) "
                        "VALUES (%s, %s, %s, %s)",
                        (actor, "delete_token", str(token_id), None),
                    )
                return affected > 0


class DbTokenVerifier(TokenVerifier):
    """Async token verifier that resolves per-user tokens from the database."""

    def __init__(self, audit_logging_enabled: bool = False):
        super().__init__(required_scopes=[])
        self._audit = audit_logging_enabled

    async def verify_token(self, token: str) -> AccessToken | None:
        store = _get_token_store()
        login = await store.verify_token(token)
        if login is None:
            if self._audit:
                log.warning("AUTH failed method=db_token reason=invalid_or_expired")
            debug_log(
                "auth_token_verify",
                login=None,
                token_prefix=token[:8] if token else None,
                result="invalid",
            )
            return None
        if self._audit:
            log.info(f"AUTH success method=db_token login={login}")
        debug_log(
            "auth_token_verify",
            login=login,
            token_prefix=token[:8] if token else None,
            result="valid",
        )
        return AccessToken(
            token=token,
            client_id=f"token-user:{login}",
            scopes=["read"],
            claims={"login": login},
        )


def build_static_token_verifier(
    mcp_api_token: str,
    audit_logging_enabled: bool = False,
) -> DebugTokenVerifier:
    """Return a DebugTokenVerifier that validates against a static token.

    Uses ``hmac.compare_digest`` for constant-time comparison.
    """

    def _validate(token: str) -> bool:
        valid = hmac.compare_digest(token, mcp_api_token)
        if audit_logging_enabled:
            if valid:
                log.info("AUTH success method=static_token")
            else:
                log.warning("AUTH failed method=static_token reason=invalid")
        return valid

    return DebugTokenVerifier(
        validate=_validate,
        client_id="mcp-static-client",
        scopes=["read"],
    )

"""MySQL-backed OAuth key-value store with Fernet encryption.

Implements the AsyncKeyValueProtocol expected by FastMCP's OAuth 2.1 proxy
so that OAuth sessions/codes/tokens survive server restarts and scale
across multiple instances.
"""

import logging
from datetime import datetime, timezone

import aiomysql

from src.crypto import decrypt_secret, encrypt_secret

log = logging.getLogger("mcp")

_CREATE_OAUTH_KV_TABLE = """
CREATE TABLE IF NOT EXISTS oauth_kv (
    kv_key      VARCHAR(512) NOT NULL PRIMARY KEY,
    kv_value    MEDIUMTEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_oauth_kv_updated (updated_at)
) ENGINE=InnoDB
"""


class PolicyDbOAuthStore:
    """Encrypted KV store for FastMCP OAuth state."""

    def __init__(self, pool: aiomysql.Pool):
        self._pool = pool

    async def ensure_table(self) -> None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(_CREATE_OAUTH_KV_TABLE)
        log.info("OAuth KV table ensured")

    async def get(self, key: str) -> str | None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT kv_value FROM oauth_kv WHERE kv_key = %s", (key,)
                )
                row = await cur.fetchone()
                if row is None:
                    return None
                return decrypt_secret(row[0])

    async def set(self, key: str, value: str) -> None:
        encrypted = encrypt_secret(value)
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO oauth_kv (kv_key, kv_value) VALUES (%s, %s) "
                    "ON DUPLICATE KEY UPDATE kv_value = VALUES(kv_value)",
                    (key, encrypted),
                )

    async def delete(self, key: str) -> None:
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("DELETE FROM oauth_kv WHERE kv_key = %s", (key,))

    async def cleanup_stale(self, max_age_hours: int = 24) -> int:
        """Delete KV entries older than max_age_hours. Returns rows deleted."""
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                cutoff = datetime.now(timezone.utc).replace(tzinfo=None)
                await cur.execute(
                    "DELETE FROM oauth_kv WHERE updated_at < DATE_SUB(%s, INTERVAL %s HOUR)",
                    (cutoff, max_age_hours),
                )
                return cur.rowcount

"""Token auto-rotation background loop.

Polls `api_tokens` for rows with `auto_rotate = 1` whose `expires_at` is
within `MCP_TOKEN_ROTATE_LEAD_DAYS` of now, then generates a replacement
secret and (optionally) emails the user.

Uses a MySQL GET_LOCK advisory lock so only one instance rotates.
"""

import asyncio
import logging
import os
from datetime import timezone

import aiomysql

from src.auth.token import TokenStore, expires_at_from_rotation_days, generate_raw_token
from src.debug import debug_log
from src.notify.email import send_email, smtp_configured

log = logging.getLogger("mcp")

LEAD_DAYS = int(os.getenv("MCP_TOKEN_ROTATE_LEAD_DAYS", "7"))
POLL_SECONDS = int(os.getenv("MCP_TOKEN_ROTATE_POLL_SEC", "3600"))
LOCK_NAME = "mcp_token_auto_rotate"
LOCK_TIMEOUT = 0  # non-blocking


async def _acquire_advisory_lock(pool: aiomysql.Pool) -> bool:
    """Try to get MySQL advisory lock (non-blocking). Returns True if acquired."""
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT GET_LOCK(%s, %s)", (LOCK_NAME, LOCK_TIMEOUT))
            row = await cur.fetchone()
            return row is not None and row[0] == 1


async def _release_advisory_lock(pool: aiomysql.Pool) -> None:
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT RELEASE_LOCK(%s)", (LOCK_NAME,))


async def run_token_auto_rotate_once(
    token_store: TokenStore,
    policy_pool: aiomysql.Pool,
    *,
    get_email_for_user=None,
) -> int:
    """Run one rotation pass. Returns how many tokens were rotated."""
    due = await token_store.list_due_for_rotation(LEAD_DAYS)
    if not due:
        return 0

    rotated = 0
    for tok in due:
        rotation_days = tok.get("rotation_days")
        if not rotation_days:
            continue

        raw, new_hash, new_prefix = generate_raw_token()
        new_expires = expires_at_from_rotation_days(rotation_days)
        login = tok["github_login"]
        name = tok.get("name", "")
        token_id = tok["id"]
        expected_expires = tok["expires_at"]

        if expected_expires and expected_expires.tzinfo is None:
            expected_expires = expected_expires.replace(tzinfo=timezone.utc)

        # Send email BEFORE applying rotation so user gets new token
        emailed = False
        if smtp_configured() and get_email_for_user:
            email_addr = await get_email_for_user(login)
            if email_addr:
                try:
                    await send_email(
                        to=email_addr,
                        subject=f"[MCP] Token rotated: {name}",
                        body=(
                            f"Your API token '{name}' has been automatically rotated.\n\n"
                            f"New token: {raw}\n\n"
                            f"This token expires at {new_expires.isoformat()}Z.\n"
                            "Please update your client configuration."
                        ),
                    )
                    emailed = True
                except Exception:
                    log.exception(f"Failed to email rotated token to {login}")

        ok = await token_store.apply_rotation(
            token_id=token_id,
            new_hash=new_hash,
            new_prefix=new_prefix,
            new_expires_at=new_expires,
            actor="auto-rotate",
            token_name=name,
            expected_expires_at=expected_expires,
            emailed=emailed,
        )
        if ok:
            rotated += 1
            debug_log(
                "token_rotated",
                token_id=token_id,
                login=login,
                name=name,
                emailed=emailed,
            )
        else:
            debug_log(
                "token_rotation_skipped",
                token_id=token_id,
                login=login,
                reason="already_rotated_or_revoked",
            )

    return rotated


async def run_token_auto_rotate_guarded(
    token_store: TokenStore,
    policy_pool: aiomysql.Pool,
    *,
    get_email_for_user=None,
) -> None:
    """Background loop: acquire advisory lock, rotate, release, sleep."""
    log.info(
        f"Token auto-rotate started (lead={LEAD_DAYS}d, poll={POLL_SECONDS}s)"
    )
    while True:
        try:
            locked = await _acquire_advisory_lock(policy_pool)
            if locked:
                try:
                    count = await run_token_auto_rotate_once(
                        token_store,
                        policy_pool,
                        get_email_for_user=get_email_for_user,
                    )
                    if count:
                        log.info(f"Token auto-rotate: rotated {count} token(s)")
                finally:
                    await _release_advisory_lock(policy_pool)
            else:
                debug_log("token_rotate_skip", reason="lock_held_by_another_instance")
        except asyncio.CancelledError:
            log.info("Token auto-rotate task cancelled")
            return
        except Exception:
            log.exception("Token auto-rotate error")

        await asyncio.sleep(POLL_SECONDS)

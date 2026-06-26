"""MCP Server with Authentication Sample.

A minimal FastMCP server demonstrating a well-designed authentication architecture:
- Static token auth (MCP_API_TOKEN)
- Per-user token auth with auto-rotation (via policy DB)
- GitHub OAuth (via GitHub App)
- Dual mode accepting either auth method
- 3-tier RBAC: admin, useradmin, user
- MFA (TOTP + backup codes) for admin UI
- Structured JSON logging with field redaction and trace IDs

This serves as a reference implementation for building MCP servers with
production-ready authentication and user management.
"""

import asyncio
import logging
import os
import time
import traceback as tb_module
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Load .env BEFORE any imports that read env vars (e.g. FASTMCP_* settings).
load_dotenv()

from fastmcp import FastMCP  # noqa: E402
from fastmcp.server.middleware import Middleware  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402

from src.auth import setup_auth, parse_bool, set_token_store_getter  # noqa: E402
from src.debug import (  # noqa: E402
    UVICORN_JSON_LOGGING_CONFIG,
    setup_debug_logging,
    debug_log,
    set_trace_id,
    clear_trace_id,
    is_debug_enabled,
)
from src.tools import hello_world  # noqa: E402

_debug = parse_bool(os.environ.get("MCP_DEBUG", ""), default=False)
_debug_verbose = parse_bool(os.environ.get("MCP_DEBUG_VERBOSE", ""), default=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%H:%M:%S",
)
# If debug mode: reconfigure to structured JSON (must be after basicConfig)
setup_debug_logging(_debug, verbose=_debug_verbose)

log = logging.getLogger("mcp")
logger = logging.getLogger(__name__)


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(server: FastMCP):
    log.info("MCP Authentication Sample Server started")
    debug_log(
        "startup",
        level=logging.INFO,
        debug=_debug,
        debug_verbose=_debug_verbose,
        auth_mode=os.environ.get("MCP_AUTH_MODE", "both"),
        host=os.environ.get("HOST", "0.0.0.0"),
        port=os.environ.get("PORT", "8000"),
        policy_db=bool(os.environ.get("MCP_POLICY_DB_HOST", "").strip()),
    )

    policy_db_host = os.environ.get("MCP_POLICY_DB_HOST", "").strip()
    pool = None
    background_tasks: list[asyncio.Task] = []

    if policy_db_host:
        # ── Full mode: initialize policy DB pool and stores ───────────
        import aiomysql

        from src.auth.oauth_store import PolicyDbOAuthStore
        from src.auth.policy import PolicyStore
        from src.auth.token import TokenStore
        from src.auth.token_rotate import run_token_auto_rotate_guarded

        pool = await aiomysql.create_pool(
            host=policy_db_host,
            port=int(os.environ.get("MCP_POLICY_DB_PORT", "3306")),
            user=os.environ.get("MCP_POLICY_DB_USER", ""),
            password=os.environ.get("MCP_POLICY_DB_PASSWORD", ""),
            db=os.environ.get("MCP_POLICY_DB_NAME", "mcp_policy"),
            autocommit=True,
            minsize=2,
            maxsize=10,
        )
        log.info(f"Policy DB pool created: {policy_db_host}")

        policy_store = PolicyStore(pool)
        token_store = TokenStore(pool)
        oauth_store = PolicyDbOAuthStore(pool)

        await policy_store.ensure_tables()
        await oauth_store.ensure_table()

        # Seed admin user if configured and table is empty
        seed_admin = os.environ.get("MCP_ADMIN_SEED", "").strip()
        if seed_admin:
            await policy_store.seed_admin(seed_admin)

        # Wire the lazy token store getter so DbTokenVerifier works
        set_token_store_getter(lambda: token_store)

        # ── Background tasks ──────────────────────────────────────────
        # Token auto-rotation
        rotate_task = asyncio.create_task(
            run_token_auto_rotate_guarded(
                token_store,
                pool,
                get_email_for_user=policy_store.get_email,
            )
        )
        background_tasks.append(rotate_task)

        # OAuth KV stale entry cleanup (every 6 hours)
        async def _oauth_kv_cleanup_loop():
            while True:
                try:
                    deleted = await oauth_store.cleanup_stale(max_age_hours=24)
                    if deleted:
                        debug_log("oauth_kv_cleanup", deleted=deleted)
                except asyncio.CancelledError:
                    return
                except Exception:
                    log.exception("OAuth KV cleanup error")
                await asyncio.sleep(6 * 3600)

        cleanup_task = asyncio.create_task(_oauth_kv_cleanup_loop())
        background_tasks.append(cleanup_task)

        log.info("Full mode: policy store, token store, background tasks initialized")
    else:
        log.info("Lightweight mode: no policy DB configured (static token auth only)")

    try:
        yield
    finally:
        # Shutdown: cancel background tasks and close pool
        for task in background_tasks:
            task.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)
        if pool:
            pool.close()
            await pool.wait_closed()
            log.info("Policy DB pool closed")
        log.info("MCP server shutdown complete")


# ── Server factory (called only at startup, not at import time) ───────────────

def create_server() -> FastMCP:
    """Construct and configure the FastMCP server.

    Called only when starting the server, not at import time, so tool
    implementations can be imported and tested without triggering auth setup.
    """
    auth = setup_auth()

    mcp = FastMCP(
        "MCP Authentication Sample",
        instructions=(
            "A minimal MCP server demonstrating FastMCP authentication patterns: "
            "static token, GitHub OAuth, and dual-mode authentication. "
            "Includes a sample hello_world tool as a reference for adding new tools."
        ),
        lifespan=lifespan,
        auth=auth,
    )

    # ── Logging middleware ────────────────────────────────────────────────

    class LoggingMiddleware(Middleware):
        async def on_call_tool(self, context, call_next):
            name = context.message.name
            args = context.message.arguments or {}
            trace = set_trace_id()

            if is_debug_enabled():
                debug_log(
                    "tool_call_start",
                    tool=name,
                    args=args,
                    trace_id=trace,
                )

            # Never include raw args in log lines — all logs may go to aggregators.
            log.info(f"▶ {name}")
            t0 = time.monotonic()
            try:
                result = await call_next(context)
                elapsed = (time.monotonic() - t0) * 1000
                size = ""
                result_chars = 0
                try:
                    content = result.content
                    if content:
                        result_chars = sum(
                            len(c.text) for c in content if hasattr(c, "text")
                        )
                        size = f"  {result_chars:,} chars"
                except Exception:
                    pass
                log.info(f"✓ {name}  {elapsed:.0f}ms{size}")
                debug_log(
                    "tool_call_end",
                    tool=name,
                    duration_ms=round(elapsed, 2),
                    result_chars=result_chars,
                    has_error=False,
                )
                return result
            except Exception as e:
                elapsed = (time.monotonic() - t0) * 1000
                # Only log exception type — str(e) may contain sensitive data.
                log.error(
                    f"✗ {name}  FAILED ({elapsed:.0f}ms): {type(e).__name__}"
                )
                debug_log(
                    "tool_call_error",
                    tool=name,
                    duration_ms=round(elapsed, 2),
                    error=str(e),
                    error_type=type(e).__name__,
                    traceback=tb_module.format_exc(),
                    args=args,
                )
                raise
            finally:
                clear_trace_id()

    mcp.add_middleware(LoggingMiddleware())

    # ── Health check endpoint ──────────────────────────────────────────

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": "MCP Authentication Sample"})

    # ═══════════════════════════════════════════════════════════════════════
    # SAMPLE TOOL — demonstrating the minimal pattern for adding tools
    # ═══════════════════════════════════════════════════════════════════════

    @mcp.tool(tags={"sample"})
    async def hello_world_tool(name: str = "World") -> str:
        """Return a friendly greeting.

        This tool exists solely as a reference implementation showing:
        - How to define a FastMCP tool with typed parameters
        - How to use tags for grouping and filtering
        - The basic structure all tools follow

        Args:
            name: The name to greet. Defaults to "World".
        """
        return await hello_world(name)

    return mcp


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import warnings

    warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn")

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    stateless = parse_bool(os.environ.get("MCP_STATELESS", "true"), default=True)

    mcp = create_server()

    mcp.run(
        transport="streamable-http",
        host=host,
        port=port,
        stateless_http=stateless,
        uvicorn_config=UVICORN_JSON_LOGGING_CONFIG,
    )

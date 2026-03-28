"""MCP Server with Authentication Sample.

A minimal FastMCP server demonstrating a well-designed authentication architecture:
- Static token auth (MCP_API_TOKEN)
- GitHub OAuth (via GitHub App)
- Dual mode accepting either auth method

This serves as a reference implementation for building MCP servers with
production-ready authentication. All GitHub-specific code has been removed
to leave a clean authentication sample.
"""

import logging
import os
import sys
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from src.auth import setup_auth, parse_bool
from src.tools import hello_world

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mcp")
logger = logging.getLogger(__name__)


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(server: FastMCP):
    print("MCP Authentication Sample Server started", file=sys.stderr)
    yield


# ── Server factory (called only at startup, not at import time) ───────────────

def create_server() -> FastMCP:
    """Construct and configure the FastMCP server.

    This function is called only when starting the server, not when
    importing the module. This allows tool implementations to be imported
    and tested independently without triggering auth setup.
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
            extra = {k: v for k, v in args.items() if v is not None}
            extra_str = f"  {extra}" if extra else ""
            log.info(f"▶ {name}{extra_str}")
            t0 = time.monotonic()
            try:
                result = await call_next(context)
                elapsed = (time.monotonic() - t0) * 1000
                size = ""
                try:
                    content = result.content
                    if content:
                        chars = sum(len(c.text) for c in content if hasattr(c, "text"))
                        size = f"  {chars:,} chars"
                except Exception:
                    pass
                log.info(f"✓ {name}  {elapsed:.0f}ms{size}")
                return result
            except Exception as e:
                elapsed = (time.monotonic() - t0) * 1000
                log.error(f"✗ {name}  FAILED ({elapsed:.0f}ms): {e}  args={args}")
                raise

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
        return hello_world(name)

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
    )

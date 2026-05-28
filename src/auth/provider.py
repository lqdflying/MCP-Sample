"""Auth provider setup.

Reads environment variables, validates them, and returns the configured
FastMCP auth provider -- either a static DebugTokenVerifier for token-only
mode, or a MultiAuth compositor for OAuth/both modes.
"""

import os
import sys
from pathlib import Path

from fastmcp import settings as fastmcp_settings
from fastmcp.server.auth import MultiAuth
from key_value.aio.stores.memory import MemoryStore

from .oauth import (
    LoginFilteredGitHubProvider,
    LoginFilteredGitHubTokenVerifier,
    normalize_oauth_scopes,
)
from .token import build_token_verifier

_VALID_AUTH_MODES = {"token", "oauth", "both"}


def parse_bool(raw: str, default: bool = False) -> bool:
    """Parse a string env-var value to bool."""
    value = (raw or "").strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "on"}


def _split_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def setup_auth():
    """Read env vars, validate, and return the configured auth provider.

    Exits the process with an error message if required variables are missing
    or configuration is invalid.

    == Auth modes ==

    token  — static MCP_API_TOKEN only (DebugTokenVerifier)
    oauth  — GitHub OAuth only: MultiAuth with OAuth 2.1 proxy (GitHubProvider)
             + OAuth 2.0 raw token fallback (GitHubTokenVerifier)
    both   — all three: static token + OAuth 2.1 proxy + OAuth 2.0 raw
    """
    auth_mode = os.environ.get("MCP_AUTH_MODE", "both").strip().lower()
    if auth_mode not in _VALID_AUTH_MODES:
        print("ERROR: MCP_AUTH_MODE must be one of: token, oauth, both.", file=sys.stderr)
        sys.exit(1)

    need_token_auth = auth_mode in {"token", "both"}
    need_oauth_auth = auth_mode in {"oauth", "both"}
    audit_logging_enabled = parse_bool(os.environ.get("MCP_AUTH_AUDIT_LOG", "true"), default=True)

    # ── Static token ──────────────────────────────────────────────────
    mcp_api_token = os.environ.get("MCP_API_TOKEN", "").strip()
    if need_token_auth and not mcp_api_token:
        print(
            "ERROR: MCP_API_TOKEN environment variable is required for token auth mode.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── OAuth vars ────────────────────────────────────────────────────
    github_client_id = os.environ.get("GITHUB_CLIENT_ID", "").strip()
    github_client_secret = os.environ.get("GITHUB_CLIENT_SECRET", "").strip()
    base_url = os.environ.get("BASE_URL", "").strip()

    oauth_vars = {
        "GITHUB_CLIENT_ID": github_client_id,
        "GITHUB_CLIENT_SECRET": github_client_secret,
        "BASE_URL": base_url,
    }

    if need_oauth_auth:
        missing = [name for name, value in oauth_vars.items() if not value]
        if missing:
            print(
                "ERROR: GitHub OAuth is enabled but missing required environment variables: "
                f"{', '.join(missing)}",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        configured = [name for name, value in oauth_vars.items() if value]
        if configured and len(configured) != len(oauth_vars):
            missing = [name for name, value in oauth_vars.items() if not value]
            print(
                "WARNING: GitHub OAuth variables are partially configured but OAuth is disabled "
                f"by MCP_AUTH_MODE. Ignored variables are missing: {', '.join(missing)}",
                file=sys.stderr,
            )

    github_oauth_scopes = normalize_oauth_scopes(
        _split_csv(os.environ.get("GITHUB_OAUTH_SCOPES", "user"))
    )
    allowed_github_logins = set(_split_csv(os.environ.get("ALLOWED_GITHUB_LOGINS", "")))

    # ── Token-only mode ───────────────────────────────────────────────
    if not need_oauth_auth:
        return build_token_verifier(
            mcp_api_token=mcp_api_token,
            audit_logging_enabled=audit_logging_enabled,
        )

    # ── OAuth storage backend ─────────────────────────────────────────
    # GitHubProvider stores OAuth transactions, authorization codes,
    # client registrations, and refresh token mappings.  By default we
    # use in-memory storage so deployments without a writable home
    # directory (containers, serverless) work out of the box.
    #
    # Set FASTMCP_HOME to point to a writable directory to switch to
    # persistent encrypted file storage that survives restarts.
    #
    # FastMCP reads settings.home at import time, so we must sync it
    # with the runtime FASTMCP_HOME value before constructing the
    # provider.  Otherwise the default file store ignores the runtime
    # env var and writes to the import-time default path.
    fastmcp_home = os.environ.get("FASTMCP_HOME", "").strip()
    if fastmcp_home:
        fastmcp_settings.home = Path(fastmcp_home)
        client_storage = None  # GitHubProvider creates encrypted file store at settings.home
        print(f"OAuth storage: persistent (FASTMCP_HOME={fastmcp_home})", file=sys.stderr)
    else:
        client_storage = MemoryStore()
        print("OAuth storage: in-memory (set FASTMCP_HOME for persistent storage)", file=sys.stderr)

    # ── Build OAuth components ────────────────────────────────────────
    # OAuth 2.1 proxy: full DCR + PKCE + CIMD flow through GitHub OAuth App
    github_provider = LoginFilteredGitHubProvider(
        client_id=github_client_id,
        client_secret=github_client_secret,
        base_url=base_url,
        required_scopes=github_oauth_scopes,
        allowed_github_logins=allowed_github_logins,
        audit_logging_enabled=audit_logging_enabled,
        client_storage=client_storage,
    )

    # OAuth 2.0 raw token: direct GitHub token validation via API
    # Supports Power Automate and other clients that have a raw GitHub token
    raw_token_verifier = LoginFilteredGitHubTokenVerifier(
        required_scopes=github_oauth_scopes,
        allowed_github_logins=allowed_github_logins,
        audit_logging_enabled=audit_logging_enabled,
    )

    # ── Compose verifiers ─────────────────────────────────────────────
    verifiers: list = [raw_token_verifier]

    if need_token_auth:
        static_verifier = build_token_verifier(
            mcp_api_token=mcp_api_token,
            audit_logging_enabled=audit_logging_enabled,
        )
        verifiers.insert(0, static_verifier)

    # MultiAuth tries the server first, then each verifier in order.
    # Order: proxy (GitHubProvider) → static token → raw GitHub token
    #
    # required_scopes=[] disables the HTTP-layer scope gate on MultiAuth
    # itself so that every verifier can enforce its own scopes.  Without
    # this, MultiAuth inherits ["user"] from GitHubProvider  and rejects
    # static tokens (which only carry ["read"]) at the middleware level.
    return MultiAuth(
        server=github_provider,
        verifiers=verifiers,
        required_scopes=[],
    )

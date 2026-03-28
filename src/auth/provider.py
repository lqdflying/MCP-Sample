"""Auth provider setup.

Reads environment variables, validates them, and returns the configured
FastMCP auth provider (either DebugTokenVerifier or TokenOrGitHubOAuthProvider).
"""

import os
import sys

from .oauth import TokenOrGitHubOAuthProvider, normalize_oauth_scopes
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

    # ── Build provider ────────────────────────────────────────────────
    if need_oauth_auth:
        return TokenOrGitHubOAuthProvider(
            mcp_api_token=mcp_api_token if need_token_auth else None,
            allow_static_token=need_token_auth,
            allowed_github_logins=allowed_github_logins,
            audit_logging_enabled=audit_logging_enabled,
            client_id=github_client_id,
            client_secret=github_client_secret,
            base_url=base_url,
            required_scopes=github_oauth_scopes,
        )

    # Token-only mode
    return build_token_verifier(
        mcp_api_token=mcp_api_token,
        audit_logging_enabled=audit_logging_enabled,
    )

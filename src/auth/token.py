"""Static token authentication.

Provides a factory that builds a DebugTokenVerifier configured with a
constant-time comparison against MCP_API_TOKEN, plus optional audit logging.
"""

import hmac
import logging

from fastmcp.server.auth.providers.debug import DebugTokenVerifier

log = logging.getLogger("mcp")


def build_token_verifier(
    mcp_api_token: str,
    audit_logging_enabled: bool = False,
) -> DebugTokenVerifier:
    """Return a DebugTokenVerifier that validates against *mcp_api_token*.

    Uses ``hmac.compare_digest`` for constant-time comparison to prevent
    timing-based token oracle attacks.
    """

    def _validate(token: str) -> bool:
        valid = hmac.compare_digest(token, mcp_api_token)
        if audit_logging_enabled:
            if valid:
                log.info("AUTH success method=token")
            else:
                log.warning("AUTH failed method=token reason=invalid_or_expired")
        return valid

    return DebugTokenVerifier(
        validate=_validate,
        client_id="mcp-client",
        scopes=["read"],
    )

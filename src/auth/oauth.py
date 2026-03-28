"""GitHub OAuth authentication provider.

Implements RFC 8252 loopback-aware CIMD manager, GitHub OAuth scope
normalization, and the hybrid TokenOrGitHubOAuthProvider that accepts
either a static MCP_API_TOKEN or a GitHub OAuth token.
"""

import hmac
import logging
from urllib.parse import urlparse

from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.cimd import CIMDClientManager
from fastmcp.server.auth.providers.github import GitHubProvider, GitHubTokenVerifier

log = logging.getLogger("mcp")

# ── RFC 8252 loopback-aware CIMD manager ─────────────────────────────
# VS Code's CIMD document lists a fixed loopback port but sends a dynamic
# port at runtime. Per RFC 8252 §7.3 the port MUST be ignored for loopback
# redirect URIs. This manager normalizes fixed ports to wildcard patterns.

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _normalize_loopback_redirect_uris(redirect_uris: list[str]) -> list[str]:
    """Replace fixed loopback ports with :* wildcards per RFC 8252."""
    normalized = []
    for uri in redirect_uris:
        parsed = urlparse(uri.rstrip("/"))
        host = (parsed.hostname or "").lower()
        if host in _LOOPBACK_HOSTS and parsed.scheme == "http" and parsed.port:
            normalized.append(f"http://{host}:*/")
        else:
            normalized.append(uri)
    return normalized


_LOOPBACK_REDIRECT_PATTERNS = ["http://127.0.0.1:*/", "http://localhost:*/"]


class _RFC8252CIMDManager(CIMDClientManager):
    """CIMD manager that normalizes fixed loopback ports to wildcards (RFC 8252).

    Also supports pre-registered static client IDs for legacy MCP clients that
    do not use CIMD dynamic registration (e.g. older VS Code versions).
    """

    def __init__(self, *, static_client_ids: list[str] | None = None, **kwargs):
        super().__init__(**kwargs)
        self._static_client_ids: set[str] = set(static_client_ids or [])

    def is_cimd_client_id(self, client_id: str) -> bool:
        """Return True for static pre-registered IDs in addition to CIMD URLs."""
        return client_id in self._static_client_ids or super().is_cimd_client_id(client_id)

    async def get_client(self, client_id_url: str):
        # Pre-registered static client IDs (legacy clients without CIMD support).
        if client_id_url in self._static_client_ids:
            from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient

            patterns = self.allowed_redirect_uri_patterns or _LOOPBACK_REDIRECT_PATTERNS
            return ProxyDCRClient(
                client_id=client_id_url,
                client_secret=None,
                redirect_uris=None,
                scope=self.default_scope,
                allowed_redirect_uri_patterns=patterns,
                client_name=client_id_url,
            )

        client = await super().get_client(client_id_url)
        if client is None or client.cimd_document is None:
            return client

        doc = client.cimd_document
        if not doc.redirect_uris:
            return client

        normalized = _normalize_loopback_redirect_uris(doc.redirect_uris)
        if normalized != list(doc.redirect_uris):
            new_doc = doc.model_copy(update={"redirect_uris": normalized})
            client = client.model_copy(update={"cimd_document": new_doc})

        return client


# ── GitHub scope normalization ────────────────────────────────────────
# GitHub App tokens return only a broad parent scope (or nothing) via
# X-OAuth-Scopes. Normalize any child scope to its parent so the token
# check always uses the scope GitHub actually reports.

_GITHUB_CHILD_TO_PARENT: dict[str, str] = {
    "read:user": "user",
    "user:email": "user",
    "user:follow": "user",
    "public_repo": "repo",
    "repo:status": "repo",
    "repo:deployment": "repo",
    "repo:invite": "repo",
    "security_events": "repo",
    "read:org": "admin:org",
    "write:org": "admin:org",
    "read:repo_hook": "write:repo_hook",
    "write:repo_hook": "admin:repo_hook",
}


def normalize_oauth_scopes(scopes: list[str]) -> list[str]:
    """Map child scopes to their GitHub parent scope, removing duplicates."""
    seen: set[str] = set()
    result: list[str] = []
    for s in scopes:
        parent = _GITHUB_CHILD_TO_PARENT.get(s, s)
        if parent not in seen:
            seen.add(parent)
            result.append(parent)
    return result


# ── Hybrid auth provider ──────────────────────────────────────────────


class TokenOrGitHubOAuthProvider(GitHubProvider):
    """Accept either a shared static token or GitHub OAuth tokens.

    Keeps existing automation that uses MCP_API_TOKEN working while enabling
    Power Automate / VS Code OAuth flows on the same MCP endpoint.
    """

    def __init__(
        self,
        *,
        mcp_api_token: str | None,
        allow_static_token: bool,
        allowed_github_logins: set[str] | None = None,
        audit_logging_enabled: bool = False,
        **kwargs,
    ):
        # Capture client_id before passing to super — used to register it as a
        # static MCP client ID so legacy VS Code versions (which send the server's
        # GitHub OAuth App client_id instead of a CIMD URL) can authenticate.
        github_client_id: str | None = kwargs.get("client_id")
        super().__init__(**kwargs)
        self._mcp_api_token = mcp_api_token
        self._allow_static_token = allow_static_token
        self._allowed_github_logins = {login.lower() for login in (allowed_github_logins or set())}
        self._audit_logging_enabled = audit_logging_enabled

        # Replace the CIMD manager with an RFC 8252-aware version that:
        # 1. Normalizes fixed loopback ports to wildcards (RFC 8252 §7.3)
        # 2. Sets default_scope so CIMD clients that don't declare a scope
        #    (e.g. VS Code) are allowed to request the server's required scopes.
        # 3. Registers GITHUB_CLIENT_ID as a static client so legacy MCP clients
        #    (older VS Code) that send it as client_id instead of a CIMD URL work.
        if self._cimd_manager is not None:
            default_scope = " ".join(self.required_scopes) if self.required_scopes else None
            static_ids = [github_client_id] if github_client_id else None
            self._cimd_manager = _RFC8252CIMDManager(
                enable_cimd=True,
                default_scope=default_scope,
                allowed_redirect_uri_patterns=self._allowed_client_redirect_uris,
                static_client_ids=static_ids,
            )

    async def verify_token(self, token: str) -> AccessToken | None:
        # Step 1: Static MCP_API_TOKEN (constant-time compare).
        if (
            self._allow_static_token
            and self._mcp_api_token
            and hmac.compare_digest(token, self._mcp_api_token)
        ):
            if self._audit_logging_enabled:
                log.info("AUTH success method=token")
            return AccessToken(
                token=token,
                client_id="mcp-token-client",
                scopes=list(self.required_scopes) if self.required_scopes else ["read"],
                claims={"auth_mode": "static_token"},
            )

        # Step 2: FastMCP proxy token (VS Code, Copilot Studio via server proxy).
        access_token = await super().verify_token(token)

        # Step 3: Raw GitHub OAuth token (e.g. Power Automate custom connector
        # obtaining a token directly from GitHub rather than through the proxy).
        if access_token is None:
            raw_verifier = GitHubTokenVerifier(
                required_scopes=list(self.required_scopes) if self.required_scopes else None,
            )
            access_token = await raw_verifier.verify_token(token)
            if access_token is not None and self._audit_logging_enabled:
                login = access_token.claims.get("login")
                log.info(
                    f"AUTH token type=raw_github login={login if isinstance(login, str) else 'unknown'}"
                )

        if access_token is None:
            if self._audit_logging_enabled:
                log.warning("AUTH failed method=oauth_or_token reason=invalid_or_expired")
            return None

        if not self._allowed_github_logins:
            if self._audit_logging_enabled:
                login = access_token.claims.get("login")
                login_label = login if isinstance(login, str) else "unknown"
                log.info(f"AUTH success method=oauth login={login_label}")
            return access_token

        login = access_token.claims.get("login")
        if isinstance(login, str) and login.lower() in self._allowed_github_logins:
            if self._audit_logging_enabled:
                log.info(f"AUTH success method=oauth login={login}")
            return access_token

        if self._audit_logging_enabled:
            blocked_login = login if isinstance(login, str) else "unknown"
            log.warning(
                f"AUTH rejected method=oauth login={blocked_login} reason=login_not_allowlisted"
            )

        return None

"""GitHub OAuth authentication utilities.

Provides GitHub OAuth scope normalization helpers and factory functions for
building the GitHubProvider (OAuth 2.1 proxy flow) and GitHubTokenVerifier
(OAuth 2.0 raw token validation) used by MultiAuth.
"""

import logging

from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.providers.github import GitHubProvider, GitHubTokenVerifier

log = logging.getLogger("mcp")

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


# ── Login allowlist filtering ─────────────────────────────────────────
# GitHubProvider doesn't have a built-in login allowlist. We wrap the token
# verifier and the provider to check the GitHub login claim after successful
# verification.


class LoginFilteredGitHubTokenVerifier(GitHubTokenVerifier):
    """GitHubTokenVerifier that additionally checks the login claim against an allowlist.

    Delegates token verification to the upstream GitHub API via the parent
    GitHubTokenVerifier, then checks the returned ``login`` claim.  Tokens
    from non-allowlisted users are rejected even if they are otherwise valid.
    """

    def __init__(
        self,
        *,
        allowed_github_logins: set[str] | None = None,
        audit_logging_enabled: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._allowed_github_logins = {login.lower() for login in (allowed_github_logins or set())}
        self._audit_logging_enabled = audit_logging_enabled

    async def verify_token(self, token: str) -> AccessToken | None:
        access_token = await super().verify_token(token)
        if access_token is None:
            return None
        return _check_login_allowlist(
            access_token,
            allowed_logins=self._allowed_github_logins,
            audit_logging_enabled=self._audit_logging_enabled,
        )


class LoginFilteredGitHubProvider(GitHubProvider):
    """GitHubProvider that additionally checks the login claim against an allowlist.

    Wraps the OAuth 2.1 proxy flow's token verification with login filtering
    so that only allowlisted GitHub users can authenticate through the proxy.
    """

    def __init__(
        self,
        *,
        allowed_github_logins: set[str] | None = None,
        audit_logging_enabled: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._allowed_github_logins = {login.lower() for login in (allowed_github_logins or set())}
        self._audit_logging_enabled = audit_logging_enabled

    async def verify_token(self, token: str) -> AccessToken | None:
        access_token = await super().verify_token(token)
        if access_token is None:
            return None
        return _check_login_allowlist(
            access_token,
            allowed_logins=self._allowed_github_logins,
            audit_logging_enabled=self._audit_logging_enabled,
        )


def _check_login_allowlist(
    access_token: AccessToken,
    *,
    allowed_logins: set[str],
    audit_logging_enabled: bool,
) -> AccessToken | None:
    """Check the login claim against the allowlist.

    Returns the access token if the user is allowed or no allowlist is set.
    Returns None if the user is blocked.
    """
    if not allowed_logins:
        if audit_logging_enabled:
            login = access_token.claims.get("login")
            login_label = login if isinstance(login, str) else "unknown"
            log.info(f"AUTH success method=oauth login={login_label}")
        return access_token

    login = access_token.claims.get("login")
    if isinstance(login, str) and login.lower() in allowed_logins:
        if audit_logging_enabled:
            log.info(f"AUTH success method=oauth login={login}")
        return access_token

    if audit_logging_enabled:
        blocked_login = login if isinstance(login, str) else "unknown"
        log.warning(
            f"AUTH rejected method=oauth login={blocked_login} reason=login_not_allowlisted"
        )
    return None

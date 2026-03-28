"""Authentication modules for the GitHub Repo Reader MCP server.

- oauth.py   — RFC 8252 loopback CIMD, scope normalization, TokenOrGitHubOAuthProvider
- token.py   — Static token verifier factory (DebugTokenVerifier)
- provider.py — setup_auth() reads env vars and returns the configured provider
"""

from .provider import setup_auth, parse_bool

__all__ = ["setup_auth", "parse_bool"]

"""Authentication modules for the MCP Authentication Sample server.

- oauth.py   — Scope normalization, login-filtered GitHub providers (OAuth 2.1 proxy + 2.0 raw)
- token.py   — Static token verifier factory (DebugTokenVerifier)
- provider.py — setup_auth() reads env vars and returns the configured provider
"""

from .provider import setup_auth, parse_bool

__all__ = ["setup_auth", "parse_bool"]

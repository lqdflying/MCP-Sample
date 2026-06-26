"""Authentication modules for the MCP Authentication Sample server.

- oauth.py        — Scope normalization, login-filtered GitHub providers (OAuth 2.1 proxy + 2.0 raw)
- oauth_store.py  — MySQL-backed encrypted OAuth KV store
- token.py        — Per-user TokenStore + DbTokenVerifier + static fallback
- token_rotate.py — Background auto-rotation loop
- policy.py       — RBAC policy store (users, roles, MFA, audit)
- mfa.py          — TOTP + backup code helpers
- password_util.py— Secure password generation
- provider.py     — setup_auth() reads env vars and returns the configured provider
"""

from .provider import setup_auth, parse_bool
from .token import set_token_store_getter

__all__ = ["setup_auth", "parse_bool", "set_token_store_getter"]

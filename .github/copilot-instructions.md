# Copilot Instructions

## Project Overview

This is **MCP Authentication Sample** — a [FastMCP](https://github.com/jlowin/fastmcp) server demonstrating production-ready authentication, RBAC, and user management patterns for Model Context Protocol (MCP) servers. It supports both a **lightweight mode** (static token only) and a **full mode** (policy database with per-user tokens, 3-tier RBAC, MFA, token auto-rotation, and audit logging).

## Architecture

```
server.py                    — FastMCP server factory, lifespan, middleware, /health endpoint, tool registration
src/debug.py                 — Structured JSON logging, field redaction, trace IDs
src/crypto.py                — Fernet encrypt/decrypt using MCP_ENCRYPTION_KEY
src/auth/provider.py         — setup_auth(): reads env vars and composes the auth provider
src/auth/oauth.py            — Login-filtered GitHub OAuth (OAuth 2.1 proxy + OAuth 2.0 raw token)
src/auth/oauth_url.py        — Loopback URL normalization (https→http for local OAuth)
src/auth/oauth_store.py      — MySQL-backed Fernet-encrypted OAuth KV store
src/auth/token.py            — Per-user TokenStore + DbTokenVerifier + static token fallback
src/auth/token_rotate.py     — Background auto-rotation loop with advisory lock
src/auth/policy.py           — MySQL-backed RBAC policy store (users, roles, MFA, audit)
src/auth/mfa.py              — TOTP + backup code helpers (pyotp, segno)
src/auth/password_util.py    — Cryptographically secure password generation
src/notify/email.py          — Async SMTP email delivery
src/tools/sample_tools.py    — hello_world reference tool implementation
src/tools/__init__.py        — Re-exports tool functions for use in server.py
config/init.sql              — Reference schema for manual DB provisioning
tests/                       — pytest suite (asyncio mode)
docs/                        — Excalidraw architecture diagrams and OAuth callback guides
```

## Operational Modes

The server supports **two operational modes**:

### Lightweight Mode (no policy DB)
When `MCP_POLICY_DB_HOST` is unset. Static token auth only via `MCP_API_TOKEN`. Simple single-user deployments.

### Full Mode (with policy DB)
When `MCP_POLICY_DB_HOST` is set. Enables:
- Per-user API tokens (TokenStore + DbTokenVerifier)
- 3-tier RBAC: `admin` (full control), `useradmin` (manage users/tokens), `user` (MCP access only)
- MFA (TOTP + backup codes) for admin panel login
- Token auto-rotation with email notifications
- Encrypted OAuth session storage (survives restarts)
- Structured audit logging

## Authentication Modes

The server supports three auth modes via `MCP_AUTH_MODE`:

| Mode    | Description |
|---------|-------------|
| `token` | Static bearer token (`MCP_API_TOKEN`) or per-user DB tokens |
| `oauth` | GitHub OAuth only (OAuth 2.1 proxy + OAuth 2.0 raw token fallback) |
| `both`  | Accept either method on the same server (default) |

In `oauth` or `both` mode, the server composes a `MultiAuth` provider:
1. **GitHubProvider** (OAuth 2.1 proxy) — handles full DCR + PKCE + CIMD flow
2. **Static token verifier** — constant-time `hmac.compare_digest` comparison
3. **DbTokenVerifier** (per-user) — validates per-user tokens from the policy DB (when configured)
4. **GitHubTokenVerifier** (OAuth 2.0 raw) — validates pre-existing GitHub tokens via API

Both OAuth components are wrapped with login-allowlist filtering (`LoginFilteredGitHubProvider`, `LoginFilteredGitHubTokenVerifier`).

## Key Conventions

- **Server factory pattern**: `create_server()` in `server.py` is called only at startup, never at import time. This allows tool implementations to be imported and tested independently of auth setup.
- **Load dotenv first**: `load_dotenv()` runs before any other imports in `server.py` so `FASTMCP_*` env vars apply at FastMCP import time.
- **Tool separation**: Tool logic lives in `src/tools/` as plain async functions. Registration with `@mcp.tool(...)` happens inside `create_server()`.
- **Environment-driven config**: All auth and transport settings come from environment variables (see `.env.example`).
- **Structured JSON logging**: All logs are JSONL via `src/debug.py`. Use `debug_log()` for structured events; never log raw args or `str(e)` in production log lines.
- **Trace IDs**: Each tool call gets a UUID4 via `set_trace_id()` for correlating log entries across async contexts.
- **Field redaction**: SQL, tool arguments, errors, and tracebacks are auto-redacted in debug events (length + SHA fingerprint). Disable with `MCP_DEBUG_VERBOSE=true` for dev.
- **Audit logging**: Auth decisions are logged with method and login info (never token values) when `MCP_AUTH_AUDIT_LOG=true`.
- **Constant-time token comparison**: Static token auth uses `hmac.compare_digest` to prevent timing attacks.
- **GitHub scope normalization**: Child scopes (e.g., `read:user`) are mapped to their parent scope (e.g., `user`) since GitHub only reports parent scopes on tokens.
- **Loopback URL normalization**: `BASE_URL` is rewritten from `https://127.0.0.1` to `http://` for local OAuth (RFC 8252).

## Adding New Tools

1. Create a new async function in `src/tools/` (or add to `sample_tools.py`).
2. Re-export from `src/tools/__init__.py`.
3. Register in `create_server()` with `@mcp.tool(tags={...})`.
4. Add tests in `tests/` — tools can be tested without auth by importing directly.

## Tech Stack

- **Python 3.12+**
- **FastMCP** (≥3.3.1) — MCP server framework with built-in auth support
- **httpx** — async HTTP client (used by OAuth token verifiers)
- **aiomysql** — async MySQL driver (policy database)
- **cryptography** — Fernet encryption (MFA secrets, OAuth KV)
- **bcrypt** — password hashing for admin panel
- **pyotp + segno** — TOTP generation and QR codes for MFA
- **python-dotenv** — loads `.env` files
- **pytest + pytest-asyncio** — test runner (asyncio_mode = "auto")
- **ruff** — linter and formatter

## Development Commands

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .

# Start server
python server.py

# Docker
docker compose up --build
```

## Environment Variables

See `.env.example` for the full list. Key variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `MCP_AUTH_MODE` | No (default: `both`) | Auth mode: `token`, `oauth`, or `both` |
| `MCP_API_TOKEN` | When mode is `token`/`both` | Static bearer token |
| `GITHUB_CLIENT_ID` | When mode is `oauth`/`both` | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | When mode is `oauth`/`both` | GitHub OAuth App secret |
| `BASE_URL` | When mode is `oauth`/`both` | Public URL for OAuth callbacks |
| `ALLOWED_GITHUB_LOGINS` | No | Comma-separated allowlist of GitHub logins |
| `FASTMCP_HOME` | No | Writable dir for persistent OAuth storage |
| `MCP_STATELESS` | No (default: `true`) | Stateless HTTP transport mode |
| `MCP_DEBUG` | No (default: `false`) | Enable structured debug events via `debug_log()` |
| `MCP_DEBUG_VERBOSE` | No (default: `false`) | Disable field redaction in debug events (dev only) |
| `HOST` | No (default: `0.0.0.0`) | Server bind address |
| `PORT` | No (default: `8000`) | Server port |
| `MCP_POLICY_DB_HOST` | No | MySQL host for policy DB (enables full mode) |
| `MCP_POLICY_DB_PORT` | No (default: `3306`) | Policy DB port |
| `MCP_POLICY_DB_USER` | When DB configured | Policy DB username |
| `MCP_POLICY_DB_PASSWORD` | When DB configured | Policy DB password |
| `MCP_POLICY_DB_NAME` | No (default: `mcp_policy`) | Policy DB name |
| `MCP_ENCRYPTION_KEY` | When DB configured | Fernet key for MFA/OAuth encryption |
| `MCP_ADMIN_SEED` | No | GitHub login to seed as first admin |
| `MCP_TOKEN_ROTATE_LEAD_DAYS` | No (default: `7`) | Days before expiry to rotate |
| `MCP_TOKEN_ROTATE_POLL_SEC` | No (default: `3600`) | Rotation poll interval (seconds) |
| `MCP_SMTP_HOST` | No | SMTP server for email notifications |

## Guidelines for Changes

- Keep the auth layer decoupled from tool logic — tools should never import from `src/auth/`.
- Validate environment variables early in `setup_auth()` and exit with clear error messages on misconfiguration.
- Never log token values; only log auth outcomes (success/failure, method, login).
- Never log `str(e)` in production log lines — error messages from drivers may contain sensitive data.
- Use `parse_bool()` from `src/auth` for any new boolean env vars.
- Use `debug_log()` from `src/debug` for structured events; sensitive fields are auto-redacted.
- Run `pytest` and `ruff check .` before committing.
- The server uses `streamable-http` transport — do not change to SSE/stdio without discussion.

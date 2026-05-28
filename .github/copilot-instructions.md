# Copilot Instructions

## Project Overview

This is **MCP Authentication Sample** — a minimal [FastMCP](https://github.com/jlowin/fastmcp) server that demonstrates production-ready authentication patterns for Model Context Protocol (MCP) servers. The focus is on the auth layer; there is one sample tool (`hello_world_tool`) as a reference for adding new tools.

## Architecture

```
server.py                 — FastMCP server factory, middleware, /health endpoint, tool registration
src/auth/provider.py      — setup_auth(): reads env vars and composes the auth provider
src/auth/oauth.py         — Login-filtered GitHub OAuth (OAuth 2.1 proxy + OAuth 2.0 raw token)
src/auth/token.py         — Constant-time static token verifier (DebugTokenVerifier)
src/tools/sample_tools.py — hello_world reference tool implementation
src/tools/__init__.py     — Re-exports tool functions for use in server.py
tests/                    — pytest suite (asyncio mode)
docs/                     — Excalidraw architecture diagrams and OAuth callback guides
```

## Authentication Modes

The server supports three auth modes via `MCP_AUTH_MODE`:

| Mode    | Description |
|---------|-------------|
| `token` | Static bearer token only (`MCP_API_TOKEN`) |
| `oauth` | GitHub OAuth only (OAuth 2.1 proxy + OAuth 2.0 raw token fallback) |
| `both`  | Accept either method on the same server (default) |

In `oauth` or `both` mode, the server composes a `MultiAuth` provider:
1. **GitHubProvider** (OAuth 2.1 proxy) — handles full DCR + PKCE + CIMD flow
2. **Static token verifier** — constant-time `hmac.compare_digest` comparison
3. **GitHubTokenVerifier** (OAuth 2.0 raw) — validates pre-existing GitHub tokens via API

Both OAuth components are wrapped with login-allowlist filtering (`LoginFilteredGitHubProvider`, `LoginFilteredGitHubTokenVerifier`).

## Key Conventions

- **Server factory pattern**: `create_server()` in `server.py` is called only at startup, never at import time. This allows tool implementations to be imported and tested independently of auth setup.
- **Tool separation**: Tool logic lives in `src/tools/` as plain async functions. Registration with `@mcp.tool(...)` happens inside `create_server()`.
- **Environment-driven config**: All auth and transport settings come from environment variables (see `.env.example`).
- **Audit logging**: Auth decisions are logged with method and login info (never token values) when `MCP_AUTH_AUDIT_LOG=true`.
- **Constant-time token comparison**: Static token auth uses `hmac.compare_digest` to prevent timing attacks.
- **GitHub scope normalization**: Child scopes (e.g., `read:user`) are mapped to their parent scope (e.g., `user`) since GitHub only reports parent scopes on tokens.

## Adding New Tools

1. Create a new async function in `src/tools/` (or add to `sample_tools.py`).
2. Re-export from `src/tools/__init__.py`.
3. Register in `create_server()` with `@mcp.tool(tags={...})`.
4. Add tests in `tests/` — tools can be tested without auth by importing directly.

## Tech Stack

- **Python 3.12+**
- **FastMCP** (≥3.3.1) — MCP server framework with built-in auth support
- **httpx** — async HTTP client (used by OAuth token verifiers)
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
| `HOST` | No (default: `0.0.0.0`) | Server bind address |
| `PORT` | No (default: `8000`) | Server port |

## Guidelines for Changes

- Keep the auth layer decoupled from tool logic — tools should never import from `src/auth/`.
- Validate environment variables early in `setup_auth()` and exit with clear error messages on misconfiguration.
- Never log token values; only log auth outcomes (success/failure, method, login).
- Use `parse_bool()` from `src/auth` for any new boolean env vars.
- Run `pytest` and `ruff check .` before committing.
- The server uses `streamable-http` transport — do not change to SSE/stdio without discussion.

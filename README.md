# MCP Authentication Sample

A minimal **FastMCP** server that demonstrates a production-ready authentication
architecture for MCP servers. It ships with one sample tool (`hello_world_tool`)
so the focus stays on the auth layer.

Supported auth modes:

- **token** — static bearer token (`MCP_API_TOKEN`)
- **oauth** — GitHub OAuth (OAuth 2.1 proxy + OAuth 2.0 raw token verifier)
- **both** — accept either method on the same server (default)

GitHub OAuth includes an optional **login allowlist** so you can restrict access
to specific GitHub users, and a structured **audit log** for every auth decision.

## Project layout

```
server.py                 — FastMCP server factory, middleware, /health, sample tool
src/debug.py              — Structured JSON logging, field redaction, trace IDs
src/auth/provider.py      — setup_auth() reads env vars and builds the auth provider
src/auth/oauth.py         — Login-filtered GitHubProvider + GitHubTokenVerifier
src/auth/oauth_url.py     — Loopback URL normalization (https→http for local OAuth)
src/auth/token.py         — Constant-time static token verifier
src/tools/sample_tools.py — hello_world reference tool
tests/                    — pytest suite for the sample tool
docs/                     — Architecture diagrams (excalidraw) and OAuth callback notes
```

## Quick start

```bash
git clone <this-repo-url>
cd MCP-Sample
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

Edit `.env` and set at minimum:

```env
MCP_AUTH_MODE=token
MCP_API_TOKEN=your_secret_mcp_token_here
```

Start the server:

```bash
python server.py
```

Health check:

```bash
curl http://localhost:8000/health
```

## Enabling GitHub OAuth

Register a [GitHub OAuth App](https://github.com/settings/developers) with the
callback URL `${BASE_URL}/auth/callback`, then set:

```env
MCP_AUTH_MODE=both
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
BASE_URL=https://your-public-host.example.com
GITHUB_OAUTH_SCOPES=read:user
ALLOWED_GITHUB_LOGINS=your-github-login
```

See [`docs/github-oauth-callback-guide.md`](docs/github-oauth-callback-guide.md)
and [`docs/oauth-callback-workflows.md`](docs/oauth-callback-workflows.md) for
the callback flow.

## Structured JSON Logging

All logs are emitted as JSONL (one JSON object per line) to stderr. Each tool
call gets a UUID4 trace ID for correlating log entries across async contexts.

Set `MCP_DEBUG=true` to enable structured debug events (tool call start/end,
auth decisions). Sensitive fields (SQL, args, errors, tracebacks) are
automatically redacted with a length + SHA fingerprint. Set
`MCP_DEBUG_VERBOSE=true` to disable redaction for local development.

The logging middleware never includes raw tool arguments or `str(e)` in
production log lines — only the exception type is logged to prevent leaking
sensitive data from downstream services.

## Loopback URL Normalization

When `BASE_URL` points to a loopback address (`127.0.0.1`, `localhost`, `::1`),
the `https://` scheme is automatically rewritten to `http://` per RFC 8252.
This handles VS Code / Cursor port-forwarding scenarios where the IDE exposes
the server as HTTPS but the local listener only supports HTTP.

## Adding your own tools

`src/tools/sample_tools.py` is the template — define an `async` function and
re-export it from `src/tools/__init__.py`. Then register it inside
`create_server()` in `server.py` with `@mcp.tool(...)`.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Docker

```bash
docker compose up --build
```

## Tech stack

- **Python 3.12+**
- **FastMCP** ≥ 3.3.1 — MCP server framework with built-in OAuth 2.1 proxy support
- **httpx** — async HTTP client (GitHub token verification)
- **python-dotenv** — loads `.env` files
- **pytest + pytest-asyncio** — test runner
- **ruff** — linter and formatter

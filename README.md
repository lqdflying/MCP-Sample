# MCP Authentication Sample

A minimal **FastMCP** server demonstrating a well-designed authentication architecture. This project serves as a reference implementation showing how to build MCP servers with production-ready authentication patterns.

The sample includes a single `hello_world` tool to demonstrate the basic tool structure, while the focus is on the authentication layer.

---

## Table of Contents

- [Authentication Architecture](#authentication-architecture)
- [Auth Modes](#auth-modes)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Running the Server](#running-the-server)
- [Docker Deployment](#docker-deployment)
- [Environment Variables Reference](#environment-variables-reference)
- [Architecture](#architecture)
- [Development](#development)

---

## Authentication Architecture

There are **two separate and independent authentication layers**:

```
MCP Client (VS Code / Copilot Studio / any MCP client)
        │
        │  Layer 1 — "Who are you?"
        │  Proved by: MCP_API_TOKEN (static)
        │              or GitHub OAuth token
        ▼
MCP Server (this server)
        │
        │  Layer 2 — "Access your resources"
        │  (Application-specific; not shown here)
        ▼
Application
```

### Auth Modes

| `MCP_AUTH_MODE` | Who can connect | Best for |
|-----------------|----------------|---------|
| `token` | Anyone with the `MCP_API_TOKEN` value | Local / trusted environments |
| `oauth` | GitHub accounts listed in `ALLOWED_GITHUB_LOGINS` | Remote deployments requiring identity |
| `both` *(default)* | Either token or GitHub OAuth | Supporting multiple client types simultaneously |

---

## Prerequisites

- **Python 3.12+** (direct) or **Docker** (containerised)
- For OAuth mode: A **GitHub App** registered in [GitHub Settings](https://github.com/settings/apps)

---

## Setup

### 1. Clone and install

```bash
git clone <this-repo-url>
cd MCP-Sample
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

### 2. Create your `.env`

```bash
cp .env.example .env
```

Edit `.env` based on your chosen auth mode (see below).

---

## Running the Server

### Option A — Static token (simplest)

Best for local development or trusted environments.

```env
MCP_AUTH_MODE=token
MCP_API_TOKEN=your_secret_token_here
```

```bash
python server.py
```

Connect clients using:
```json
{
  "servers": {
    "mcp-sample": {
      "type": "http",
      "url": "http://localhost:8000/mcp",
      "headers": {
        "Authorization": "Bearer your_secret_token_here"
      }
    }
  }
}
```

### Option B — GitHub OAuth (remote deployments)

Best for production deployments where you want GitHub identity verification.

**Step 1 — Create a GitHub App**

1. Go to **[GitHub → Settings → Developer Settings → GitHub Apps](https://github.com/settings/apps/new)**
2. Fill in:
   - **GitHub App name**: e.g. `my-mcp-auth-sample` (globally unique)
   - **Homepage URL**: your server URL, e.g. `https://your-domain`
   - **Callback URL**: `https://your-domain/auth/callback`
   - **Webhook**: uncheck **Active**
3. Under **Account permissions**: **Email addresses** → Read-only, **Profile** → Read-only
4. **Where can this GitHub App be installed?** → **Only on this account**
5. Click **Create GitHub App**, note the **Client ID**, and generate a **client secret**

**Step 2 — Configure `.env`**

```env
MCP_AUTH_MODE=oauth
GITHUB_CLIENT_ID=your_github_app_client_id
GITHUB_CLIENT_SECRET=your_github_app_client_secret
BASE_URL=https://your-domain
ALLOWED_GITHUB_LOGINS=your-github-username
```

### Option C — Both token and OAuth simultaneously

```env
MCP_AUTH_MODE=both
MCP_API_TOKEN=your_secret_token_here
GITHUB_CLIENT_ID=your_github_app_client_id
GITHUB_CLIENT_SECRET=your_github_app_client_secret
BASE_URL=https://your-domain
ALLOWED_GITHUB_LOGINS=your-github-username
```

---

## Docker Deployment

### 1. Prepare the environment file

```bash
cp .env.example .env
# Edit .env with your auth configuration
```

Example `.env` for dual auth:

```env
MCP_AUTH_MODE=both
MCP_AUTH_AUDIT_LOG=true
MCP_API_TOKEN=your_secret_mcp_token_here
GITHUB_CLIENT_ID=your_oauth_client_id
GITHUB_CLIENT_SECRET=your_oauth_client_secret
BASE_URL=https://your-domain
ALLOWED_GITHUB_LOGINS=your-github-username
HOST=0.0.0.0
PORT=8000
```

### 2. Start with Docker Compose

```bash
docker compose up -d          # start in background
docker compose logs -f        # follow logs
docker compose down           # stop
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MCP_AUTH_MODE` | No | `both` | `token` — static token only; `oauth` — GitHub OAuth only; `both` — either method accepted. **Note: `both` requires all three OAuth vars (`GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `BASE_URL`).** |
| `MCP_AUTH_AUDIT_LOG` | No | `true` | Log auth decisions (method, login, allowlist result). Never logs token values. |
| `MCP_API_TOKEN` | Conditional | — | Required when `MCP_AUTH_MODE=token` or `both`. The shared secret clients send as a Bearer token. |
| `GITHUB_CLIENT_ID` | Conditional | — | GitHub App client ID. Required when OAuth is enabled. |
| `GITHUB_CLIENT_SECRET` | Conditional | — | GitHub App client secret. Required when OAuth is enabled. |
| `BASE_URL` | Conditional | — | Public HTTPS URL of this server. Required when OAuth is enabled. |
| `ALLOWED_GITHUB_LOGINS` | **Strongly recommended** | *(empty = allow all)* | Comma-separated GitHub usernames permitted for OAuth. **Empty means any GitHub account can sign in.** |
| `MCP_STATELESS` | No | `true` | `true` — stateless mode (default, recommended). `false` — stateful mode with SSE event replay via Redis. |
| `UPSTASH_REDIS_REST_URL` | When `MCP_STATELESS=false` | — | Upstash Redis URL. |
| `UPSTASH_REDIS_REST_TOKEN` | When `MCP_STATELESS=false` | — | Upstash Redis token. |
| `HOST` | No | `0.0.0.0` | Network interface to bind to |
| `PORT` | No | `8000` | Port to listen on |

---

## Architecture

```
server.py                    ← FastMCP entry point; auth setup + hello_world sample tool
src/
└── auth/
    ├── __init__.py          ← Exports setup_auth(), parse_bool()
    ├── oauth.py            ← RFC 8252 loopback CIMD, scope normalization, TokenOrGitHubOAuthProvider
    ├── token.py            ← Static token verifier factory (DebugTokenVerifier)
    └── provider.py         ← setup_auth() reads env vars and returns configured provider
tests/
├── conftest.py              ← Shared test fixtures
└── test_hello_world.py     ← Tests for the sample tool
```

### Auth Code Structure

The authentication implementation in `src/auth/` handles:

1. **`provider.py`** — `setup_auth()` reads `MCP_AUTH_MODE` and returns the appropriate FastMCP auth provider
2. **`oauth.py`** — RFC 8252 compliant OAuth 2.0 loopback redirect, GitHub scope normalization, and `TokenOrGitHubOAuthProvider` that tries token first then falls back to OAuth
3. **`token.py`** — `build_token_verifier()` factory creating a constant-time comparison verifier using HMAC

### Adding Your Own Tools

Tools follow this pattern:

```python
@mcp.tool(tags={"category"})
async def my_tool(param: str, optional_param: str | None = None) -> str:
    """Tool description.

    Args:
        param: Description of param.
        optional_param: Optional parameter description.
    """
    # Your implementation
    return result
```

The `@mcp.tool()` decorator registers the function as an MCP tool. Tags are used for filtering, and the docstring becomes the tool description.

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/

# Run a single test
pytest tests/test_hello_world.py

# Lint and format
ruff check .
ruff format .
```

---

## License

MIT

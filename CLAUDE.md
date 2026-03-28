# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run the server
python server.py

# Run all tests
pytest tests/

# Run a single test file
pytest tests/test_file_ops.py

# Run a single test
pytest tests/test_file_ops.py::test_read_file_success

# Lint and format
ruff check .
ruff format .
```

## Environment

`GITHUB_PAT` is always required. Auth-mode variables determine what else is needed:

| Variable | Required | Description |
|---|---|---|
| `GITHUB_PAT` | Always | GitHub PAT. **Read-only tools**: classic `public_repo`/`repo`; fine-grained `Contents: Read` + `Metadata: Read`. **Write tools**: classic `repo`; fine-grained `Contents: Read+Write` + `Metadata: Read` + `Pull requests: Read+Write` + `Actions: Read+Write` + `Issues: Read+Write` + `Workflows: Read+Write` |
| `MCP_READ_ONLY` | No (default: `false`) | `true` = disable all write/PR/CI tools at startup (safe for read-only PATs) |
| `MCP_AUTH_MODE` | No (default: `both`) | `token` \| `oauth` \| `both` |
| `MCP_API_TOKEN` | When mode is `token` or `both` | Static bearer token for clients |
| `GITHUB_CLIENT_ID` | When mode is `oauth` or `both` | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | When mode is `oauth` or `both` | GitHub OAuth App client secret |
| `BASE_URL` | When mode is `oauth` or `both` | Public URL of this server (for OAuth callbacks) |
| `GITHUB_OAUTH_SCOPES` | No (default: `read:user`) | Comma-separated OAuth scopes |
| `ALLOWED_GITHUB_LOGINS` | No | Comma-separated GitHub logins allowed via OAuth; empty = all users |
| `MCP_AUTH_AUDIT_LOG` | No (default: `true`) | Log auth decisions (never logs token values) |
| `MCP_STATELESS` | No (default: `true`) | `true` = stateless (survives restarts, recommended); `false` = stateful SSE replay via Redis (requires Upstash vars) |
| `UPSTASH_REDIS_REST_URL` | When `MCP_STATELESS=false` | Upstash REST URL, e.g. `https://host.upstash.io`; both vars required |
| `UPSTASH_REDIS_REST_TOKEN` | When `MCP_STATELESS=false` | Upstash REST token; both vars required |
| `HOST` | No (default: `0.0.0.0`) | Bind address |
| `PORT` | No (default: `8000`) | Bind port |

Copy `.env.example` to `.env` and fill in values before running.

## Architecture

```
server.py                    ← FastMCP entry point; 29 MCP tool definitions (14 read + 15 write/todo)
src/
├── github_client.py         ← Async REST + GraphQL client (httpx); the only place that calls GitHub API
├── cache.py                 ← Two shared TTLCache instances: tree_cache (5 min), file_cache (2 min)
├── auth/
│   ├── __init__.py          ← Exports setup_auth(), parse_bool()
│   ├── provider.py          ← setup_auth(): reads env vars, validates, returns configured provider
│   ├── oauth.py             ← RFC 8252 CIMD, scope normalization, TokenOrGitHubOAuthProvider
│   └── token.py             ← build_token_verifier() factory (DebugTokenVerifier + hmac)
└── tools/
    ├── file_ops.py          ← read_file, list_directory, find_files
    ├── code_search.py       ← search_code, get_file_summary
    ├── git_ops.py           ← list_branches, get_commits, get_diff, get_blame, get_file_history
    ├── repo_info.py         ← get_repo_info, get_repo_structure, get_languages, get_rate_limit
    ├── write_ops.py         ← create_branch, push_files, delete_file, list_workflow_runs, get_workflow_run_logs, trigger_workflow
    ├── pr_ops.py            ← create_pull_request, list_pull_requests, get_pull_request, merge_pull_request, add_pr_comment, create_issue
    └── todo_ops.py          ← todo_write, todo_read, todo_update (in-session task tracking)
tests/
├── conftest.py              ← Shared mock_client fixture (AsyncMock of GitHubClient)
└── test_*.py                ← Unit tests per tool module
```

### Two-layer tool pattern

`server.py` contains thin `@mcp.tool()` wrappers that validate nothing — they just call `_get_client()` and delegate to a pure async function in `src/tools/`. All real logic lives in the tool modules. This keeps tools independently testable without FastMCP.

### GitHubClient

A single `GitHubClient` instance is created at startup (lifespan) and accessed via `_get_client()`. It wraps:
- REST calls via `self._http` (httpx.AsyncClient with `api.github.com` base URL)
- GraphQL calls via `self._graphql_http` (used only for blame)
- Rate limit tracking — updated from response headers on every call

Files > 1 MB are fetched via the Git Blobs API (`get_blob`) instead of the Contents API. The `get_full_tree` helper resolves branch/tag names through the refs API before fetching the recursive tree.

### Caching

`tree_cache` and `file_cache` in `src/cache.py` are module-level singletons shared across all tool calls. Cache keys use the pattern `"tree:{owner}/{repo}:{ref}"`. The TTLCache is not thread-safe but that is acceptable for the async single-process server model.

### Search strategy

`search_code` uses two paths: simple text queries on the default branch go to GitHub's Search API (subject to 30 req/min rate limit); regex patterns or branch-specific searches fetch files locally and search with Python `re`.

### Auth

`MCP_AUTH_MODE` controls which authentication methods are accepted:

- **`token`** — static `MCP_API_TOKEN` only; uses FastMCP's `DebugTokenVerifier`
- **`oauth`** — GitHub OAuth only; uses FastMCP's `GitHubProvider`
- **`both`** (default) — `TokenOrGitHubOAuthProvider` tries static token first (constant-time compare via `hmac.compare_digest`), then falls back to GitHub OAuth

`ALLOWED_GITHUB_LOGINS` (when set) restricts OAuth sign-in to specific GitHub accounts. The `/health` endpoint is unauthenticated.

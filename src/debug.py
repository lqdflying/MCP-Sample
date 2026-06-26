"""Structured JSON logging for MCP servers.

All loggers that propagate to the root logger emit one JSON object per line to stderr
(JSONL). MCP_DEBUG=true enables additional structured debug events via debug_log();
it does not switch JSON on or off.

HTTP access lines (uvicorn.access) are JSON when Uvicorn starts with log_config=None;
see UVICORN_JSON_LOGGING_CONFIG and server.py.

Each tool call gets a UUID4 trace_id via ContextVar for correlating log entries.

By default, sensitive fields in debug events are redacted (truncated + fingerprinted).
Set MCP_DEBUG_VERBOSE=true to log full content (dev/staging only).

Usage in instrumented modules:
    from src.debug import debug_log, get_trace_id
    debug_log("tool_call_start", tool=name, args=args)
"""

import hashlib
import json
import logging
import re
import sys
import traceback as tb_module
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

_trace_id: ContextVar[str | None] = ContextVar("_trace_id", default=None)
_debug_enabled: bool = False
_debug_verbose: bool = False

# Fields that contain SQL and should be redacted when not verbose
_SQL_FIELDS = frozenset({
    "sql", "sql_original", "sql_cleaned", "sql_input", "sql_output",
})
# Fields that contain tool arguments (dict) to redact
_ARGS_FIELDS = frozenset({"args"})
# Fields that may contain error messages with embedded sensitive data
_ERROR_FIELDS = frozenset({"error", "traceback"})

# Extract leading SQL keyword — only allowlisted keywords are preserved in logs.
_SQL_TYPE_RE = re.compile(r"^\s*(\w+)", re.IGNORECASE)
_KNOWN_SQL_KEYWORDS = frozenset({
    "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "WITH", "SET",
    "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "TRUNCATE",
    "GRANT", "REVOKE", "CALL", "EXECUTE", "BEGIN", "COMMIT", "ROLLBACK",
})


def is_debug_enabled() -> bool:
    return _debug_enabled


def is_verbose() -> bool:
    return _debug_verbose


def get_trace_id() -> str | None:
    return _trace_id.get()


def set_trace_id(tid: str | None = None) -> str:
    """Set trace_id for the current async context. Generates a new UUID4 if None."""
    if tid is None:
        tid = uuid.uuid4().hex
    _trace_id.set(tid)
    return tid


def clear_trace_id() -> None:
    _trace_id.set(None)


def _fingerprint(value: str) -> str:
    """Return a short SHA256 fingerprint for correlation."""
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _redact_sql(sql: str) -> str:
    """Replace SQL content with statement type + length + fingerprint.

    Example: 'SELECT * FROM users WHERE email = 'x'' → 'SELECT <len=43 sha=a1b2c3d4e5f6>'
    Only allowlisted SQL keywords are preserved; anything else becomes UNKNOWN.
    """
    if not isinstance(sql, str):
        return sql
    m = _SQL_TYPE_RE.match(sql)
    if m and m.group(1).upper() in _KNOWN_SQL_KEYWORDS:
        stmt_type = m.group(1).upper()
    else:
        stmt_type = "UNKNOWN"
    return f"{stmt_type} <len={len(sql)} sha={_fingerprint(sql)}>"


def _redact_value(value: str) -> str:
    """Replace a string value with its type + length + fingerprint."""
    return f"<str len={len(value)} sha={_fingerprint(value)}>"


def _redact_error(error: str) -> str:
    """Redact error messages that may contain sensitive data."""
    return f"<error len={len(error)} sha={_fingerprint(error)}>"


def _redact_traceback(tb: str | list) -> str:
    """Redact traceback — may contain sensitive data in frame locals."""
    text = tb if isinstance(tb, str) else "\n".join(tb)
    return f"<traceback len={len(text)} sha={_fingerprint(text)}>"


def _redact_args(args: dict) -> dict:
    """Redact arg values that may contain user data."""
    if not isinstance(args, dict):
        return args
    redacted = {}
    for k, v in args.items():
        if k in _SQL_FIELDS and isinstance(v, str):
            redacted[k] = _redact_sql(v)
        elif isinstance(v, str) and len(v) > 50:
            redacted[k] = _redact_value(v)
        else:
            redacted[k] = v
    return redacted


def _maybe_redact(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Apply redaction to known sensitive fields unless verbose mode is on."""
    if _debug_verbose:
        return kwargs
    result = {}
    for k, v in kwargs.items():
        if k in _SQL_FIELDS and isinstance(v, str):
            result[k] = _redact_sql(v)
        elif k in _ARGS_FIELDS and isinstance(v, dict):
            result[k] = _redact_args(v)
        elif k == "error" and isinstance(v, str):
            result[k] = _redact_error(v)
        elif k == "traceback" and isinstance(v, (str, list)):
            result[k] = _redact_traceback(v)
        else:
            result[k] = v
    return result


def debug_log(event: str, *, level: int = logging.DEBUG, **kwargs: Any) -> None:
    """Emit a structured debug log entry. No-op when debug is disabled.

    Fields in _SQL_FIELDS, _ARGS_FIELDS, and _ERROR_FIELDS are redacted by default.
    Set MCP_DEBUG_VERBOSE=true for full content.
    """
    if not _debug_enabled:
        return
    redacted = _maybe_redact(kwargs)
    logger = logging.getLogger("mcp.debug")
    logger.log(level, "", extra={"_event": event, "_fields": redacted})


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects (JSONL/ndjson)."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "trace_id": _trace_id.get(),
            "module": record.name,
        }

        # Structured event from debug_log()
        event = getattr(record, "_event", None)
        if event:
            entry["event"] = event
            fields = getattr(record, "_fields", {})
            entry.update(fields)
        else:
            # Regular log message
            entry["event"] = "log"
            msg = record.getMessage()
            if msg:
                entry["message"] = msg

        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            entry["error"] = str(record.exc_info[1])
            entry["error_type"] = record.exc_info[0].__name__
            entry["traceback"] = tb_module.format_exception(*record.exc_info)

        return json.dumps(entry, default=str, ensure_ascii=False)


# Pass to FastMCP mcp.run(uvicorn_config=...) so uvicorn loggers propagate to root
# JsonFormatter instead of Uvicorn's plain-text AccessFormatter / dictConfig.
UVICORN_JSON_LOGGING_CONFIG: dict[str, Any] = {"log_config": None}


def _wire_fastmcp_loggers_to_root() -> None:
    """Route FastMCP loggers through root JsonFormatter (Rich handlers attach at import)."""
    for name in list(logging.Logger.manager.loggerDict):
        if name == "fastmcp" or name.startswith("fastmcp."):
            lg = logging.getLogger(name)
            lg.handlers.clear()
            lg.propagate = True


def setup_debug_logging(enabled: bool, verbose: bool = False) -> None:
    """Configure root logging to JSON (JSONL on stderr).

    JSON formatting applies in both modes. When enabled=True, the mcp.debug
    logger emits DEBUG structured events via debug_log(). When enabled=False, only
    normal INFO+ log lines (no debug_log events). Root stays at INFO to suppress
    third-party DEBUG noise.

    Uvicorn HTTP access/error lines are JSON only if the server starts with
    UVICORN_JSON_LOGGING_CONFIG (log_config=None); see server.py.
    FastMCP loggers are rewired to propagate to root (see _wire_fastmcp_loggers_to_root).
    When verbose=True, fields in debug events are unredacted (dev/staging).
    """
    global _debug_enabled, _debug_verbose
    _debug_enabled = enabled
    _debug_verbose = verbose

    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    # Root stays at INFO — suppresses third-party DEBUG noise
    root.setLevel(logging.INFO)

    # Our debug logger gets DEBUG level when enabled
    debug_logger = logging.getLogger("mcp.debug")
    if enabled:
        debug_logger.setLevel(logging.DEBUG)
    else:
        debug_logger.setLevel(logging.WARNING)

    _wire_fastmcp_loggers_to_root()

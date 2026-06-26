"""SMTP email delivery.

Configuration is read from environment variables (no secrets stored in DB):

    MCP_SMTP_HOST        SMTP server hostname (required to enable email)
    MCP_SMTP_PORT        SMTP port (default 587)
    MCP_SMTP_USERNAME    SMTP auth username (optional)
    MCP_SMTP_PASSWORD    SMTP auth password (optional)
    MCP_SMTP_FROM        From address (default: MCP_SMTP_USERNAME)
    MCP_SMTP_FROM_NAME   From display name (default "MCP Server")
    MCP_SMTP_STARTTLS    Use STARTTLS (default true)
    MCP_SMTP_SSL         Use implicit TLS / SMTPS (default false)
    MCP_SMTP_TIMEOUT     Socket timeout seconds (default 10)

smtplib is blocking, so the actual send runs in a worker thread via
asyncio.to_thread to avoid blocking the event loop.
"""

import asyncio
import logging
import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr

log = logging.getLogger(__name__)


class EmailNotConfigured(RuntimeError):
    """Raised when an email send is attempted but SMTP is not configured."""


def _parse_bool(value: str, default: bool) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class SMTPConfig:
    host: str
    port: int
    username: str
    password: str
    from_addr: str
    from_name: str
    starttls: bool
    use_ssl: bool
    timeout: float


def smtp_config() -> SMTPConfig | None:
    """Build SMTPConfig from the environment, or None if host is unset."""
    host = os.environ.get("MCP_SMTP_HOST", "").strip()
    if not host:
        return None
    username = os.environ.get("MCP_SMTP_USERNAME", "").strip()
    from_addr = os.environ.get("MCP_SMTP_FROM", "").strip() or username
    try:
        port = int(os.environ.get("MCP_SMTP_PORT", "587").strip() or "587")
    except ValueError:
        port = 587
    try:
        timeout = float(os.environ.get("MCP_SMTP_TIMEOUT", "10").strip() or "10")
    except ValueError:
        timeout = 10.0
    return SMTPConfig(
        host=host,
        port=port,
        username=username,
        password=os.environ.get("MCP_SMTP_PASSWORD", ""),
        from_addr=from_addr,
        from_name=os.environ.get("MCP_SMTP_FROM_NAME", "MCP Server").strip() or "MCP Server",
        starttls=_parse_bool(os.environ.get("MCP_SMTP_STARTTLS", ""), default=True),
        use_ssl=_parse_bool(os.environ.get("MCP_SMTP_SSL", ""), default=False),
        timeout=timeout,
    )


def smtp_configured() -> bool:
    """Return True if a usable SMTP configuration is present."""
    cfg = smtp_config()
    return cfg is not None and bool(cfg.from_addr)


def _send_sync(cfg: SMTPConfig, to_addr: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((cfg.from_name, cfg.from_addr))
    msg["To"] = to_addr
    msg.set_content(body)

    context = ssl.create_default_context()
    if cfg.use_ssl:
        server = smtplib.SMTP_SSL(
            cfg.host, cfg.port, timeout=cfg.timeout, context=context
        )
    else:
        server = smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout)
    try:
        server.ehlo()
        if cfg.starttls and not cfg.use_ssl:
            server.starttls(context=context)
            server.ehlo()
        if cfg.username:
            server.login(cfg.username, cfg.password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


async def send_email(to_addr: str, subject: str, body: str) -> None:
    """Send a plaintext email. Raises EmailNotConfigured if SMTP is not set up."""
    cfg = smtp_config()
    if cfg is None or not cfg.from_addr:
        raise EmailNotConfigured(
            "SMTP is not configured. Set MCP_SMTP_HOST (and MCP_SMTP_FROM)."
        )
    await asyncio.to_thread(_send_sync, cfg, to_addr, subject, body)
    log.info("Sent email to %s (subject=%r)", to_addr, subject)

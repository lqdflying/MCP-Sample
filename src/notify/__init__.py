"""Outbound notifications (email/SMTP)."""

from src.notify.email import (
    EmailNotConfigured,
    SMTPConfig,
    send_email,
    smtp_config,
    smtp_configured,
)

__all__ = [
    "EmailNotConfigured",
    "SMTPConfig",
    "send_email",
    "smtp_config",
    "smtp_configured",
]

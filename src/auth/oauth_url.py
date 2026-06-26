"""OAuth URL helpers — loopback scheme normalization for local clients."""

from urllib.parse import urlparse, urlunparse

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def normalize_loopback_oauth_url(url: str) -> str:
    """Rewrite https loopback origins to http; leave public HTTPS URLs unchanged.

    VS Code / Cursor port-forwarding can expose the server as https://127.0.0.1
    while the local server only listens on HTTP. OAuth redirect URIs must use http
    for loopback hosts per RFC 8252.
    """
    trimmed = url.strip()
    if not trimmed:
        return trimmed

    parsed = urlparse(trimmed)
    if parsed.scheme != "https":
        return trimmed

    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        return trimmed

    return urlunparse(parsed._replace(scheme="http"))

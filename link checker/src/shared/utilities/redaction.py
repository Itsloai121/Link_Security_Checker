"""Privacy by design (USSA pillars 05 and 11): submitted URLs may carry tokens or personal data.

Logs and metrics therefore record only a redacted form (scheme + host), never path, query or credentials.
"""
from __future__ import annotations

import re

_AUTH = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):(?://|\\\\|/)*(?:[^/\\?#@]*@)?([^/\\?#]*)")


def redact_url(raw: str, limit: int = 120) -> str:
    """'https://user:pw@host.tld/a?token=1' -> 'https://host.tld/…'. Never raises."""
    try:
        m = _AUTH.match(raw.strip())
        if not m:
            return "<unparsed>"
        scheme, host = m.group(1).lower(), m.group(2)
        out = f"{scheme}://{host}/…" if scheme in {"http", "https", "ftp"} else f"{scheme}:<redacted>"
        return out[:limit]
    except Exception:  # pragma: no cover - defensive
        return "<unparsed>"

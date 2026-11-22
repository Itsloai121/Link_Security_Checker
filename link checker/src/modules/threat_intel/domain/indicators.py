"""Threat indicators and feed parsing - pure functions, no I/O (USDA §4: feed data is derived and rebuildable)."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

KINDS = ("url", "host", "cidr", "asn")
CATEGORIES = ("phishing", "malware", "scam", "abuse", "unknown")
FORMATS = ("urls", "hosts", "cidr_json_lines", "cidr_text", "asn_json_lines", "asn_text")
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z0-9-]{2,63}$")


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str
    category: str = "unknown"


@dataclass(frozen=True)
class FeedDefinition:
    name: str
    title: str
    url: str
    format: str
    kind: str
    category: str
    min_expected: int = 1
    max_bytes: int = 10_000_000
    terms: str = ""
    terms_url: str = ""
    attribution: str = ""


@dataclass(frozen=True)
class IndicatorHit:
    source: str
    kind: str
    value: str
    category: str
    loaded_at: str


@dataclass(frozen=True)
class ParsedFeed:
    indicators: tuple[Indicator, ...]
    rejected_lines: int


def normalize_url(raw: str) -> str | None:
    """Canonical form for matching: lower-case scheme+host, no default port, no fragment, no userinfo. None if not http(s)."""
    try:
        p = urlsplit(raw.strip())
        if p.scheme.lower() not in ("http", "https") or not p.hostname:
            return None
        host = p.hostname.lower().rstrip(".")
        port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
        path = p.path or "/"
        return f"{p.scheme.lower()}://{host}{port}{path}" + (f"?{p.query}" if p.query else "")
    except ValueError:
        return None


def url_lookup_keys(raw: str) -> list[str]:
    """A checked URL matches a listed one exactly, or with its query string removed (kits append per-victim parameters)."""
    full = normalize_url(raw)
    if not full:
        return []
    base = full.split("?", 1)[0]
    keys = [full] if base == full else [full, base]
    alt = ("http://" + full[8:]) if full.startswith("https://") else ("https://" + full[7:])
    return keys + [alt.split("?", 1)[0]]  # a feed may list the same page over the other scheme


def normalize_host(value: str) -> str | None:
    v = value.strip().lower().rstrip(".")
    return v if _HOST.match(v) else None


def parse_feed(text: str, fmt: str, kind: str, category: str) -> ParsedFeed:
    if fmt not in FORMATS:
        raise ValueError(f"unsupported feed format: {fmt}")
    out: dict[tuple[str, str], Indicator] = {}
    rejected = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", ";", "//")):
            continue
        try:
            ind = _parse_line(s, fmt, category)
        except (ValueError, KeyError, json.JSONDecodeError, TypeError):
            ind = None
        if ind is _IGNORE:
            continue  # metadata lines are expected in some feeds and are not errors
        if ind is None:
            rejected += 1
        else:
            out[(ind.kind, ind.value)] = ind
    return ParsedFeed(tuple(out.values()), rejected)


_IGNORE = object()


def _parse_line(s: str, fmt: str, category: str):
    if fmt == "urls":
        n = normalize_url(s.split()[0])
        return Indicator("url", n, category) if n else None
    if fmt == "hosts":
        parts = s.split()
        h = normalize_host(parts[-1] if len(parts) > 1 else parts[0])
        return Indicator("host", h, category) if h else None
    if fmt == "cidr_json_lines":
        d = json.loads(s)
        if "cidr" not in d:
            return _IGNORE  # metadata line (e.g. {"type":"metadata",...})
        return Indicator("cidr", str(ipaddress.ip_network(d["cidr"], strict=False)), category)
    if fmt == "cidr_text":
        return Indicator("cidr", str(ipaddress.ip_network(re.split(r"[;\s]", s, maxsplit=1)[0], strict=False)), category)
    if fmt == "asn_json_lines":
        d = json.loads(s)
        if "asn" not in d:
            return _IGNORE
        return Indicator("asn", str(int(d["asn"])), category)
    if fmt == "asn_text":
        m = re.match(r"^(?:AS)?(\d{1,10})\b", s, re.I)
        return Indicator("asn", m.group(1), category) if m else None
    return None


def reconcile(*, new_count: int, previous_count: int | None, min_expected: int, min_ratio: float = 0.2) -> tuple[bool, str]:
    """Reject suspicious updates instead of silently replacing good data (USDA §10: reconcile loads)."""
    if new_count < min_expected:
        return False, f"only {new_count} indicators parsed (expected at least {min_expected})"
    if previous_count and new_count < previous_count * min_ratio:
        return False, f"indicator count fell from {previous_count} to {new_count}"
    return True, "ok"

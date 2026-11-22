r"""URL parsing that mirrors what a *browser* does, not what RFC 3986 says.

Attackers exploit parser differentials: `https://evil.com\@good.com` goes to `evil.com` in every browser (the
backslash ends the authority) while a naive RFC parser - e.g. an allow-list validator - sees host `good.com`. This module follows the WHATWG rules for special schemes (backslash == slash,
tabs/newlines stripped, authority ends at the first / \\ ? #, userinfo splits at the LAST @, percent-decoded and
IDNA-mapped hosts, legacy decimal/hex/octal IPv4 forms) and records a flag for every quirk it had to normalise.
It never raises: unparseable input yields host_kind == "invalid".
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

import idna

from shared.utilities.public_suffix import split_host

SPECIAL_SCHEMES = frozenset({"http", "https", "ftp", "ws", "wss", "file"})
DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_FORBIDDEN_HOST = re.compile(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]")
_NUMERIC_LAST = re.compile(r"^(?:[0-9]+|0[xX][0-9a-fA-F]*)$")
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})


@dataclass(frozen=True)
class ParsedUrl:
    raw: str
    scheme: str
    scheme_assumed: bool
    userinfo: str | None
    host: str                 # canonical ASCII host (punycode), lower-case; dotted-decimal for IPv4
    host_unicode: str         # what a browser may *display* (decoded punycode)
    host_raw: str             # host exactly as typed (before decoding / mapping)
    host_kind: str            # domain | ipv4 | ipv6 | none | invalid
    ip_form: str | None       # dotted | decimal | hex | octal | abbreviated | ipv6
    port: int | None
    path: str
    query: str
    fragment: str
    opaque: str               # body of non-hierarchical schemes (javascript:, data:, mailto:)
    subdomain_labels: tuple[str, ...]
    label: str                # the registrable label, e.g. "evil" in login.evil.co.uk
    suffix: str               # public suffix, e.g. "co.uk"
    registrable: str          # "evil.co.uk" (or the IP for IP hosts)
    flags: frozenset[str]

    @property
    def is_web(self) -> bool:
        return self.scheme in ("http", "https") and self.host_kind in ("domain", "ipv4", "ipv6")

    @property
    def effective_port(self) -> int | None:
        return self.port if self.port is not None else DEFAULT_PORTS.get(self.scheme)

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if self.host_kind == "ipv6" else self.host
        default = DEFAULT_PORTS.get(self.scheme)
        return host if self.port is None or self.port == default else f"{host}:{self.port}"

    @property
    def fetch_url(self) -> str:
        """Canonical URL used for fetching: no userinfo (never sent), no fragment (never sent by browsers)."""
        q = f"?{self.query}" if self.query else ""
        return f"{self.scheme}://{self.netloc}{self.path or '/'}{q}"

    @property
    def display_url(self) -> str:
        auth = f"{self.userinfo}@" if self.userinfo is not None else ""
        frag = f"#{self.fragment}" if self.fragment else ""
        q = f"?{self.query}" if self.query else ""
        if self.host_kind in ("none", "invalid") and not self.host:
            return f"{self.scheme}:{self.opaque}" if self.opaque else self.raw
        return f"{self.scheme}://{auth}{self.netloc}{self.path}{q}{frag}"


def _parse_ipv4(host: str) -> tuple[str, str] | None:
    parts = host.rstrip(".").split(".") if host.endswith(".") else host.split(".")
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts):
        return None
    nums, forms = [], set()
    for p in parts:
        if re.fullmatch(r"0[xX][0-9a-fA-F]*", p):
            nums.append(int(p[2:] or "0", 16)); forms.add("hex")
        elif re.fullmatch(r"0[0-7]+", p):
            nums.append(int(p, 8)); forms.add("octal")
        elif re.fullmatch(r"[0-9]+", p):
            nums.append(int(p)); forms.add("decimal")
        else:
            return None
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1] + sum(n * 256 ** (3 - i) for i, n in enumerate(nums[:-1]))
    canonical = str(ipaddress.IPv4Address(value))
    if len(parts) == 4 and forms == {"decimal"} and all(str(int(p)) == p for p in parts):
        form = "dotted"
    elif "hex" in forms:
        form = "hex"
    elif "octal" in forms:
        form = "octal"
    elif len(parts) == 1:
        form = "decimal"
    else:
        form = "abbreviated"
    return canonical, form


def _ascii_host(host: str, flags: set[str]) -> str:
    host = host.translate(_DOTS)
    if host.isascii():
        return host.lower()
    flags.add("idn_host")
    try:
        return idna.encode(host, uts46=True, transitional=False).decode("ascii")
    except idna.IDNAError:
        flags.add("idna_invalid")
        return unicodedata.normalize("NFKC", host).lower()


def _unicode_host(ascii_host: str, flags: set[str]) -> str:
    if "xn--" not in ascii_host:
        return ascii_host
    flags.add("punycode")
    out = []
    for label in ascii_host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(idna.decode(label))
            except (idna.IDNAError, UnicodeError):
                flags.add("punycode_invalid")
                out.append(label)
        else:
            out.append(label)
    return ".".join(out)


def parse_url(raw: str) -> ParsedUrl:
    flags: set[str] = set()
    text = raw
    stripped = text.strip("".join(chr(i) for i in range(0x21)))
    if stripped != text:
        flags.add("outer_whitespace_trimmed")
    cleaned = re.sub(r"[\t\n\r]", "", stripped)
    if cleaned != stripped:
        flags.add("inner_whitespace_removed")
    if re.search(r"[\x00-\x1f\x7f]", cleaned):
        flags.add("control_characters")
    if _INVISIBLE.search(raw):
        flags.add("invisible_characters")
    if re.search("[\u202a-\u202e\u2066-\u2069]", raw):
        flags.add("bidi_override")

    scheme, assumed, rest = "", False, cleaned
    m = _SCHEME.match(cleaned)
    if cleaned.startswith("\\\\"):
        scheme, rest = "file", cleaned[2:]; flags.add("unc_path")
    elif m and len(m.group(1)) == 1:
        scheme, rest = "file", cleaned[2:]; flags.add("windows_path")
    elif m:
        cand, after = m.group(1).lower(), cleaned[m.end():]
        looks_host_port = ("." in cand or cand == "localhost") and re.match(r"^\d{1,5}(?:[/?#\\]|$)", after)
        if looks_host_port:
            scheme, assumed, rest = "https", True, cleaned
        else:
            scheme, rest = cand, after
    else:
        scheme, assumed = "https", True
        rest = cleaned
    if assumed:
        flags.add("scheme_assumed")

    special = scheme in SPECIAL_SCHEMES
    if not special and not rest.startswith("//"):
        # opaque / non-hierarchical (javascript:, data:, mailto:, tel:, ms-msdt: ...)
        return ParsedUrl(raw, scheme, False, None, "", "", "", "none", None, None, "", "", "", rest, (), "", "", "", frozenset(flags))

    lead = len(rest) - len(rest.lstrip("/\\"))
    if special and lead != 2 and not assumed:
        flags.add("nonstandard_slashes")
    if "\\" in rest[:lead]:
        flags.add("backslashes")
    rest = rest.lstrip("/\\") if (special or lead >= 2) else rest[2:]
    end = len(rest)
    for ch in ("/", "\\", "?", "#"):
        i = rest.find(ch)
        if i != -1:
            end = min(end, i)
    authority, tail = rest[:end], rest[end:]
    if special and tail.startswith("\\") and "@" in re.split(r"[/?#]", tail[1:], maxsplit=1)[0]:
        flags.add("backslash_at_trick")

    fragment, query = "", ""
    if "#" in tail:
        tail, fragment = tail.split("#", 1)
    if "?" in tail:
        tail, query = tail.split("?", 1)
    path = tail
    if special and "\\" in path:
        path = path.replace("\\", "/"); flags.add("backslashes")

    userinfo = None
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
        flags.add("userinfo")
        if userinfo.count("@") or "%40" in userinfo.lower():
            flags.add("multiple_at")

    host_raw, port, port_text = authority, None, ""
    if authority.startswith("["):
        close = authority.find("]")
        if close == -1:
            return _invalid(raw, scheme, assumed, userinfo, authority, path, query, fragment, flags | {"bad_ipv6"})
        host_raw, port_text = authority[: close + 1], authority[close + 1:]
        port_text = port_text[1:] if port_text.startswith(":") else port_text
    elif ":" in authority:
        host_raw, port_text = authority.rsplit(":", 1)
    if port_text:
        if port_text.isdigit() and int(port_text) <= 65535:
            port = int(port_text)
        else:
            flags.add("invalid_port")
            return _invalid(raw, scheme, assumed, userinfo, host_raw, path, query, fragment, flags)

    host_kind, ip_form, host, host_unicode = "domain", None, "", ""
    if host_raw.startswith("["):
        try:
            host = str(ipaddress.IPv6Address(host_raw[1:-1].split("%")[0]))
            host_kind, ip_form, host_unicode = "ipv6", "ipv6", host
        except ValueError:
            return _invalid(raw, scheme, assumed, userinfo, host_raw, path, query, fragment, flags | {"bad_ipv6"})
    else:
        decoded = unquote(host_raw, errors="replace") if "%" in host_raw else host_raw
        if decoded != host_raw:
            flags.add("percent_encoded_host")
        if not decoded.isascii():
            folded = unicodedata.normalize("NFKC", decoded)
            if folded != decoded and folded.isascii():
                flags.add("compat_characters_in_host")
            decoded = folded
        if _FORBIDDEN_HOST.search(decoded.translate(_DOTS)):
            flags.add("encoded_delimiter_in_host" if decoded != host_raw else "forbidden_host_character")
            return _invalid(raw, scheme, assumed, userinfo, host_raw, path, query, fragment, flags)
        if host_raw.translate(_DOTS) != host_raw:
            flags.add("fullwidth_dots")
        ascii_host = _ascii_host(decoded, flags)
        if ascii_host.endswith("."):
            flags.add("trailing_dot"); ascii_host = ascii_host.rstrip(".")
        if not ascii_host and scheme != "file":
            return _invalid(raw, scheme, assumed, userinfo, host_raw, path, query, fragment, flags | {"empty_host"})
        last = ascii_host.rsplit(".", 1)[-1]
        if ascii_host and _NUMERIC_LAST.match(last):
            parsed = _parse_ipv4(ascii_host)
            if parsed is None:
                return _invalid(raw, scheme, assumed, userinfo, host_raw, path, query, fragment, flags | {"bad_ipv4"})
            host, ip_form = parsed
            host_kind, host_unicode = "ipv4", host
            if ip_form != "dotted":
                flags.add("nonstandard_ip_notation")
        else:
            host, host_unicode = ascii_host, _unicode_host(ascii_host, flags)
            if len(host) > 253 or any(len(l) > 63 for l in host.split(".")):
                flags.add("host_too_long")
        if not host:
            host_kind = "none"

    sub, label, suffix, registrable = (), "", "", ""
    if host_kind == "domain":
        parts = split_host(host)
        sub, label, suffix, registrable = parts.subdomain_labels, parts.label, parts.suffix, parts.registrable
    elif host_kind in ("ipv4", "ipv6"):
        registrable = host
    return ParsedUrl(raw, scheme, assumed, userinfo, host, host_unicode, host_raw, host_kind, ip_form, port,
                     path, query, fragment, "", sub, label, suffix, registrable, frozenset(flags))


def _invalid(raw, scheme, assumed, userinfo, host_raw, path, query, fragment, flags) -> ParsedUrl:
    return ParsedUrl(raw, scheme, assumed, userinfo, "", "", host_raw, "invalid", None, None, path, query, fragment,
                     "", (), "", "", "", frozenset(flags))

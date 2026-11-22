"""Evidence: plain, immutable facts gathered about a link. Checks are pure functions of (URL, evidence, reference data).

Every evidence source can fail. A failure is represented explicitly (`Evidence.missing(reason)`), never as an
empty value, so a check can say "not verified" instead of silently reporting "safe" (USSA: fail securely).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class Evidence(Generic[T]):
    value: T | None = None
    reason: str | None = None

    @property
    def available(self) -> bool:
        return self.reason is None and self.value is not None

    @staticmethod
    def of(value: T) -> "Evidence[T]":
        return Evidence(value=value)

    @staticmethod
    def missing(reason: str) -> "Evidence":
        return Evidence(value=None, reason=reason)


# ---- page snapshot (produced by an HTML parser adapter; contains facts only, no judgement) -------------------
@dataclass(frozen=True)
class FieldInfo:
    type: str = "text"
    name: str = ""
    id: str = ""
    placeholder: str = ""
    autocomplete: str = ""
    label: str = ""
    hidden: bool = False  # styled/attribute-hidden (type=hidden is reported through `type`)


@dataclass(frozen=True)
class FormInfo:
    action: str | None
    method: str
    fields: tuple[FieldInfo, ...]
    style: str = ""
    submit_texts: tuple[str, ...] = ()


@dataclass(frozen=True)
class AnchorInfo:
    href: str
    text: str


@dataclass(frozen=True)
class FrameInfo:
    src: str
    style: str = ""
    width: str = ""
    height: str = ""
    hidden_attr: bool = False


@dataclass(frozen=True)
class ElementInfo:
    tag: str
    id: str = ""
    classes: str = ""
    style: str = ""
    hidden_attr: bool = False
    has_input: bool = False
    link_count: int = 0
    text_len: int = 0


@dataclass(frozen=True)
class PageSnapshot:
    title: str = ""
    description: str = ""
    og_site_name: str = ""
    og_title: str = ""
    og_url: str = ""
    canonical: str = ""
    base_href: str = ""
    lang: str = ""
    meta_refresh: str = ""
    headings: tuple[str, ...] = ()
    image_alts: tuple[str, ...] = ()
    visible_text: str = ""
    forms: tuple[FormInfo, ...] = ()
    anchors: tuple[AnchorInfo, ...] = ()
    iframes: tuple[FrameInfo, ...] = ()
    elements: tuple[ElementInfo, ...] = ()
    style_rules: tuple[tuple[str, str], ...] = ()
    inline_scripts: tuple[str, ...] = ()
    script_srcs: tuple[str, ...] = ()
    input_count: int = 0
    byte_size: int = 0
    truncated: bool = False


# ---- network journey --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Hop:
    index: int
    url: str
    status: int | None
    via: str                    # initial | http_redirect | meta_refresh | javascript
    location: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    disposition: str | None = None
    sniffed: str | None = None  # executable | archive | pdf | office | image | html | script | text | unknown
    error: str | None = None
    insecure_tls: bool = False


@dataclass(frozen=True)
class FetchResult:
    profile: str                # scanner | browser
    outcome: str                # ok | blocked | dns_failed | connect_failed | tls_failed | timeout | too_many_redirects | redirect_loop | not_fetchable
    detail: str | None
    hops: tuple[Hop, ...] = ()
    final_url: str | None = None
    final_status: int | None = None
    page: PageSnapshot | None = None
    digest: str | None = None
    fingerprint: frozenset[int] = frozenset()


# ---- reputation / infrastructure ----------------------------------------------------------------------------
@dataclass(frozen=True)
class BlocklistHit:
    provider: str
    matched: str
    kind: str                   # url | host
    category: str = "unknown"   # phishing | malware | scam | unknown
    listed_on: str | None = None


@dataclass(frozen=True)
class BlocklistReport:
    checked: tuple[str, ...]
    failed: tuple[tuple[str, str], ...] = ()
    hits: tuple[BlocklistHit, ...] = ()
    freshness: tuple[tuple[str, str], ...] = ()  # (provider, last refresh ISO)


@dataclass(frozen=True)
class DnsReport:
    addresses: dict[str, tuple[str, ...]] = field(default_factory=dict)
    errors: dict[str, tuple[str, str]] = field(default_factory=dict)  # host -> (kind, reason)


@dataclass(frozen=True)
class HostingEntry:
    ip: str
    asn: int | None = None
    as_name: str | None = None
    country: str | None = None
    prefix: str | None = None
    listed_in: tuple[str, ...] = ()


@dataclass(frozen=True)
class HostingReport:
    entries: tuple[HostingEntry, ...]
    lookup_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class CertInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    san: tuple[str, ...]
    self_signed: bool


@dataclass(frozen=True)
class TlsReport:
    host: str
    port: int
    https: bool
    handshake_ok: bool = False
    verified: bool = False
    verify_error: str | None = None
    protocol: str | None = None
    cert: CertInfo | None = None
    error: str | None = None


@dataclass(frozen=True)
class RegistrationInfo:
    domain: str
    created: datetime | None
    expires: datetime | None
    registrar: str | None = None
    statuses: tuple[str, ...] = ()


@dataclass(frozen=True)
class RegistrationReport:
    records: tuple[RegistrationInfo, ...] = ()
    errors: tuple[tuple[str, str], ...] = ()  # (domain, reason)


EVIDENCE_KEYS = ("journey", "journey_browser", "blocklist", "dns", "hosting", "tls", "registration")

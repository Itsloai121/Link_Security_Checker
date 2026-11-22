"""Reference data (USDA §4.2): brands, word lists and thresholds, owned in `config/defaults/reference/*.json`.

The domain only sees this immutable structure; loading and validation live in infrastructure.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


def norm_text(value: str) -> str:
    """Lower-case, strip Arabic diacritics/tatweel and unify alef forms so lexicon matching is script-tolerant."""
    v = unicodedata.normalize("NFKC", value).casefold()
    v = re.sub("[\u064b-\u065f\u0670\u0640]", "", v)
    return re.sub("[\u0623\u0625\u0622]", "\u0627", v)


@dataclass(frozen=True)
class Brand:
    key: str
    name: str
    domains: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    tld_variants: bool = False
    category: str = ""

    @property
    def tokens(self) -> tuple[str, ...]:
        """Strings that denote the brand inside a domain label, e.g. 'paypal', 'bankofamerica'."""
        names = {re.sub(r"[^a-z0-9]", "", norm_text(n)) for n in (self.name, self.key, *self.aliases)}
        return tuple(sorted(t for t in names if len(t) >= 3))


@dataclass(frozen=True)
class LexiconEntry:
    phrase: str
    category: str   # suspension | verify | payment | prize | delivery | security | threat | crypto | support
    lang: str = "en"
    weak: bool = False  # generic words ("urgent") that only count in combination


@dataclass(frozen=True)
class ReferenceData:
    brands: tuple[Brand, ...]
    shorteners: frozenset[str]
    suspicious_tlds: frozenset[str]
    ugc_hosting: frozenset[str]
    dynamic_dns: frozenset[str]
    popular_domains: frozenset[str]
    redirect_params: frozenset[str]
    sensitive_words: frozenset[str]
    dangerous_schemes: dict[str, tuple[str, str]]       # scheme -> (severity, explanation)
    urgency: tuple[LexiconEntry, ...]
    exfil_hosts: frozenset[str]
    risky_asns: frozenset[int] = frozenset()
    risky_countries: frozenset[str] = frozenset()
    free_cert_issuers: frozenset[str] = frozenset()
    version: str = "0"
    _official: dict[str, Brand] = field(default_factory=dict, repr=False, compare=False)
    _targets: tuple[tuple[str, str, str], ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        official = {d: b for b in self.brands for d in b.domains}
        targets: list[tuple[str, str, str]] = []
        for b in self.brands:
            for t in b.tokens:
                targets.append((t, b.domains[0], b.name))
        for d in sorted(self.popular_domains):
            label = d.split(".")[0]
            if len(label) >= 4:
                targets.append((re.sub(r"[^a-z0-9]", "", label), d, label))
        object.__setattr__(self, "_official", official)
        object.__setattr__(self, "_targets", tuple(dict.fromkeys(targets)))

    # -- lookups -------------------------------------------------------------------------------------------
    def official_brand(self, registrable: str) -> Brand | None:
        """Brand whose *official* registrable domain this is (including its country variants)."""
        hit = self._official.get(registrable)
        if hit:
            return hit
        label, _, suffix = registrable.partition(".")
        for b in self.brands:
            if b.tld_variants and label in b.tokens and re.fullmatch(r"(?:[a-z]{2}|(?:com?|net|org|gov|ac)\.[a-z]{2})", suffix):
                return b
        return None

    def is_popular(self, registrable: str) -> bool:
        return registrable in self.popular_domains

    def is_trusted(self, registrable: str) -> bool:
        return self.official_brand(registrable) is not None or self.is_popular(registrable)

    def is_ugc_host(self, host: str) -> bool:
        """True when anyone can publish pages under this host (github.io, sites.google.com, amazonaws.com ...)."""
        return any(host == s or host.endswith("." + s) for s in self.ugc_hosting)

    def is_dynamic_dns(self, host: str) -> bool:
        return any(host == s or host.endswith("." + s) for s in self.dynamic_dns)

    @property
    def lookalike_targets(self) -> tuple[tuple[str, str, str], ...]:
        """(token, official registrable, display name) for typosquat comparison."""
        return self._targets

    def brands_in_text(self, text: str, min_len: int = 4) -> list[Brand]:
        low = norm_text(text)
        found: list[Brand] = []
        for b in self.brands:
            names = {norm_text(n) for n in (b.name, *b.aliases)}
            if any(len(n) >= min_len and re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", low) for n in names):
                found.append(b)
        return found

"""Loads and VALIDATES reference data at startup (USDA §10: validate third-party and file-based inputs; USBA §14: fail fast).

A malformed reference file stops the application from starting rather than silently weakening detection.
JSON Schemas under config/schemas/ are generated from these models (scripts/export_schemas.py).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from modules.link_analysis.domain.reference import Brand, LexiconEntry, ReferenceData, norm_text

_DOMAIN = re.compile(r"^(?=.{3,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class BrandModel(_Strict):
    key: str = Field(pattern=r"^[a-z0-9_]{2,40}$")
    name: str = Field(min_length=2, max_length=60)
    domains: list[str] = Field(min_length=1)
    aliases: list[str] = []
    tld_variants: bool = False
    category: str = ""

    @field_validator("domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        for d in v:
            if not _DOMAIN.match(d) and d not in {"a.co", "x.com", "t.co", "t.me", "fb.me", "wa.me", "we.tl"}:
                raise ValueError(f"not a registrable domain: {d!r}")
        return v


class BrandsFile(_Strict):
    version: str
    description: str = ""
    brands: list[BrandModel]


class ListsFile(_Strict):
    version: str
    description: str = ""
    shorteners: list[str]
    suspicious_tlds: list[str]
    ugc_hosting: list[str]
    dynamic_dns: list[str]
    popular_domains: list[str]
    redirect_params: list[str]
    sensitive_words: list[str]
    dangerous_schemes: dict[str, tuple[str, str]]
    exfil_hosts: list[str]
    free_cert_issuers: list[str] = []
    risky_asns: list[int] = []
    risky_countries: list[str] = []

    @field_validator("dangerous_schemes")
    @classmethod
    def _sev(cls, v: dict[str, tuple[str, str]]) -> dict[str, tuple[str, str]]:
        bad = [k for k, (sev, _) in v.items() if sev not in _SEVERITIES]
        if bad:
            raise ValueError(f"unknown severity for schemes: {bad}")
        return v


class LexiconEntryModel(_Strict):
    phrase: str = Field(min_length=3, max_length=80)
    category: str
    lang: str = "en"
    weak: bool = False


class LexiconFile(_Strict):
    version: str
    description: str = ""
    urgency: list[LexiconEntryModel]


def load_reference(directory: Path) -> ReferenceData:
    def read(name: str) -> dict:
        return json.loads((directory / name).read_text(encoding="utf-8"))

    brands = BrandsFile.model_validate(read("brands.json"))
    lists = ListsFile.model_validate(read("lists.json"))
    lex = LexiconFile.model_validate(read("lexicons.json"))
    keys = [b.key for b in brands.brands]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate brand keys in brands.json")
    lower = lambda xs: frozenset(x.lower() for x in xs)  # noqa: E731
    return ReferenceData(
        brands=tuple(Brand(b.key, b.name, tuple(b.domains), tuple(b.aliases), b.tld_variants, b.category) for b in brands.brands),
        shorteners=lower(lists.shorteners), suspicious_tlds=lower(lists.suspicious_tlds), ugc_hosting=lower(lists.ugc_hosting),
        dynamic_dns=lower(lists.dynamic_dns), popular_domains=lower(lists.popular_domains), redirect_params=lower(lists.redirect_params),
        sensitive_words=lower(lists.sensitive_words), dangerous_schemes={k.lower(): v for k, v in lists.dangerous_schemes.items()},
        urgency=tuple(LexiconEntry(norm_text(e.phrase), e.category, e.lang, e.weak) for e in lex.urgency),
        exfil_hosts=lower(lists.exfil_hosts), risky_asns=frozenset(lists.risky_asns), risky_countries=frozenset(c.upper() for c in lists.risky_countries),
        free_cert_issuers=lower(lists.free_cert_issuers), version=f"{brands.version}/{lists.version}/{lex.version}",
    )

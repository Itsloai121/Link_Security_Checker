"""Interfaces for everything that touches the network. Adapters live in infrastructure; fakes live in tests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from collections.abc import Iterable

from modules.link_analysis.domain.evidence import (BlocklistHit, DnsReport, FetchResult, HostingEntry, RegistrationInfo, TlsReport)
from modules.link_analysis.domain.url_model import ParsedUrl


@dataclass(frozen=True)
class BlocklistQuery:
    urls: tuple[str, ...]
    hosts: tuple[str, ...]


class PageFetcher(Protocol):
    async def fetch_journey(self, url: ParsedUrl, profile: str) -> FetchResult:
        """Follow redirects (HTTP, meta-refresh, simple JS) with the given client profile ('scanner' | 'browser')."""


class DnsLookup(Protocol):
    async def resolve_many(self, hosts: Iterable[str]) -> DnsReport: ...


class TlsInspector(Protocol):
    async def inspect(self, host: str, port: int) -> TlsReport: ...


class RegistrationLookup(Protocol):
    async def lookup(self, registrable_domain: str) -> RegistrationInfo:
        """Raise `DependencyFailure` when the registry cannot be queried."""


class IpIntelligence(Protocol):
    async def lookup(self, ip: str) -> HostingEntry: ...


@dataclass(frozen=True)
class BlocklistAnswer:
    hits: tuple[BlocklistHit, ...]
    checked: tuple[str, ...]                       # human names of the lists actually consulted
    freshness: tuple[tuple[str, str], ...] = ()    # (list name, last refresh ISO)


class BlocklistProvider(Protocol):
    name: str

    async def check(self, query: BlocklistQuery) -> BlocklistAnswer:
        """Raise `DependencyFailure` if the list cannot be consulted: an unreachable list must never read as 'clean'."""

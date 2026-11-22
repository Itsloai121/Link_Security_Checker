"""Gathers evidence concurrently. Each source is isolated: a timeout or crash in one becomes `Evidence.missing(reason)`
for that source only, so a single unreachable service can never sink the whole analysis (USBA §12, USSA fail-securely).
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence

from infrastructure.observability.logging import event
from infrastructure.observability.metrics import Metrics
from modules.link_analysis.application.settings import AnalysisPolicy
from modules.link_analysis.domain.evidence import (EVIDENCE_KEYS, BlocklistReport, Evidence, HostingReport, RegistrationReport, TlsReport)
from modules.link_analysis.domain.reference import ReferenceData
from modules.link_analysis.domain.url_model import ParsedUrl, parse_url
from modules.link_analysis.ports.evidence_sources import (BlocklistProvider, BlocklistQuery, DnsLookup, IpIntelligence, PageFetcher,
                                                          RegistrationLookup, TlsInspector)
from shared.errors import AppError

log = logging.getLogger("unmask.evidence")
TIMEOUTS = {"journey": 38.0, "journey_browser": 32.0, "dns": 8.0, "hosting": 10.0, "tls": 12.0, "registration": 12.0, "blocklist": 14.0}


class EvidenceCollector:
    def __init__(self, *, fetcher: PageFetcher, dns: DnsLookup, tls: TlsInspector, registration: RegistrationLookup | None,
                 ip_intel: IpIntelligence | None, blocklists: Sequence[BlocklistProvider], reference: ReferenceData,
                 policy: AnalysisPolicy, metrics: Metrics | None = None):
        self.fetcher, self.dns, self.tls, self.registration, self.ip_intel = fetcher, dns, tls, registration, ip_intel
        self.blocklists, self.ref, self.policy, self.metrics = list(blocklists), reference, policy, metrics or Metrics()

    def start(self, url: ParsedUrl) -> "EvidenceSession":
        return EvidenceSession(self, url)


class EvidenceSession:
    def __init__(self, c: EvidenceCollector, url: ParsedUrl):
        self.c, self.url = c, url
        self._tasks: dict[str, asyncio.Task] = {k: asyncio.create_task(self._guard(k)) for k in EVIDENCE_KEYS}

    async def get(self, key: str) -> Evidence:
        return await asyncio.shield(self._tasks[key])

    def peek(self, key: str) -> Evidence:
        t = self._tasks[key]
        if t.done() and not t.cancelled():
            return t.result()
        return Evidence.missing("not finished")

    def cancel(self) -> None:
        for t in self._tasks.values():
            if not t.done():
                t.cancel()

    async def _guard(self, key: str) -> Evidence:
        try:
            ev = await asyncio.wait_for(getattr(self, f"_collect_{key}")(), TIMEOUTS[key])
            outcome = "ok" if ev.available else "unavailable"
        except TimeoutError:
            ev, outcome = Evidence.missing("The lookup timed out."), "timeout"
        except asyncio.CancelledError:
            raise
        except AppError as exc:
            ev, outcome = Evidence.missing(exc.message), "dependency_error"
        except Exception as exc:  # isolate: never let one source break the scan
            event(log, "evidence_source_crashed", logging.ERROR, source=key, exc_type=type(exc).__name__)
            ev, outcome = Evidence.missing("An internal error occurred while gathering this evidence."), "error"
        self.c.metrics.inc("unmask_evidence_total", {"source": key, "outcome": outcome})
        return ev

    # ---- helpers -------------------------------------------------------------------------------------------
    def _final(self, j: Evidence) -> ParsedUrl:
        return parse_url(j.value.final_url) if j.available and j.value.final_url else self.url

    def _hosts(self, j: Evidence) -> list[ParsedUrl]:
        urls = [self.url] + ([parse_url(h.url) for h in j.value.hops] if j.available else [])
        out: dict[str, ParsedUrl] = {}
        for p in urls:
            if p.host_kind in ("domain", "ipv4", "ipv6") and p.host not in out:
                out[p.host] = p
        # always keep first and last, cap the rest
        ordered = list(out.values())
        return ordered[: self.c.policy.max_hosts_resolved - 1] + ordered[-1:] if len(ordered) > self.c.policy.max_hosts_resolved else ordered

    # ---- sources -------------------------------------------------------------------------------------------
    async def _collect_journey(self) -> Evidence:
        if not self.url.is_web:
            return Evidence.missing("Only web addresses (http/https) can be followed.")
        return Evidence.of(await self.c.fetcher.fetch_journey(self.url, "scanner"))

    async def _collect_journey_browser(self) -> Evidence:
        j = await self.get("journey")
        if not self.c.policy.cloaking_probe:
            return Evidence.missing("The browser-view comparison is switched off in this installation.")
        if not j.available:
            return Evidence.missing(j.reason or "skipped")
        if j.value.outcome in ("blocked", "dns_failed", "not_fetchable"):
            return Evidence.missing(f"Skipped: {j.value.detail or j.value.outcome}")
        return Evidence.of(await self.c.fetcher.fetch_journey(self.url, "browser"))

    async def _collect_dns(self) -> Evidence:
        j = await self.get("journey")
        hosts = [p.host for p in self._hosts(j)]
        if not hosts:
            return Evidence.missing("There is no host name to look up.")
        return Evidence.of(await self.c.dns.resolve_many(hosts))

    async def _collect_hosting(self) -> Evidence:
        if not self.c.ip_intel or not self.c.policy.ip_intelligence:
            return Evidence.missing("Network-ownership lookups are switched off in this installation.")
        d = await self.get("dns")
        if not d.available:
            return Evidence.missing(d.reason or "DNS was not available")
        ips = list(dict.fromkeys(ip for addrs in d.value.addresses.values() for ip in addrs))[: self.c.policy.max_ips_enriched]
        if not ips:
            return Evidence.missing("No server address was found to look up.")
        results = await asyncio.gather(*(self.c.ip_intel.lookup(ip) for ip in ips), return_exceptions=True)
        entries = tuple(r for r in results if not isinstance(r, BaseException))
        errors = tuple(str(getattr(r, "message", r))[:120] for r in results if isinstance(r, BaseException))
        if not entries:
            return Evidence.missing(errors[0] if errors else "Network ownership could not be looked up.")
        return Evidence.of(HostingReport(entries, errors))

    async def _collect_tls(self) -> Evidence:
        j = await self.get("journey")
        final = self._final(j)
        if final.scheme not in ("http", "https") or final.host_kind not in ("domain", "ipv4", "ipv6"):
            return Evidence.missing("Not a web address.")
        port = final.effective_port or 443
        if final.scheme != "https":
            return Evidence.of(TlsReport(host=final.host, port=port, https=False))
        return Evidence.of(await self.c.tls.inspect(final.host, port))

    async def _collect_registration(self) -> Evidence:
        if not self.c.registration or not self.c.policy.registration_lookup:
            return Evidence.missing("Domain-age lookups are switched off in this installation.")
        j = await self.get("journey")
        domains: list[str] = []
        for p in [self.url, *( [parse_url(h.url) for h in j.value.hops] if j.available else [])]:
            if p.host_kind == "domain" and p.registrable and p.registrable not in domains:
                if self.c.ref.is_trusted(p.registrable) and not self.c.ref.is_ugc_host(p.host):
                    continue  # well-known domains: age is not informative and the lookup would leak needless data
                if p.registrable in self.c.ref.shorteners:
                    continue
                domains.append(p.registrable)
        domains = domains[: self.c.policy.max_registration_domains]
        records, errors = [], []
        results = await asyncio.gather(*(self.c.registration.lookup(d) for d in domains), return_exceptions=True)
        for d, r in zip(domains, results, strict=True):
            if isinstance(r, BaseException):
                errors.append((d, str(getattr(r, "message", "lookup failed"))[:120]))
            else:
                records.append(r)
        return Evidence.of(RegistrationReport(tuple(records), tuple(errors)))

    async def _collect_blocklist(self) -> Evidence:
        if not self.c.blocklists:
            return Evidence.missing("No blocklists are configured.")
        try:
            j = await asyncio.wait_for(asyncio.shield(self._tasks["journey"]), 15)
        except Exception:  # journey late or failed: still check the submitted link itself
            j = Evidence.missing("journey unavailable")
        urls = [self.url.fetch_url if self.url.is_web else self.url.display_url, self.url.display_url]
        if j.available:
            urls += [h.url for h in j.value.hops]
        urls = list(dict.fromkeys(u for u in urls if u))[:14]
        hosts = list(dict.fromkeys(parse_url(u).host for u in urls if parse_url(u).host))[:10]
        query = BlocklistQuery(tuple(urls), tuple(hosts))
        results = await asyncio.gather(*(p.check(query) for p in self.c.blocklists), return_exceptions=True)
        checked, failed, hits, fresh = [], [], [], []
        for p, r in zip(self.c.blocklists, results, strict=True):
            if isinstance(r, BaseException):
                failed.append((p.name, str(getattr(r, "message", "unreachable"))[:100]))
            else:
                checked += list(r.checked)
                hits += list(r.hits)
                fresh += list(r.freshness)
        return Evidence.of(BlocklistReport(tuple(checked), tuple(failed), tuple(hits), tuple(fresh)))

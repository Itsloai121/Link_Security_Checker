"""Public application interface of the threat_intel module. Other modules call ONLY these classes (USBA §3 boundaries)."""
from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field
from collections.abc import Iterable, Sequence

from infrastructure.observability.logging import event
from infrastructure.observability.metrics import Metrics
from modules.threat_intel.domain.indicators import IndicatorHit, normalize_host, parse_feed, reconcile, url_lookup_keys
from modules.threat_intel.ports.feeds import FeedCatalog, FeedDownloader, IndicatorRepository
from shared.contracts.clock import Clock
from shared.errors import AppError

log = logging.getLogger("unmask.threat_intel")


@dataclass(frozen=True)
class LookupResult:
    hits: tuple[IndicatorHit, ...] = ()
    freshness: dict[str, str] = field(default_factory=dict)


class LookupIndicators:
    """Read side: which of these URLs / hosts / IPs / ASNs are on a downloaded list?"""

    CIDR_CACHE_SECONDS = 300

    def __init__(self, repo: IndicatorRepository):
        self.repo = repo
        self._cidrs: list[tuple[ipaddress._BaseNetwork, IndicatorHit]] = []
        self._cidrs_at: float | None = None  # None = never loaded (monotonic() is 'time since boot', so 0.0 is not a safe sentinel)

    async def _networks(self):
        if self._cidrs_at is None or time.monotonic() - self._cidrs_at > self.CIDR_CACHE_SECONDS:  # derived cache, rebuilt from the database
            parsed = []
            for h in await self.repo.all_of_kind("cidr"):
                try:
                    parsed.append((ipaddress.ip_network(h.value, strict=False), h))
                except ValueError:
                    continue
            self._cidrs, self._cidrs_at = parsed, time.monotonic()
        return self._cidrs

    async def execute(self, *, urls: Iterable[str] = (), hosts: Iterable[str] = (), ips: Iterable[str] = (), asns: Iterable[int] = ()) -> LookupResult:
        hits: list[IndicatorHit] = []
        keys = list(dict.fromkeys(k for u in urls for k in url_lookup_keys(u)))
        if keys:
            hits += await self.repo.find("url", keys)
        hs = list(dict.fromkeys(h for h in (normalize_host(x) for x in hosts) if h))
        if hs:
            hits += await self.repo.find("host", hs)
        asn_values = [str(a) for a in dict.fromkeys(asns)]
        if asn_values:
            hits += await self.repo.find("asn", asn_values)
        ip_objs = []
        for ip in ips:
            try:
                ip_objs.append(ipaddress.ip_address(ip))
            except ValueError:
                continue
        if ip_objs:
            for net, hit in await self._networks():
                if any(ip.version == net.version and ip in net for ip in ip_objs):
                    hits.append(hit)
        return LookupResult(tuple(dict.fromkeys(hits)), await self.repo.freshness())


@dataclass(frozen=True)
class FeedUpdateResult:
    source: str
    status: str            # succeeded | rejected | failed | skipped
    loaded: int = 0
    previous: int = 0
    note: str = ""


class RefreshFeeds:
    """Write side: download -> parse -> reconcile -> atomic replace. A bad download never destroys good data."""

    def __init__(self, repo: IndicatorRepository, downloader: FeedDownloader, catalog: FeedCatalog, clock: Clock, enabled: Sequence[str], metrics: Metrics):
        self.repo, self.downloader, self.catalog, self.clock, self.enabled, self.metrics = repo, downloader, catalog, clock, set(enabled), metrics

    async def import_text(self, name: str, text: str) -> FeedUpdateResult:
        """Load a feed from text the operator supplies (offline use, manual downloads) through the same safety pipeline."""
        feed = next((f for f in self.catalog.feeds() if f.name == name), None)
        if feed is None:
            return FeedUpdateResult(name, "failed", note="unknown feed name")

        class _Local:
            async def download(self, _feed):
                return text
        return (await self._run([feed], _Local(), force=True))[0]

    async def execute(self, only: str | None = None) -> list[FeedUpdateResult]:
        return await self._run([f for f in self.catalog.feeds() if not only or f.name == only], self.downloader, force=False)

    async def _run(self, feeds, downloader, *, force: bool) -> list[FeedUpdateResult]:
        results: list[FeedUpdateResult] = []
        for feed in feeds:
            if not force and feed.name not in self.enabled:
                results.append(FeedUpdateResult(feed.name, "skipped", note="not in UNMASK_ENABLED_FEEDS"))
                continue
            update_id = await self.repo.start_update(feed.name, self.clock.now())
            previous = await self.repo.count(feed.name)
            try:
                text = await downloader.download(feed)
                parsed = parse_feed(text, feed.format, feed.kind, feed.category)
                ok, why = reconcile(new_count=len(parsed.indicators), previous_count=previous, min_expected=feed.min_expected)
                if not ok:
                    res = FeedUpdateResult(feed.name, "rejected", len(parsed.indicators), previous, why)
                else:
                    await self.repo.replace_source(feed.name, parsed.indicators, self.clock.now())
                    res = FeedUpdateResult(feed.name, "succeeded", len(parsed.indicators), previous, f"{parsed.rejected_lines} unreadable lines skipped" if parsed.rejected_lines else "")
            except AppError as exc:
                res = FeedUpdateResult(feed.name, "failed", 0, previous, exc.message)
            except Exception as exc:
                event(log, "feed_refresh_crashed", logging.ERROR, feed=feed.name, exc_type=type(exc).__name__)
                res = FeedUpdateResult(feed.name, "failed", 0, previous, "unexpected error")
            await self.repo.finish_update(update_id, status=res.status, loaded=res.loaded if res.status != "failed" else None, previous=previous, note=res.note[:300] or None, now=self.clock.now())
            self.metrics.inc("unmask_feed_updates_total", {"feed": feed.name, "status": res.status})
            event(log, "feed_updated", feed=feed.name, status=res.status, loaded=res.loaded)
            results.append(res)
        return results


class GetFeedStatus:
    def __init__(self, repo: IndicatorRepository, catalog: FeedCatalog, enabled: Sequence[str]):
        self.repo, self.catalog, self.enabled = repo, catalog, set(enabled)

    async def execute(self) -> list[dict]:
        last = await self.repo.last_updates()
        out = []
        for f in self.catalog.feeds():
            u = last.get(f.name, {})
            out.append({"name": f.name, "title": f.title, "enabled": f.name in self.enabled, "indicators": await self.repo.count(f.name),
                        "last_status": u.get("status"), "last_finished": u.get("finished_at"), "note": u.get("note"), "terms": f.terms, "terms_url": f.terms_url})
        return out

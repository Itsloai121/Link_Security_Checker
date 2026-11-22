"""Composition root: the ONLY place where interfaces are connected to implementations (USBA §3.5)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bootstrap.settings import APP_VERSION, Settings
from infrastructure.cache.rate_limit import SlidingWindowLimiter
from infrastructure.external_services.guarded_http import GuardedHttpClient
from infrastructure.external_services.network_policy import GuardedResolver, NetworkPolicy
from infrastructure.messaging.in_process_queue import InProcessJobQueue
from infrastructure.observability.metrics import Metrics
from infrastructure.persistence.sqlite import SqliteDatabase
from modules.link_analysis.application.evidence_collector import EvidenceCollector
from modules.link_analysis.application.queries import DeleteScan, GetScanResult, ListCheckCatalog, PurgeExpiredScans, RecoverInterruptedScans
from modules.link_analysis.application.run_analysis import RunLinkAnalysis
from modules.link_analysis.application.settings import AnalysisPolicy
from modules.link_analysis.application.submit_link import SubmitLinkForAnalysis
from modules.link_analysis.infrastructure.blocklist_adapters import GoogleSafeBrowsingBlocklist, ThreatIntelBlocklist, UrlhausBlocklist
from modules.link_analysis.infrastructure.http_page_fetcher import HttpPageFetcher
from modules.link_analysis.infrastructure.network_adapters import CymruIpIntelligence, GuardedDnsLookup, RdapRegistrationLookup, SocketTlsInspector
from modules.link_analysis.infrastructure.reference_loader import load_reference
from modules.link_analysis.infrastructure.sqlite_scan_repository import SqliteScanRepository
from modules.threat_intel.application.use_cases import GetFeedStatus, LookupIndicators, RefreshFeeds
from modules.threat_intel.infrastructure.feed_adapters import HttpFeedDownloader, JsonFeedCatalog
from modules.threat_intel.infrastructure.sqlite_indicator_repository import SqliteIndicatorRepository
from shared.utilities.ids import SecureIdGenerator
from shared.utilities.time import SystemClock


@dataclass
class Container:
    settings: Settings
    metrics: Metrics
    clock: Any
    ids: Any
    db: SqliteDatabase
    queue: InProcessJobQueue
    http: GuardedHttpClient
    policy: AnalysisPolicy
    reference: Any
    scan_repo: Any
    submit_link: SubmitLinkForAnalysis
    run_analysis: RunLinkAnalysis
    get_scan: GetScanResult
    delete_scan: DeleteScan
    list_checks: ListCheckCatalog
    purge_scans: PurgeExpiredScans
    recover_scans: RecoverInterruptedScans
    lookup_indicators: LookupIndicators
    refresh_feeds: RefreshFeeds
    feed_status: GetFeedStatus
    submit_limiter: SlidingWindowLimiter
    read_limiter: SlidingWindowLimiter
    host_limiter: SlidingWindowLimiter
    extras: dict[str, Any] = field(default_factory=dict)

    async def aclose(self) -> None:
        await self.http.aclose()


def build_container(settings: Settings, *, fetcher=None, dns=None, tls=None, registration=None, ip_intel=None, blocklists=None,
                    clock=None, http: GuardedHttpClient | None = None) -> Container:
    """Optional keyword overrides let tests swap real network adapters for fakes without touching production wiring."""
    clock = clock or SystemClock()
    ids, metrics = SecureIdGenerator(), Metrics()
    metrics.describe("unmask_scans_completed_total", "Completed scans by verdict")
    metrics.describe("unmask_scan_duration_seconds", "End-to-end scan duration")
    db = SqliteDatabase(settings.database_path)
    queue = InProcessJobQueue(settings.queue_size)

    policy_net = NetworkPolicy(allowed_ports=settings.fetch_ports, allow_private_networks=settings.allow_private_networks)
    resolver = GuardedResolver(policy_net)
    http = http or GuardedHttpClient(policy_net, resolver)

    reference = load_reference(settings.config_dir / "reference")
    policy = AnalysisPolicy(engine_version=APP_VERSION, retention_hours=settings.scan_retention_hours, scan_deadline_seconds=settings.scan_deadline_seconds,
                            max_input_length=settings.max_url_length, cloaking_probe=settings.enable_cloaking_probe,
                            registration_lookup=settings.enable_registration_lookup, ip_intelligence=settings.enable_ip_intelligence)

    # threat_intel module
    indicator_repo = SqliteIndicatorRepository(db)
    catalog = JsonFeedCatalog(settings.config_dir / "feeds.json")
    lookup = LookupIndicators(indicator_repo)
    titles = {f.name: f.title for f in catalog.feeds()}
    refresh = RefreshFeeds(indicator_repo, HttpFeedDownloader(http), catalog, clock, settings.enabled_feed_names, metrics)
    feed_status = GetFeedStatus(indicator_repo, catalog, settings.enabled_feed_names)

    # link_analysis module
    async def listings(ip: str, asn: int | None) -> tuple[str, ...]:
        r = await lookup.execute(ips=[ip], asns=[asn] if asn else [])
        return tuple(sorted({titles.get(h.source, h.source) for h in r.hits if h.kind in ("cidr", "asn")}))

    provs = blocklists if blocklists is not None else [ThreatIntelBlocklist(lookup, titles)]
    if blocklists is None:
        if settings.gsb_api_key:
            provs.append(GoogleSafeBrowsingBlocklist(http, settings.gsb_api_key.get_secret_value()))
        if settings.urlhaus_auth_key:
            provs.append(UrlhausBlocklist(http, settings.urlhaus_auth_key.get_secret_value()))
    scan_repo = SqliteScanRepository(db)
    collector = EvidenceCollector(
        fetcher=fetcher or HttpPageFetcher(http, max_redirects=settings.max_redirects), dns=dns or GuardedDnsLookup(resolver),
        tls=tls or SocketTlsInspector(resolver), registration=registration or RdapRegistrationLookup(http),
        ip_intel=ip_intel or CymruIpIntelligence(listings), blocklists=provs, reference=reference, policy=policy, metrics=metrics)
    return Container(
        settings=settings, metrics=metrics, clock=clock, ids=ids, db=db, queue=queue, http=http, policy=policy, reference=reference, scan_repo=scan_repo,
        submit_link=SubmitLinkForAnalysis(scan_repo, queue, clock, ids, policy, metrics),
        run_analysis=RunLinkAnalysis(scan_repo, collector, reference, clock, policy, metrics),
        get_scan=GetScanResult(scan_repo, clock), delete_scan=DeleteScan(scan_repo), list_checks=ListCheckCatalog(),
        purge_scans=PurgeExpiredScans(scan_repo, clock), recover_scans=RecoverInterruptedScans(scan_repo, queue, clock, policy),
        lookup_indicators=lookup, refresh_feeds=refresh, feed_status=feed_status,
        submit_limiter=SlidingWindowLimiter(settings.rate_limit_submit_per_minute, 60),
        read_limiter=SlidingWindowLimiter(settings.rate_limit_read_per_minute, 60),
        host_limiter=SlidingWindowLimiter(settings.per_host_scans_per_minute, 60))

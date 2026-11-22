"""Deterministic stand-ins for the network services. Real adapters are exercised separately; these let tests run offline."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from bootstrap.dependency_wiring import build_container
from bootstrap.settings import Settings
from infrastructure.external_services.guarded_http import GuardedHttpClient
from infrastructure.external_services.network_policy import GuardedResolver, NetworkPolicy
from modules.link_analysis.domain.evidence import BlocklistHit, CertInfo, HostingEntry, RegistrationInfo, TlsReport
from modules.link_analysis.infrastructure.network_adapters import GuardedDnsLookup
from modules.link_analysis.ports.evidence_sources import BlocklistAnswer
from shared.errors import DependencyFailure

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


class MappingResolver(GuardedResolver):
    """Maps fake host names to addresses (still subject to the network policy), otherwise defers to real DNS."""

    def __init__(self, policy: NetworkPolicy, mapping: dict[str, str]):
        super().__init__(policy)
        self.mapping = mapping

    async def resolve(self, host: str, port: int = 443) -> list[str]:
        ip = self.mapping.get(host.strip("[]"))
        if ip:
            self.policy.check_ip(ip)
            return [ip]
        return await super().resolve(host, port)


class FakeTls:
    def __init__(self, reports: dict[str, TlsReport] | None = None):
        self.reports = reports or {}

    async def inspect(self, host: str, port: int) -> TlsReport:
        if host in self.reports:
            return self.reports[host]
        cert = CertInfo(host, "Example CA", NOW - timedelta(days=60), NOW + timedelta(days=30), (host,), False)
        return TlsReport(host, port, True, True, True, None, "TLSv1.3", cert)


class FakeRegistration:
    """created_days_ago maps registrable domain -> age; unknown domains are five years old; `fail` raises like an unreachable registry."""

    def __init__(self, created_days_ago: dict[str, int] | None = None, fail: set[str] | None = None, now: datetime = NOW):
        self.ages, self.fail, self.now = created_days_ago or {}, fail or set(), now

    async def lookup(self, domain: str) -> RegistrationInfo:
        if domain in self.fail:
            raise DependencyFailure("The domain registry could not be reached.")
        age = self.ages.get(domain, 1800)
        return RegistrationInfo(domain, self.now - timedelta(days=age), self.now + timedelta(days=200), "Example Registrar, Inc.", ("client transfer prohibited",))


class FakeIpIntel:
    def __init__(self, listed: dict[str, tuple[str, ...]] | None = None):
        self.listed = listed or {}

    async def lookup(self, ip: str) -> HostingEntry:
        return HostingEntry(ip, 64500, "EXAMPLE-NET Demo Hosting", "ZZ", "127.0.0.0/8", self.listed.get(ip, ()))


class FakeBlocklist:
    def __init__(self, name: str = "Demo threat list", listed_substrings: tuple[str, ...] = (), fail: bool = False):
        self.name, self.listed, self.fail = name, listed_substrings, fail

    async def check(self, query) -> BlocklistAnswer:
        if self.fail:
            raise DependencyFailure("The list could not be reached.")
        hits = tuple(BlocklistHit(self.name, u, "url", "phishing") for u in query.urls if any(s in u for s in self.listed))
        return BlocklistAnswer(hits, (self.name,), ((self.name, "2026-11-21T06:00:00Z"),))


def build_test_container(tmp_path, site, *, registration=None, blocklists=None, tls=None, ip_intel=None, **settings_overrides):
    """A container wired to the fixture site: real fetcher/DNS/parser/DB, fake registry/TLS/blocklist/ASN services."""
    values = dict(database_path=tmp_path / "unmask-test.db", environment="test", log_level="ERROR", allow_private_networks=True,
                  allowed_fetch_ports=f"80,443,{site.port}", scan_deadline_seconds=30, auto_migrate=True)
    values.update(settings_overrides)
    settings = Settings(_env_file=None, **values)
    policy = NetworkPolicy(allowed_ports=settings.fetch_ports, allow_private_networks=settings.allow_private_networks)
    resolver = MappingResolver(policy, site.host_map)
    http = GuardedHttpClient(policy, resolver)
    return build_container(settings, http=http, dns=GuardedDnsLookup(resolver), tls=tls or FakeTls(),
                           registration=registration or FakeRegistration({"login-paypa1.test": 3, "short.test": 400, "cloak.test": 5, "dl.test": 20, "meta.test": 40, "js.test": 40}),
                           ip_intel=ip_intel or FakeIpIntel(), blocklists=blocklists if blocklists is not None else [FakeBlocklist(listed_substrings=("login-paypa1.test",))])

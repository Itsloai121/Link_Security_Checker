"""Adapters from the shared network primitives to link_analysis ports: DNS, TLS, domain registration (RDAP), network ownership."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from datetime import datetime, timezone
from collections.abc import Awaitable, Callable, Iterable
from urllib.parse import urljoin

import dns.asyncresolver
import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.x509.oid import NameOID

from infrastructure.external_services.guarded_http import FetchError, GuardedHttpClient
from infrastructure.external_services.network_policy import BlockedDestination, DnsFailure, GuardedResolver
from infrastructure.external_services.tls_probe import probe_tls
from modules.link_analysis.domain.evidence import CertInfo, DnsReport, HostingEntry, RegistrationInfo, TlsReport
from shared.errors import DependencyFailure


class GuardedDnsLookup:
    def __init__(self, resolver: GuardedResolver):
        self.resolver = resolver

    async def resolve_many(self, hosts: Iterable[str]) -> DnsReport:
        addresses: dict[str, tuple[str, ...]] = {}
        errors: dict[str, tuple[str, str]] = {}

        async def one(host: str) -> None:
            try:
                addresses[host] = tuple(await self.resolver.resolve(host, 443))
            except BlockedDestination as exc:
                errors[host] = ("blocked", exc.reason)
            except DnsFailure as exc:
                errors[host] = (exc.kind, exc.reason)

        await asyncio.gather(*(one(h) for h in dict.fromkeys(hosts)))
        return DnsReport(addresses, errors)


def parse_certificate(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)

    def name(n: x509.Name) -> str:
        for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
            attrs = n.get_attributes_for_oid(oid)
            if attrs:
                return str(attrs[0].value)
        return n.rfc4514_string()[:120]

    try:
        san = tuple(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))[:30]
    except x509.ExtensionNotFound:
        san = ()
    issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return CertInfo(subject=name(cert.subject), issuer=str(issuer_org[0].value) if issuer_org else name(cert.issuer),
                    not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc, san=san, self_signed=cert.subject == cert.issuer)


class SocketTlsInspector:
    def __init__(self, resolver: GuardedResolver):
        self.resolver = resolver

    async def inspect(self, host: str, port: int) -> TlsReport:
        r = await probe_tls(host, port, self.resolver)
        cert = None
        if r.cert_der:
            try:
                cert = parse_certificate(r.cert_der)
            except Exception:  # unreadable certificate: report the handshake without details
                cert = None
        return TlsReport(host, port, True, r.handshake_ok, r.verified, r.verify_error, r.protocol, cert, r.error)


# ---------------------------------------------------------------------------------------------- RDAP
def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class RdapRegistrationLookup:
    """Domain registration data via the public RDAP bootstrap service (JSON over HTTPS, no API key)."""

    BASE = "https://rdap.org/domain/"

    def __init__(self, client: GuardedHttpClient):
        self.client = client

    async def lookup(self, registrable_domain: str) -> RegistrationInfo:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]", registrable_domain):  # also prevents URL injection
            raise DependencyFailure("The domain name is not valid for a registry lookup.")
        url = self.BASE + registrable_domain
        for _ in range(4):
            try:
                resp = await self.client.request("GET", url, headers={"Accept": "application/rdap+json, application/json"}, max_bytes=512_000,
                                                 total_timeout=10, allow_insecure_retry=False)
            except (FetchError, BlockedDestination) as exc:
                raise DependencyFailure("The domain registry could not be reached.") from exc
            if resp.status in (301, 302, 303, 307, 308) and "location" in resp.headers:
                url = urljoin(url, resp.headers["location"])
                if not url.startswith("https://"):
                    raise DependencyFailure("The registry redirected to an insecure address.")
                continue
            if resp.status == 404:
                raise DependencyFailure("The registry does not publish a record for this domain.")
            if resp.status == 429:
                raise DependencyFailure("The registry is rate-limiting lookups right now.")
            if resp.status != 200:
                raise DependencyFailure(f"The registry answered with HTTP {resp.status}.")
            try:
                data = json.loads(resp.body)
            except ValueError as exc:
                raise DependencyFailure("The registry sent an unreadable answer.") from exc
            return self._parse(registrable_domain, data)
        raise DependencyFailure("The registry redirected too many times.")

    @staticmethod
    def _parse(domain: str, data: dict) -> RegistrationInfo:
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
        registrar = None
        for ent in data.get("entities", []):
            if isinstance(ent, dict) and "registrar" in ent.get("roles", []):
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if isinstance(item, list) and item and item[0] == "fn":
                        registrar = str(item[3])[:80]
        return RegistrationInfo(domain, _dt(events.get("registration")), _dt(events.get("expiration")), registrar,
                                tuple(str(s)[:40] for s in data.get("status", []) if isinstance(s, str))[:8])


# ------------------------------------------------------------------------------------- network ownership
Listings = Callable[[str, int | None], Awaitable[tuple[str, ...]]]


class CymruIpIntelligence:
    """ASN, network name and country from Team Cymru's free DNS service, plus abuse-list membership from threat_intel."""

    def __init__(self, listings: Listings | None = None, timeout: float = 4.0):
        self.listings, self.timeout = listings, timeout

    async def lookup(self, ip: str) -> HostingEntry:
        addr = ipaddress.ip_address(ip)
        asn = prefix = country = as_name = None
        try:
            if addr.version == 4:
                qname = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
            else:
                qname = ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = resolver.timeout = self.timeout
            first = (await resolver.resolve(qname, "TXT"))[0].to_text().strip('"').split("|")
            asn, prefix, country = int(first[0].split()[0]), first[1].strip(), first[2].strip() or None
            name_txt = (await resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT"))[0].to_text().strip('"').split("|")
            as_name = name_txt[4].strip()[:80] if len(name_txt) > 4 else None
        except (dns.exception.DNSException, ValueError, IndexError):
            pass  # keep whatever was found; an entry without ASN is still useful for IP-based list matching
        listed = await self.listings(ip, asn) if self.listings else ()
        return HostingEntry(ip, asn, as_name, country, prefix, tuple(listed))

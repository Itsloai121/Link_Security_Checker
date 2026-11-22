import asyncio
import datetime as dt
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from infrastructure.external_services.network_policy import GuardedResolver, NetworkPolicy
from infrastructure.external_services.tls_probe import probe_tls
from modules.link_analysis.application import evidence_collector as ec_mod
from modules.link_analysis.application.evidence_collector import EvidenceCollector
from modules.link_analysis.application.settings import AnalysisPolicy
from modules.link_analysis.domain.evidence import DnsReport, FetchResult, Hop
from modules.link_analysis.domain.url_model import parse_url
from modules.link_analysis.infrastructure.network_adapters import RdapRegistrationLookup, parse_certificate
from shared.errors import DependencyFailure
from tests.fixtures.fakes import FakeBlocklist, FakeIpIntel, FakeRegistration, FakeTls


def make_self_signed(cn="localhost", valid_days=30):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=valid_days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False).sign(key, hashes.SHA256()))
    return cert, key


async def test_tls_probe_reports_why_verification_failed_and_still_returns_the_certificate(tmp_path):
    cert, key = make_self_signed()
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    try:
        resolver = GuardedResolver(NetworkPolicy(allow_private_networks=True))
        res = await probe_tls("localhost", port, resolver)
        assert res.handshake_ok and not res.verified and "self" in (res.verify_error or "").lower() and res.protocol.startswith("TLS")
        info = parse_certificate(res.cert_der)
        assert info.subject == "localhost" and info.self_signed and "localhost" in info.san
        strict = await probe_tls("localhost", port, GuardedResolver(NetworkPolicy()))            # default policy: loopback refused
        assert not strict.handshake_ok and "private" in strict.error
    finally:
        server.close(); await server.wait_closed()


RDAP = {"events": [{"eventAction": "registration", "eventDate": "2026-11-18T10:00:00Z"}, {"eventAction": "expiration", "eventDate": "2027-11-18T10:00:00Z"}],
        "status": ["client transfer prohibited"], "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]}]}


def test_rdap_parsing():
    info = RdapRegistrationLookup._parse("fresh.example", RDAP)
    assert info.created.year == 2026 and info.created.month == 11 and info.registrar == "Example Registrar, Inc." and info.statuses == ("client transfer prohibited",)
    assert RdapRegistrationLookup._parse("x.example", {}).created is None            # privacy-redacted / missing dates are handled


async def test_rdap_rejects_hostile_input_before_any_request():
    class NeverCalled:
        async def request(self, *a, **k): raise AssertionError("must not be called")
    with pytest.raises(DependencyFailure):
        await RdapRegistrationLookup(NeverCalled()).lookup("evil.com/../../admin?x=")


# ---- evidence collector: one failing source must not hurt the others ----------------------------------------------------
class Fetcher:
    def __init__(self, boom=False):
        self.boom = boom

    async def fetch_journey(self, url, profile):
        if self.boom:
            raise RuntimeError("kaboom")
        return FetchResult(profile, "ok", None, (Hop(0, url.fetch_url, 200, "initial", sniffed="html"),), url.fetch_url, 200)


class SlowDns:
    async def resolve_many(self, hosts):
        await asyncio.sleep(30)


class OkDns:
    async def resolve_many(self, hosts): return DnsReport({h: ("203.0.113.5",) for h in hosts})


def collector(ref, fetcher, dns):
    return EvidenceCollector(fetcher=fetcher, dns=dns, tls=FakeTls(), registration=FakeRegistration(), ip_intel=FakeIpIntel(), blocklists=[FakeBlocklist()],
                             reference=ref, policy=AnalysisPolicy())


async def test_a_crashing_source_becomes_missing_evidence_not_a_crashed_scan(ref):
    s = collector(ref, Fetcher(boom=True), OkDns()).start(parse_url("https://fresh.example/"))
    try:
        journey, blocklist, reg = await s.get("journey"), await s.get("blocklist"), await s.get("registration")
        assert not journey.available and "internal error" in journey.reason
        assert blocklist.available and reg.available                                  # unrelated sources unaffected
    finally:
        s.cancel()


async def test_timeout_in_one_source_does_not_cancel_the_source_it_depends_on(ref, monkeypatch):
    monkeypatch.setitem(ec_mod.TIMEOUTS, "dns", 0.05)
    s = collector(ref, Fetcher(), SlowDns()).start(parse_url("https://fresh.example/"))
    try:
        assert not (await s.get("dns")).available                                       # dns timed out...
        assert (await s.get("journey")).available                                       # ...but journey (which dns awaited) was shielded
        assert not (await s.get("hosting")).available                                   # dependents degrade to 'missing', never to a crash
    finally:
        s.cancel()

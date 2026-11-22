"""Builders for evidence objects so check tests stay short and readable."""
from datetime import timedelta

from modules.link_analysis.domain.evidence import (CertInfo, FetchResult, FieldInfo, FormInfo,
                                                   Hop, PageSnapshot, RegistrationInfo, RegistrationReport, TlsReport)
from tests.unit.conftest import NOW


def hop(i, url, status=200, via="initial", ct="text/html", sniffed="html", disposition=None):
    return Hop(i, url, status, via, None, ct, None, disposition, sniffed)


def page(**kw):
    return PageSnapshot(**kw)


def form(action, *fields, method="post"):
    return FormInfo(action, method, tuple(FieldInfo(**f) if isinstance(f, dict) else f for f in fields))


def journey(urls, page_=None, profile="scanner", outcome="ok", status=200, vias=None, **hopkw):
    vias = vias or ["initial"] + ["http_redirect"] * (len(urls) - 1)
    hops = tuple(hop(i, u, 302 if i < len(urls) - 1 else status, vias[i], **({} if i < len(urls) - 1 else hopkw)) for i, u in enumerate(urls))
    return FetchResult(profile, outcome, None, hops, urls[-1], status, page_, None, frozenset())


PWD = {"type": "password", "name": "password"}
EMAIL = {"type": "email", "name": "email"}


def reg(domain, days, expires_days=300):
    return RegistrationReport((RegistrationInfo(domain, NOW - timedelta(days=days), NOW + timedelta(days=expires_days), "Example Registrar"),))


def tls(host="example.com", verified=True, error=None, https=True, days_old=60, days_left=30, protocol="TLSv1.3", issuer="Example CA"):
    cert = CertInfo(host, issuer, NOW - timedelta(days=days_old), NOW + timedelta(days=days_left), (host,), False)
    return TlsReport(host, 443, https, True, verified, error, protocol, cert)

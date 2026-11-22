
from infrastructure.external_services.guarded_http import GuardedHttpClient
from infrastructure.external_services.network_policy import NetworkPolicy
from modules.link_analysis.domain.url_model import parse_url
from modules.link_analysis.infrastructure.http_page_fetcher import HttpPageFetcher
from tests.fixtures.fakes import MappingResolver


async def fetch(client, site, host, path="/", profile="scanner", **kw):
    return await HttpPageFetcher(client, **kw).fetch_journey(parse_url(site.url(host, path)), profile)


async def test_follows_http_redirect_chain_and_parses_final_page(client, site):
    r = await fetch(client, site, "short.test", "/abc")
    assert r.outcome == "ok" and [h.via for h in r.hops] == ["initial", "http_redirect", "http_redirect"]
    assert [h.status for h in r.hops] == [302, 302, 200] and r.final_url.endswith("/signin")
    assert r.page.title.startswith("PayPal") and any(f.action and "collector.test" in f.action for f in r.page.forms)


async def test_follows_meta_refresh_and_javascript_redirects(client, site):
    meta = await fetch(client, site, "meta.test")
    assert [h.via for h in meta.hops] == ["initial", "meta_refresh"] and meta.final_url.endswith("/signin")
    js = await fetch(client, site, "js.test")
    assert [h.via for h in js.hops] == ["initial", "javascript"] and "login-paypa1.test" in js.final_url


async def test_loop_and_redirect_limit_are_reported_not_endless(client, site):
    assert (await fetch(client, site, "loop.test")).outcome == "redirect_loop"
    limited = await fetch(client, site, "short.test", "/abc", max_redirects=1)
    assert limited.outcome == "too_many_redirects" and len(limited.hops) == 2


async def test_download_disguised_as_pdf_is_sniffed_from_first_bytes(client, site):
    r = await fetch(client, site, "dl.test", "/invoice.pdf")
    h = r.hops[-1]
    assert h.content_type == "application/pdf" and h.sniffed == "executable" and r.page is None     # claimed PDF, really an EXE; body never parsed


async def test_scanner_and_browser_profiles_can_see_different_pages(client, site):
    s, b = await fetch(client, site, "cloak.test", profile="scanner"), await fetch(client, site, "cloak.test", profile="browser")
    assert s.page.title == "Coming soon" and b.page.title.startswith("PayPal")
    assert s.fingerprint != b.fingerprint


async def test_failures_are_classified(client, site):
    assert (await fetch(client, site, "nonexistent-host.invalid")).outcome == "dns_failed"
    r = await HttpPageFetcher(client).fetch_journey(parse_url("ftp://files.example/x"), "scanner")
    assert r.outcome == "not_fetchable"


async def test_default_policy_refuses_to_follow_into_private_space(site):
    strict = NetworkPolicy(allowed_ports=frozenset({site.port}))                   # allow_private_networks defaults to False
    c = GuardedHttpClient(strict, MappingResolver(strict, site.host_map))
    try:
        r = await HttpPageFetcher(c).fetch_journey(parse_url(site.url("login-paypa1.test", "/signin")), "scanner")
        assert r.outcome == "blocked" and r.page is None and r.hops[0].status is None
        direct = await HttpPageFetcher(c).fetch_journey(parse_url(f"http://127.0.0.1:{site.port}/"), "scanner")
        assert direct.outcome == "blocked"
    finally:
        await c.aclose()

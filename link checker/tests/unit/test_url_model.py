"""The parser must read links the way a browser does, because attackers exploit the differences."""
import pytest

from modules.link_analysis.domain.url_model import parse_url


@pytest.mark.parametrize("raw,host,kind", [
    ("https://trusted.com@evil-site.com/login", "evil-site.com", "domain"),
    ("https://evil.com\\@good.com/x", "evil.com", "domain"),           # backslash ends the authority in browsers
    ("https:///evil.com", "evil.com", "domain"),
    ("https:\\\\evil.com\\a", "evil.com", "domain"),
    ("ht\ttps://a.com", "a.com", "domain"),                             # tabs are stripped
    ("http://3232235777/a", "192.168.1.1", "ipv4"),                     # decimal IP
    ("http://0xC0.0xA8.0.1/", "192.168.0.1", "ipv4"),                   # hex IP
    ("http://0300.0250.0.1:8080/", "192.168.0.1", "ipv4"),              # octal IP
    ("https://１２７.０.０.１/", "127.0.0.1", "ipv4"),                    # full-width digits
    ("https://evil%2ecom/", "evil.com", "domain"),                      # percent-encoded dot
    ("https://ex。ample.com", "ex.ample.com", "domain"),                # ideographic full stop
    ("https://[::1]:8443/", "::1", "ipv6"),
    ("paypal.com/login", "paypal.com", "domain"),                       # no scheme -> https assumed
    ("example.com:8080/x", "example.com", "domain"),
])
def test_browser_equivalent_host(raw, host, kind):
    u = parse_url(raw)
    assert (u.host, u.host_kind) == (host, kind)


def test_userinfo_and_port_and_flags():
    u = parse_url("https://secure.paypal.com@login.evil.co.uk:444/a?b=1#c")
    assert u.userinfo == "secure.paypal.com" and u.registrable == "evil.co.uk" and u.port == 444
    assert u.subdomain_labels == ("login",) and "userinfo" in u.flags
    assert "backslash_at_trick" in parse_url("https://evil.com\\@good.com/").flags
    assert "nonstandard_ip_notation" in parse_url("http://0x7f.1/").flags


def test_punycode_and_homograph_forms():
    u = parse_url("https://pаypal.com")            # Cyrillic а
    assert u.host == "xn--pypal-4ve.com" and u.host_unicode == "pаypal.com" and "punycode" in u.flags


@pytest.mark.parametrize("raw,scheme", [("javascript:alert(1)", "javascript"), ("data:text/html,<b>", "data"), ("mailto:a@b.c", "mailto"),
                                       ("ms-msdt:/id x", "ms-msdt"), ("C:\\Windows\\x.exe", "file"), ("\\\\server\\share", "file")])
def test_non_web_schemes_are_never_hosts(raw, scheme):
    u = parse_url(raw)
    assert u.scheme == scheme and not u.is_web


@pytest.mark.parametrize("raw", ["https://exa mple.com", "https://a.com:99999/", "https://trusted.com%40evil.com/", "http://[::1", "", "   "])
def test_garbage_never_raises(raw):
    u = parse_url(raw)
    assert u.host_kind in ("invalid", "none", "domain")


def test_fetch_url_drops_userinfo_and_fragment():
    assert parse_url("https://a@b.com/p?q=1#frag").fetch_url == "https://b.com/p?q=1"


def test_unknown_tld_still_splits_label():
    u = parse_url("https://paypa1-login.example/")
    assert (u.label, u.suffix, u.registrable) == ("paypa1-login", "example", "paypa1-login.example")

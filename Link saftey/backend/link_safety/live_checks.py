from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

import dns.resolver
from publicsuffixlist import PublicSuffixList

from .errors import InspectionError, PolicyBlocked
from .network import follow_redirects, request_public, resolve_public
from .url_analysis import finish_assessment, normalize_url


_PSL = PublicSuffixList(accept_unknown=True)
_BOOTSTRAP = {
    "dns": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}
_bootstrap_cache: dict[str, tuple[float, dict]] = {}
_phishtank_cache: OrderedDict[str, tuple[float, dict[str, str]]] = OrderedDict()
_phishtank_cache_lock = threading.Lock()
_analysis_update_lock = threading.Lock()
_STATUS_PRIORITY = {"pending": 0, "clear": 1, "error": 2, "blocked": 3, "warning": 4}


def _is_html_content_type(value: str) -> bool:
    media_type = value.split(";", 1)[0].strip().lower()
    return media_type in {"text/html", "application/xhtml+xml"}


def _update(analysis: dict, check_id: str, status: str, detail: str) -> None:
    if status not in _STATUS_PRIORITY:
        raise ValueError("Unsupported check status.")
    # Multiple live checks run in worker threads and can update shared findings.
    # Keep each status/detail pair atomic and never replace a stronger finding
    # (for example, a redirect downgrade warning) with a later success result.
    with _analysis_update_lock:
        item = next((entry for entry in analysis["checks"] if entry["id"] == check_id), None)
        if item is not None:
            current = item.get("status", "pending")
            if _STATUS_PRIORITY.get(current, 0) > _STATUS_PRIORITY[status]:
                return
            item["status"] = status
            item["detail"] = _clean_detail(detail)


def _clean_detail(value: str) -> str:
    value = re.sub(r"[\r\n\t\x00-\x1f]", " ", str(value))
    return value[:900]


def _failure(analysis: dict, check_ids: list[str], error: BaseException) -> None:
    status = "blocked" if isinstance(error, PolicyBlocked) else "error"
    safe = "The request was blocked by the outbound safety policy." if status == "blocked" else _safe_error(error)
    for check_id in check_ids:
        _update(analysis, check_id, status, safe)


def _safe_error(error: BaseException) -> str:
    name = type(error).__name__
    if isinstance(error, InspectionError):
        text = str(error)
        if len(text) < 160 and text.isascii() and not re.search(r"https?://|[?&](?:token|key|password)=", text, re.I):
            return text
    return f"The lookup could not complete ({name})."


def _strict_json_loads(raw: bytes | str):
    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON keys are not accepted.")
            result[key] = value
        return result

    def reject_constant(_value: str):
        raise ValueError("Non-standard JSON constants are not accepted.")

    return json.loads(raw, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_constant)


def _json_response(url: str, *, method: str = "GET", body: bytes | None = None, content_type: str | None = None, limit: int = 256 * 1024, timeout: float = 3.0) -> dict:
    headers = {"Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = content_type
    response = request_public(url, method=method, body=body, headers=headers, max_bytes=limit, timeout=timeout)
    if not 200 <= response.status < 300:
        raise InspectionError(f"Lookup service returned HTTP {response.status}.")
    if response.truncated:
        raise InspectionError("The lookup response exceeded its size limit.")
    try:
        value = _strict_json_loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise InspectionError("Lookup service returned invalid JSON.") from exc
    if not isinstance(value, dict):
        raise InspectionError("Lookup service returned an unexpected response.")
    return value


def _rdap_bootstrap(kind: str) -> dict:
    cached = _bootstrap_cache.get(kind)
    now = time.monotonic()
    if cached and cached[0] > now:
        return cached[1]
    data = _json_response(_BOOTSTRAP[kind], limit=1024 * 1024)
    _bootstrap_cache[kind] = (now + 86400, data)
    return data


def _rdap_domain_base(host: str) -> str:
    data = _rdap_bootstrap("dns")
    labels = host.lower().split(".")
    for index in range(len(labels) - 1, -1, -1):
        suffix = ".".join(labels[index:])
        for service in data.get("services", []):
            if isinstance(service, list) and len(service) == 2 and isinstance(service[0], list) and isinstance(service[1], list):
                if any(isinstance(item, str) and item.lower() == suffix for item in service[0]):
                    for base in service[1]:
                        if isinstance(base, str) and base.startswith("https://"):
                            return base.rstrip("/") + "/"
    raise InspectionError("No RDAP registry is published for this domain suffix.")


def _domain_age(host: str) -> tuple[str, str]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        raise InspectionError("Registration age is unavailable for an IP address.")
    domain = _PSL.privatesuffix(host)
    if not domain:
        raise InspectionError("A registrable domain could not be determined.")
    base = _rdap_domain_base(domain)
    data = _json_response(base + "domain/" + domain, limit=256 * 1024, timeout=2.5)
    if data.get("ldhName") and str(data["ldhName"]).lower() != domain.lower():
        raise InspectionError("The registry response did not match the queried domain.")
    created = next((event.get("eventDate") for event in data.get("events", [])
                    if isinstance(event, dict) and re.search(r"registration|registered", str(event.get("eventAction", "")), re.I)), None)
    if not created:
        raise InspectionError("The registry did not publish a registration date.")
    try:
        registered = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise InspectionError("The registry published an invalid registration date.") from exc
    days = max(0, (datetime.now(timezone.utc) - registered.astimezone(timezone.utc)).days)
    message = f"The domain was registered on {registered.date().isoformat()} ({days} days ago)."
    if days < 90:
        message += " A recent registration merits extra care."
    return ("warning" if days < 90 else "clear", message)


def _ip_rdap_base(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    data = _rdap_bootstrap("ipv4" if address.version == 4 else "ipv6")
    for service in data.get("services", []):
        if not isinstance(service, list) or len(service) != 2:
            continue
        for network in service[0] if isinstance(service[0], list) else []:
            try:
                if address in ipaddress.ip_network(network, strict=False):
                    for base in service[1] if isinstance(service[1], list) else []:
                        if isinstance(base, str) and base.startswith("https://"):
                            return base.rstrip("/") + "/"
            except ValueError:
                continue
    raise InspectionError("No RDAP registry is published for this address.")


def _origin_record(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        query = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        query = address.exploded.replace(":", "")
        query = ".".join(reversed(query)) + ".origin6.asn.cymru.com"
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 0.7
    resolver.lifetime = 1.5
    answers = resolver.resolve(query, "TXT", lifetime=1.5, search=False)
    text = "".join(part.decode("ascii", "replace") if isinstance(part, bytes) else str(part) for answer in answers for part in answer.strings)
    values = [part.strip() for part in text.split("|")]
    if len(values) < 4 or not values[0].isdigit():
        raise InspectionError("No public BGP origin record was returned.")
    return f"AS{values[0]}, prefix {values[1]}, registry country {values[2]}"


class _PageSignals(HTMLParser):
    def __init__(self, origin: str):
        super().__init__(convert_charrefs=True)
        self.origin = origin
        self.text: list[str] = []
        self.password_fields = 0
        self.external_form = 0
        self.hidden_controls = 0
        self.overlay_like = 0
        self.in_title = False
        self.title: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "input":
            if values.get("type", "").lower() == "password":
                self.password_fields += 1
            if values.get("type", "").lower() == "hidden":
                self.hidden_controls += 1
        if tag.lower() == "form" and values.get("action"):
            action = values["action"].strip()
            if action and not action.startswith("#"):
                candidate_parts = urlsplit(urljoin(self.origin + "/", action))
                origin_parts = urlsplit(self.origin)
                candidate_port = candidate_parts.port or (443 if candidate_parts.scheme == "https" else 80)
                origin_port = origin_parts.port or (443 if origin_parts.scheme == "https" else 80)
                same_origin = (
                    candidate_parts.scheme.lower() == origin_parts.scheme.lower()
                    and (candidate_parts.hostname or "").lower() == (origin_parts.hostname or "").lower()
                    and candidate_port == origin_port
                )
                if not same_origin:
                    self.external_form += 1
        style = values.get("style", "").lower().replace(" ", "")
        if ("position:fixed" in style or "position:absolute" in style) and re.search(r"z-index:(?:[1-9]\d{2,}|\d{4,})", style) and any(item in style for item in ("100vw", "100vh", "inset:0", "top:0")):
            self.overlay_like += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title.append(data)
        if len(self.text) < 6000:
            self.text.append(data)


def _inspect_page(raw_url: str, analysis: dict) -> None:
    response, redirects, final_url = follow_redirects(raw_url, max_hops=5, max_bytes=384 * 1024, timeout=4.0, request_timeout=2.4)
    original_scheme, original_host = urlsplit(raw_url).scheme, urlsplit(raw_url).hostname or ""
    final = urlsplit(final_url)
    if original_scheme == "https" and final.scheme == "http":
        _update(analysis, "tls", "warning", "The HTTPS destination redirected to unencrypted HTTP.")
    cross_host = sorted({to_host for from_host, to_host, _from_scheme, _to_scheme in redirects
                         if from_host.lower() != to_host.lower()})
    downgraded = any(from_scheme == "https" and to_scheme == "http"
                     for _from_host, _to_host, from_scheme, to_scheme in redirects)
    if downgraded:
        _update(analysis, "tls", "warning", "At least one redirect downgraded the connection from HTTPS to unencrypted HTTP.")
    if cross_host:
        _update(analysis, "redirect", "warning", "The destination crossed to " + ", ".join(cross_host[:3]) + f" during {len(redirects)} redirect(s).")
    elif redirects:
        _update(analysis, "redirect", "clear", f"The destination redirected {len(redirects)} time(s) without changing host.")
    else:
        current = next(item for item in analysis["checks"] if item["id"] == "redirect")
        if current["status"] != "warning":
            _update(analysis, "redirect", "clear", "No HTTP redirect was returned by the destination.")
    if original_host in {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at", "rb.gy", "lnkd.in"}:
        _update(analysis, "shortener", "clear", "Expanded through " + str(len(redirects)) + " redirect(s) to " + (final.hostname or "the final destination") + ". Confirm the final host before continuing.")

    content_type = response.headers.get("content-type", "")
    if not _is_html_content_type(content_type):
        for key in ("forms", "formaction", "brand", "hidden", "cloaking"):
            _update(analysis, key, "clear", "The destination did not return an HTML page to inspect.")
        return
    parser = _PageSignals(f"{final.scheme}://{final.netloc}")
    try:
        parser.feed(response.body.decode("utf-8", "replace"))
        parser.close()
    except (ValueError, AssertionError):
        raise InspectionError("The HTML page could not be parsed within safe limits.")
    text = " ".join(parser.text)
    if parser.password_fields:
        _update(analysis, "forms", "warning", f"Found {parser.password_fields} password field(s). Only static HTML was inspected; the page was not rendered.")
    else:
        _update(analysis, "forms", "clear", "No password inputs were found in the returned static HTML.")
    if parser.external_form:
        _update(analysis, "formaction", "warning", f"Found {parser.external_form} form(s) posting off-origin or using a different/insecure scheme or port.")
    else:
        _update(analysis, "formaction", "clear", "No off-origin or insecure form action was found in the returned HTML.")
    urgency = re.search(r"\b(?:urgent|immediately|act now|account (?:locked|suspended|restricted)|verify (?:your )?(?:account|identity)|password expires|payment failed|unusual activity|within \d+ hours|limited time|avoid suspension)\b", text, re.I)
    brand = re.search(r"\b(?:paypal|microsoft|google|amazon|apple|netflix|facebook|instagram|whatsapp|discord|steam|bank of america|chase|dhl|fedex)\b", text, re.I)
    registered = _PSL.privatesuffix(final.hostname or "") or final.hostname or ""
    if brand and registered.lower() not in {"paypal.com", "microsoft.com", "google.com", "amazon.com", "apple.com", "netflix.com", "facebook.com", "discord.com", "instagram.com", "whatsapp.com", "steampowered.com", "bankofamerica.com", "chase.com", "dhl.com", "fedex.com"}:
        _update(analysis, "brand", "warning", "Page text mentions a well-known brand, but the registered domain differs. This may be legitimate third-party content.")
    elif urgency:
        _update(analysis, "brand", "warning", "Urgency or account-pressure wording was found in the returned page text. Context may be legitimate.")
    else:
        _update(analysis, "brand", "clear", "No built-in brand mismatch or urgent account-pressure phrase was found in the returned text.")
    frame_header = response.headers.get("x-frame-options", "")
    csp = response.headers.get("content-security-policy", "")
    frame_safe = frame_header.lower() in {"deny", "sameorigin"} or bool(re.search(r"frame-ancestors\s+(?:'none'|'self'|[a-z][a-z0-9+.-]*://[^;\s]+)", csp, re.I))
    if parser.hidden_controls or parser.overlay_like:
        _update(analysis, "hidden", "warning", f"Found {parser.hidden_controls} hidden control(s) and {parser.overlay_like} overlay-like element(s) in static HTML/CSS. Browser rendering was not performed.")
    elif not frame_safe:
        _update(analysis, "hidden", "warning", "No restrictive frame-ancestors or X-Frame-Options header was found. This is a framing weakness, not proof of malicious behavior.")
    else:
        _update(analysis, "hidden", "clear", "No suspicious hidden controls were found and the response limits framing. The page was not rendered.")
    if response.truncated:
        for key in ("forms", "formaction", "brand", "hidden"):
            item = next(entry for entry in analysis["checks"] if entry["id"] == key)
            item["detail"] = (item["detail"] + " Only the first 384 KB of HTML was inspected.")[:900]

    alternate, alternate_redirects, _alternate_url = follow_redirects(raw_url, max_hops=5, max_bytes=384 * 1024, timeout=4.0, request_timeout=2.4,
        user_agent="Googlebot/2.1 (+https://www.google.com/bot.html)")
    if not _is_html_content_type(alternate.headers.get("content-type", "")):
        _update(analysis, "cloaking", "warning", "The browser response was HTML but the crawler response was not HTML. This may indicate user-agent-dependent content; scripts were not executed.")
        return
    bot = _PageSignals(f"{urlsplit(_alternate_url).scheme}://{urlsplit(_alternate_url).netloc}")
    try:
        bot.feed(alternate.body.decode("utf-8", "replace"))
        bot.close()
    except (ValueError, AssertionError):
        _update(analysis, "cloaking", "error", "The crawler HTML response could not be parsed within safe limits.")
        return
    bot_text = " ".join(bot.text)
    title_a = " ".join(parser.title).strip().lower()
    title_b = " ".join(bot.title).strip().lower()
    ratio = max(len(text), len(bot_text)) / max(1, min(len(text), len(bot_text)))
    primary_origin = (final.scheme.lower(), (final.hostname or "").lower())
    alternate_parts = urlsplit(_alternate_url)
    alternate_origin = (alternate_parts.scheme.lower(), (alternate_parts.hostname or "").lower())
    changed_destination = primary_origin != alternate_origin
    changed_redirect_path = redirects != alternate_redirects
    different_truncation = response.truncated != alternate.truncated
    if changed_destination or changed_redirect_path or different_truncation or response.status != alternate.status or (title_a and title_b and title_a != title_b) or ratio >= 3.5:
        _update(analysis, "cloaking", "warning", f"Responses differed by user agent (HTTP {response.status} vs {alternate.status}); destination changed: {str(changed_destination).lower()}, redirect path changed: {str(changed_redirect_path).lower()}. Personalization may be normal; scripts were not run.")
    else:
        _update(analysis, "cloaking", "clear", "Browser and crawler requests returned similar status, title, and text size. JavaScript behavior was not compared.")


def _inspect_tls(host: str, scheme: str, analysis: dict) -> None:
    if scheme != "https":
        _update(analysis, "tls", "warning", "The submitted URL uses HTTP and has no TLS encryption.")
        return
    try:
        netloc = f"[{host}]" if ":" in host else host
        target = urlunsplit(("https", netloc, "/", "", ""))
        response = request_public(target, max_bytes=1, timeout=3.2)
        if response.status:
            _update(analysis, "tls", "clear", "The TLS chain and requested hostname validated successfully.")
    except Exception as exc:
        text = str(exc).upper() + " " + type(exc).__name__.upper()
        if any(marker in text for marker in ("CERTIFICATE", "CERT_", "SSLERROR", "SSLCERT")):
            _update(analysis, "tls", "warning", "TLS certificate validation failed. Do not send sensitive information to this destination.")
        else:
            _failure(analysis, ["tls"], exc)


def _inspect_hosting(host: str, analysis: dict) -> None:
    records = resolve_public(host)
    addresses = [address for address, _family in records][:3]
    notes: list[str] = []
    for address in addresses[:2]:
        try:
            notes.append(address + " (" + _origin_record(address) + ")")
        except Exception:
            try:
                data = _json_response(_ip_rdap_base(address) + "ip/" + address, limit=128 * 1024, timeout=2.3)
                name = str(data.get("name") or data.get("handle") or "network registry")[:80]
                country = str(data.get("country") or "")[:2]
                notes.append(address + " (" + name + (", registry country " + country if country else "") + ")")
            except Exception:
                continue
    if not notes:
        raise InspectionError("DNS resolved to public IP address(es), but ASN and registry enrichment was unavailable.")
    _update(analysis, "hosting", "clear", "Resolved to public IP address(es): " + "; ".join(notes) + ". Registry country is not physical geolocation; no abuse reputation was inferred.")


def _phishtank(url: str, app_key: str) -> dict[str, str]:
    import hashlib

    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    now = time.monotonic()
    with _phishtank_cache_lock:
        cached = _phishtank_cache.get(digest)
        if cached and cached[0] > now:
            _phishtank_cache.move_to_end(digest)
            return dict(cached[1])
        if cached:
            _phishtank_cache.pop(digest, None)
    form = {"url": url, "format": "json"}
    if app_key:
        form["app_key"] = app_key
    response = request_public("https://checkurl.phishtank.com/checkurl/", method="POST",
        body=urlencode(form).encode("ascii"), headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", "User-Agent": "PhishTank/LinkSafety-URL-Check/0.3"},
        max_bytes=64 * 1024, timeout=3.0)
    if response.status == 403:
        raise InspectionError("PhishTank returned HTTP 403; its security challenge blocked the lookup.")
    if not 200 <= response.status < 300:
        raise InspectionError(f"PhishTank returned HTTP {response.status}.")
    if response.truncated:
        raise InspectionError("PhishTank response exceeded its size limit.")
    try:
        data = _strict_json_loads(response.body.decode("utf-8"))
        result = data["results"]
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError, KeyError, TypeError) as exc:
        raise InspectionError("PhishTank returned an unexpected response.") from exc
    if not isinstance(result, dict) or "in_database" not in result:
        raise InspectionError("PhishTank returned an unexpected response.")
    in_database = str(result.get("in_database", "")).lower() in {"true", "1", "yes", "y"}
    verified = str(result.get("verified", "")).lower() in {"true", "1", "yes", "y"}
    valid = str(result.get("valid", "")).lower() in {"true", "1", "yes", "y"}
    if in_database:
        status = "warning"
        detail = "PhishTank has a verified, currently valid phishing match. Treat this URL as unsafe." if verified and valid else "PhishTank has a reported match, but it is not confirmed as both verified and currently valid. Review before proceeding."
    else:
        status = "clear"
        detail = "No match was found in PhishTank at lookup time. This is not a safety guarantee."
    finding = {"status": status, "detail": detail}
    with _phishtank_cache_lock:
        _phishtank_cache[digest] = (time.monotonic() + 300, finding)
        _phishtank_cache.move_to_end(digest)
        while len(_phishtank_cache) > 500:
            _phishtank_cache.popitem(last=False)
    return dict(finding)


async def run_live_checks(analysis: dict, *, phishtank_app_key: str = "") -> dict:
    url = analysis["normalized"]
    parsed, host, _normalized = normalize_url(url)

    async def run(check_ids: list[str], func, *args):
        try:
            result = await asyncio.to_thread(func, *args)
            if isinstance(result, dict) and "status" in result:
                _update(analysis, check_ids[0], result["status"], result["detail"])
            elif isinstance(result, tuple) and len(result) == 2:
                _update(analysis, check_ids[0], result[0], result[1])
            elif isinstance(result, str):
                _update(analysis, check_ids[0], "clear", result)
        except Exception as exc:
            _failure(analysis, check_ids, exc)

    tasks = [
        run(["blocklist"], _phishtank, url, phishtank_app_key),
        run(["age"], _domain_age, host),
        run(["hosting"], _inspect_hosting, host, analysis),
        run(["tls"], _inspect_tls, host, parsed.scheme, analysis),
        run(["forms", "formaction", "brand", "hidden", "cloaking", "redirect", "shortener"], _inspect_page, url, analysis),
    ]
    await asyncio.gather(*tasks)
    return finish_assessment(analysis)

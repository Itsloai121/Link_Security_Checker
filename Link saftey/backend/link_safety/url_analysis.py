from __future__ import annotations

import ipaddress
import re
from .ip_policy import is_public_ip
from urllib.parse import SplitResult, urlsplit, urlunsplit

from publicsuffixlist import PublicSuffixList


_PSL = PublicSuffixList(accept_unknown=True)
_CONTROL = re.compile(r"[\x00-\x20\x7f\\]")
_ENCODED = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)
_BRAND = re.compile(r"paypa[il1]|micros[o0]ft|g[o0]{2}gle|amaz[o0]n|apple|netflix|faceb[o0]{2}k|instagram|whatsapp|discord|steam|bankofamerica|chase|dhl|fedex", re.I)
_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at", "rb.gy", "lnkd.in"}
_META = {
    "blocklist": ("Threat & phishing blocklist", "Checks the submitted URL against PhishTank's phishing database."),
    "age": ("Domain age & freshness", "A recent registration can be a useful risk signal, but is not proof of abuse."),
    "hosting": ("Hosting IP, ASN & registry risk", "Public routing and registry records add infrastructure context; country codes are not precise geolocation."),
    "forms": ("Login & credential forms", "Credential prompts can be risky on unfamiliar sites."),
    "formaction": ("Form action destination", "A form may submit credentials to a different host."),
    "brand": ("Brand impersonation & urgency", "Brand clues and pressure language can indicate social engineering."),
    "hidden": ("Hidden elements & clickjacking", "Hidden controls and framing policy can affect visitor safety."),
    "cloaking": ("Cloaking & bot evasion", "Different responses to browser and crawler user agents can conceal behavior."),
    "tls": ("TLS certificate validity", "Certificates should be valid and match the requested host."),
    "redirect": ("Open redirect & cross-domain jump", "Redirects can move a visitor to a different destination."),
    "shortener": ("Shortener & redirect unwrapping", "Short links hide their final destination until expanded."),
}


def normalize_url(value: str) -> tuple[SplitResult, str, str]:
    if not isinstance(value, str) or not value or len(value) > 16384 or _CONTROL.search(value):
        raise ValueError("Enter a complete public HTTP or HTTPS URL.")
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing username or password fields are not accepted.")
        host = parsed.hostname.rstrip(".").lower()
        if not host or "%" in host:
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None:
            if not is_public_ip(address):
                raise ValueError("Only public internet destinations can be scanned.")
            ascii_host = address.compressed
            display_host = address.compressed
        else:
            if ":" in host or host.endswith("."):
                raise ValueError
            labels = host.split(".")
            if len(labels) < 2 or any(not label for label in labels):
                raise ValueError
            encoded_labels = [label.encode("idna").decode("ascii").lower() for label in labels]
            if any(len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in encoded_labels):
                raise ValueError
            for label in encoded_labels:
                if label.startswith("xn--"):
                    try:
                        label.encode("ascii").decode("idna")
                    except UnicodeError as exc:
                        raise ValueError("The URL contains an invalid internationalized domain label.") from exc
            ascii_host = ".".join(encoded_labels)
            # Reject ambiguous legacy numeric host forms such as 127.1 or integer IPv4.
            if all(re.fullmatch(r"[0-9]+", label) for label in encoded_labels):
                raise ValueError
            if not _PSL.privatesuffix(ascii_host):
                raise ValueError
            display_host = ascii_host
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        if port not in (None, 80, 443):
            raise ValueError("Live checks only allow standard HTTP and HTTPS ports (80 and 443).")
        if (scheme == "http" and port == 443) or (scheme == "https" and port == 80):
            raise ValueError("The URL uses a port that does not match its scheme.")
        netloc = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
        if port and port != (80 if scheme == "http" else 443):
            netloc += f":{port}"
        normalized = urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, parsed.fragment))
        return parsed._replace(scheme=scheme), ascii_host, normalized
    except (UnicodeError, ValueError, TypeError) as exc:
        if isinstance(exc, ValueError) and str(exc) and str(exc) not in {"Invalid IPv6 URL", "Port could not be cast to integer value as ''"}:
            raise
        raise ValueError("Enter a valid public URL such as https://example.com/path.") from exc


def analyze_url(url_text: str, max_url_length: int = 4096) -> dict:
    if not isinstance(url_text, str):
        raise ValueError("The url field must be a string.")
    url_text = url_text.strip()
    if not url_text:
        raise ValueError("Enter a URL to analyze.")
    if len(url_text) > max_url_length:
        raise ValueError(f"URL must be {max_url_length} characters or fewer.")
    parsed, host, normalized = normalize_url(url_text)
    path = parsed.path or "/"
    risk_count = 0
    checks: list[dict[str, str]] = []

    def add(identifier: str, title: str, description: str, status: str, detail: str) -> None:
        nonlocal risk_count
        if status == "warning":
            risk_count += 1
        checks.append({"id": identifier, "title": title, "description": description, "status": status, "detail": detail[:900]})

    def signal(identifier: str, title: str, desc: str, flagged: bool, yes: str, no: str) -> None:
        add(identifier, title, desc, "warning" if flagged else "clear", yes if flagged else no)

    userinfo = parsed.username is not None or parsed.password is not None or "@" in parsed.netloc
    signal("userinfo", "User-info (@) masking", "The @ separator can make decoy text look like the destination host.", userinfo,
           f"This URL contains user-info or an @ sign. The actual host is {host}.", "No user-info section or @ sign was found.")
    signal("scheme", "Dangerous scheme & protocol", "Only ordinary web links use HTTP or HTTPS.", False,
           "Only HTTP and HTTPS URLs are accepted.", f"The protocol is {parsed.scheme.upper()}.")
    signal("https", "HTTPS scheme", "HTTPS encrypts traffic in transit, but does not prove a site is trustworthy.", parsed.scheme != "https",
           "The URL does not use HTTPS.", "The URL uses HTTPS. Certificate chain and hostname are checked separately below.")
    try:
        unicode_host = host.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise ValueError("The URL contains an invalid internationalized domain name.") from exc
    signal("homograph", "Homograph & punycode", "Internationalized domains can use lookalike characters.",
           unicode_host != host, f"This host has an internationalized/punycode representation: {unicode_host}.",
           "No punycode label was detected. Mixed-script lookalikes need deeper analysis.")
    labels = host.split(".")
    trusted_roots = {"paypal.com", "microsoft.com", "google.com", "amazon.com", "apple.com", "netflix.com", "facebook.com", "discord.com"}
    root = _PSL.privatesuffix(host) or host
    suspicious_brand = bool(_BRAND.search(".".join(labels[:-1]) + " " + path)) and root not in trusted_roots
    signal("lookalike", "Lookalike & typosquatting", "Brand-like spellings on unrelated domains may impersonate a trusted service.", suspicious_brand,
           "A common brand-like string appears in this host or path. Confirm the registrable domain independently.",
           "No obvious match to the built-in brand heuristic was found.")
    deep = len(labels) >= 5 or any(re.fullmatch(r"secure|login|account|verify|signin|bank", label, re.I) for label in labels[:-2])
    signal("subdomain", "Subdomain spoofing", "A trusted-looking word in a subdomain does not make the root domain trusted.", deep,
           f"The host has {len(labels)} labels or a security-themed subdomain. Root-domain reputation is not implied.",
           "No unusually deep or obvious security-themed subdomain was found.")
    path_lower = path.lower()
    misleading_doc = bool(re.search(r"\.(?:pdf|docx?|xlsx?|txt)(?:/|$)", path_lower) and not re.search(r"\.(?:pdf|docx?|xlsx?|txt)$", path_lower))
    signal("portpath", "Port & path anomaly", "Unusual ports and misleading paths can hide a service or download.", misleading_doc,
           "A document-like extension appears before more path segments.", "No non-standard port or obvious misleading document path was found.")
    escapes = len(_ENCODED.findall(url_text))
    obfuscated = escapes >= 4 or bool(re.search(r"(?:0x[0-9a-f]{2,}|\\u[0-9a-f]{4}|[a-z0-9+/]{28,}={0,2})", url_text, re.I))
    signal("obfuscation", "URL obfuscation & encoding", "Heavy encoding can conceal characters or destinations.", obfuscated,
           f"Found {escapes} percent-encoded bytes or a string matching a common encoded-payload pattern.",
           "No heavy percent-encoding or obvious encoded blob was found.")
    risky_file = bool(re.search(r"\.(?:exe|msi|apk|iso|zip|js|vbs|scr|bat|dll)$", path_lower))
    signal("download", "Auto-download & file trigger", "Executable and script downloads carry elevated risk.", risky_file,
           "The path ends with a potentially executable or archive file extension.", "No risky file extension is visible in the URL path.")
    redirectish = bool(re.search(r"https?://|%2f%2f", url_text, re.I) and re.search(r"(?:url|redirect|return|next|continue)=", url_text, re.I))
    signal("redirect", "Open redirect & cross-domain jump", "Redirect parameters can send users to a different host.", redirectish,
           "A redirect-like parameter and destination pattern is present; it has not yet been followed.", "No obvious redirect parameter was found. Redirect behavior is checked separately.")
    known_shortener = host in _SHORTENERS
    signal("shortener", "Shortener & redirect unwrapping", "Short links hide their final destination until expanded.", known_shortener,
           "This is a known shortener domain. The final destination will be checked through bounded redirects.",
           "The host is not in the built-in shortener list; redirects are checked separately.")
    add("display", "Display text vs destination", "A link label can differ from the real URL destination.", "clear",
        f"The destination can be inspected as {parsed.scheme}://{host}. A displayed label was not supplied.")
    for identifier, (title, description) in _META.items():
        if identifier not in {"redirect", "shortener"}:
            add(identifier, title, description, "pending", {
                "blocklist": "Checking the exact submitted URL against PhishTank.",
                "age": "Checking domain registration data with RDAP.",
                "hosting": "Checking public DNS, BGP origin, and registry records.",
                "forms": "Inspecting the returned HTML for password fields.",
                "formaction": "Comparing password-form actions with the inspected page origin.",
                "brand": "Checking visible page text for brand mismatch and urgency signals.",
                "hidden": "Checking HTML/CSS signals and framing response headers.",
                "cloaking": "Comparing bounded responses from two user agents.",
                "tls": "Verifying the TLS chain and requested hostname.",
            }[identifier])
    return {
        "input": url_text, "normalized": normalized, "host": host,
        "score": max(0, 100 - risk_count * 12), "verdict": "caution" if risk_count else "incomplete",
        "summary": f"{risk_count} potential concern(s) found." if risk_count else "No obvious URL-structure concerns found. Live checks are in progress.",
        "checks": checks,
    }


def finish_assessment(analysis: dict) -> dict:
    warnings = sum(item["status"] == "warning" for item in analysis["checks"])
    unavailable = sum(item["status"] in {"pending", "error", "blocked"} for item in analysis["checks"])
    confirmed_phishing = any(
        item["id"] == "blocklist" and item["status"] == "warning"
        and "verified, currently valid phishing match" in item["detail"]
        for item in analysis["checks"]
    )
    analysis["score"] = max(0, 100 - warnings * 12)
    if confirmed_phishing:
        analysis["score"] = 0
        analysis["verdict"] = "high"
        analysis["summary"] = "A phishing provider returned a verified, currently valid match. Treat this URL as unsafe."
    else:
        analysis["verdict"] = "high" if warnings >= 3 else "caution" if warnings else "incomplete" if unavailable else "clear"
    if not confirmed_phishing and warnings:
        analysis["summary"] = f"{warnings} potential concern(s) found." + (f" {unavailable} check(s) could not be completed." if unavailable else "")
    elif not confirmed_phishing and unavailable:
        analysis["summary"] = f"No obvious risk signals found in completed checks; {unavailable} check(s) could not be completed."
    elif not confirmed_phishing:
        analysis["summary"] = "No obvious risk signals found in the checks that ran. This screening is not a safety guarantee."
    return analysis

"""Checks 2, 3, 6, 7, 8, 9, 13 - everything that can be learned from the address alone (plus the content type for #13)."""
from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import parse_qsl, unquote

from modules.link_analysis.domain.checks._helpers import pretty_list
from modules.link_analysis.domain.checks.base import Category, CheckContext, CheckSpec, Outcome, Severity as S, fnd
from modules.link_analysis.domain.confusables import LOOKALIKE_SLASH_DOT, ascii_variants, damerau_levenshtein, scripts_in, skeleton
from modules.link_analysis.domain.sniff import DOC_EXT, EXEC_EXT, extension_of
from modules.link_analysis.domain.url_model import DEFAULT_PORTS

_NORM = lambda s: re.sub(r"[^a-z0-9]", "", s)  # noqa: E731
_SEV = {"critical": S.CRITICAL, "high": S.HIGH, "medium": S.MEDIUM, "low": S.LOW, "info": S.INFO}


def _uni_label(ctx: CheckContext) -> str:
    u = ctx.url
    n = len(u.registrable.split("."))
    return ".".join(u.host_unicode.split(".")[-n:]).split(".")[0]


# --------------------------------------------------------------------------------------------------- 3 homograph
class HomographCheck:
    spec = CheckSpec("homograph", 3, "Homograph & Punycode (xn--) Inspection", Category.ADDRESS,
                     "Detects non-Latin or lookalike characters (like Cyrillic or Unicode characters that look like Latin letters) used to disguise a fake domain as a real one.")

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u = ctx.url
        if u.host_kind != "domain":
            return Outcome.clear("The address has no domain name that could be disguised.")
        targets: dict[str, tuple[str, str]] = {}
        for t, d, n in ctx.ref.lookalike_targets:
            targets.setdefault(t, (n, d))  # brands come first, so they win over popular-domain labels
        findings = []
        for ascii_l, uni_l in zip(u.host.split("."), u.host_unicode.split("."), strict=False):
            if uni_l.isascii() and not ascii_l.startswith("xn--"):
                continue
            scripts = scripts_in(uni_l)
            skel = _NORM(skeleton(uni_l))
            hit = targets.get(skel) if skel != _NORM(uni_l) or len(scripts) > 1 else None
            mixed = len(scripts) > 1
            if mixed:
                findings.append(fnd(S.HIGH if "Latin" in scripts else S.MEDIUM, "mixed_scripts",
                                    f"The name “{uni_l}” mixes {' and '.join(sorted(scripts))} letters, a classic way to fake a familiar name.",
                                    Letters_from=", ".join(sorted(scripts))))
            if hit and hit[1] != u.registrable and not ctx.ref.official_brand(u.registrable):
                findings.append(fnd(S.CRITICAL if mixed else S.HIGH, "brand_homograph",
                                    f"“{uni_l}” is built from look-alike characters and reads as “{skel}”, the name of {hit[0]}.",
                                    Looks_like=hit[0], Real_address=u.host))
        slashy = sorted({f"U+{ord(c):04X}" for c in (u.host_raw + (u.userinfo or "")) if c in LOOKALIKE_SLASH_DOT})
        if slashy:
            findings.append(fnd(S.HIGH, "lookalike_separators", "The address contains characters that imitate a slash, dot or hyphen, so part of it only looks like a path.", Characters=", ".join(slashy)))
        for flag, msg in (("bidi_override", "Hidden right-to-left override characters can display the address backwards."),
                          ("invisible_characters", "Invisible characters are hidden inside the address.")):
            if flag in u.flags:
                findings.append(fnd(S.HIGH, flag, msg))
        if "punycode_invalid" in u.flags:
            findings.append(fnd(S.MEDIUM, "punycode_invalid", "The address contains a malformed xn-- (punycode) label."))
        facts = {}
        if "punycode" in u.flags or "idn_host" in u.flags:
            facts = dict(Typed_as=u.host_raw, Real_ASCII_address=u.host, Displayed_as=u.host_unicode)
            if not findings:
                findings.append(fnd(S.INFO, "idn", f"An internationalised domain name; browsers may show it as “{u.host_unicode}”."))
        if not findings:
            return Outcome.clear("Only plain Latin letters, digits and hyphens - no disguised characters.")
        return Outcome.flagged(findings, **facts)


# --------------------------------------------------------------------------------------------------- 2 lookalike
class LookalikeCheck:
    spec = CheckSpec("lookalike", 2, "Lookalike & Typosquatting Detection", Category.ADDRESS,
                     "Checks if the domain mimics a trusted brand using swapped letters, extra words, or slight misspellings (paypa1, micros0ft-login).")

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u, ref = ctx.url, ctx.ref
        if u.host_kind != "domain" or not u.label:
            return Outcome.clear("No domain name to compare with known brands.")
        official = ref.official_brand(u.registrable)
        if official:
            return Outcome.clear(f"This is an official {official.name} domain.", Domain=u.registrable)
        if ref.is_popular(u.registrable):
            return Outcome.clear("A well-known domain with no look-alike signals.", Domain=u.registrable)
        skel = skeleton(_uni_label(ctx))
        norm = _NORM(skel)
        parts = [p for p in re.split(r"[-_.]", skel) if p]
        whole_variants = {_NORM(v) for v in ascii_variants(skel)} - {norm}
        part_variants = {p: {_NORM(v) for v in ascii_variants(p)} - {_NORM(p)} for p in parts}
        best: dict[str, tuple[S, str, str]] = {}

        def note(name: str, sev: S, code: str, msg: str) -> None:
            if name not in best or sev > best[name][0]:
                best[name] = (sev, code, msg)

        for token, dom, name in ref.lookalike_targets:
            if len(token) < 3 or dom == u.registrable:
                continue
            short = len(token) <= 4
            if norm == token:
                note(name, S.MEDIUM if short else S.HIGH, "wrong_domain", f"Uses the name “{token}” but not {name}'s real domain ({dom}).")
            elif len(token) >= 4 and any(token in v for v in part_variants.values()):
                note(name, S.HIGH, "swapped_characters", f"“{u.label}” looks like {name} with characters swapped for look-alikes (digits for letters).")
            elif len(token) >= 6 and norm[:1] == token[:1] and (d := damerau_levenshtein(norm, token, 2)) <= (1 if len(token) < 9 else 2):
                note(name, S.HIGH if d == 1 else S.MEDIUM, "misspelling", f"“{u.label}” is {d} letter{'s' if d > 1 else ''} away from {name} ({token}).")
            elif token in parts and len(parts) > 1:
                extras = [p for p in parts if p != token]
                risky = [p for p in extras if p in ref.sensitive_words]
                note(name, S.HIGH if risky or not short else S.MEDIUM, "extra_words",
                     f"Adds {pretty_list(extras)} to the name {name}, a trick used to look official.")
            elif len(token) >= 6 and (token in norm or any(token in v for v in whole_variants)):
                note(name, S.MEDIUM, "embedded_name", f"“{u.label}” contains the name {name} inside a different domain.")
        if not best:
            return Outcome.clear("The domain does not resemble any known brand.", Domain=u.registrable)
        ranked = sorted(best.items(), key=lambda kv: -kv[1][0])[:3]
        findings = [fnd(sev, code, msg, Brand=name, Domain=u.registrable) for name, (sev, code, msg) in ranked]
        return Outcome.flagged(findings, Domain=u.registrable)


# --------------------------------------------------------------------------------------------- 6 @ / user-info
class UserInfoMaskingCheck:
    spec = CheckSpec("userinfo_masking", 6, "User-Info (@) Masking Check", Category.ADDRESS,
                     "Catches links containing @ (such as https://trusted.com@evil-site.com), where everything before @ is just decoy text and the real host is after @.")

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u = ctx.url
        if u.host_kind == "none":
            return Outcome.clear("Not a web address, so there is no host to mask.")
        findings = []
        if u.userinfo is not None:
            decoy = unquote(u.userinfo)
            decoy_like = bool(re.search(r"[A-Za-z0-9-]+\.[A-Za-z]{2,}", decoy)) or decoy.lower().startswith(("http", "www"))
            if decoy_like:
                findings.append(fnd(S.CRITICAL, "decoy_userinfo", f"Everything before the @ (“{decoy}”) is decoy text. The link really goes to {u.host or u.host_raw}.",
                                    Decoy_text=decoy, Real_host=u.host or u.host_raw))
            elif ":" in decoy:
                findings.append(fnd(S.MEDIUM, "embedded_credentials", "The link carries a username and password before the @, which normal links do not.", Real_host=u.host))
            else:
                findings.append(fnd(S.MEDIUM, "userinfo", "The link has a name before the @, which is unusual and can mislead readers about the real host.", Real_host=u.host))
        if "multiple_at" in u.flags:
            findings.append(fnd(S.HIGH, "multiple_at", "Several @ signs (or an encoded %40) are used to confuse which part is the host."))
        if "backslash_at_trick" in u.flags:
            findings.append(fnd(S.HIGH, "backslash_at", "A backslash before the @ makes browsers and security filters disagree about the host. Browsers go to " + u.host + ".", Browsers_go_to=u.host))
        if "encoded_delimiter_in_host" in u.flags and "%40" in u.host_raw.lower():
            findings.append(fnd(S.HIGH, "encoded_at", "An encoded @ (%40) is hidden inside the host name."))
        if not findings:
            return Outcome.clear("No @ trick: the host is exactly what the link shows.", Host=u.host)
        return Outcome.flagged(findings, Real_host=u.host or u.host_raw)


# ------------------------------------------------------------------------------------------ 7 subdomain spoofing
_TLD_WORDS = ("com", "net", "org", "co", "gov", "edu")


class SubdomainSpoofingCheck:
    spec = CheckSpec("subdomain_spoofing", 7, "Subdomain Spoofing Analysis", Category.ADDRESS,
                     "Inspects deep or deceptive subdomains (like login.secure-bank.example.com) where a familiar word sits in a subdomain while the real root domain is unfamiliar.")

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u, ref = ctx.url, ctx.ref
        if u.host_kind != "domain":
            return Outcome.clear("No domain name, so no subdomains to inspect.")
        facts = dict(Real_root_domain=u.registrable, Subdomains=".".join(u.subdomain_labels) or "none")
        official = ref.official_brand(u.registrable)
        if official:
            return Outcome.clear(f"Every subdomain sits under {official.name}'s own domain.", **facts)
        subs, dotted = u.subdomain_labels, "." + ".".join(u.subdomain_labels) + "."
        findings = []
        known = {d: b.name for b in ref.brands for d in b.domains} | {d: d for d in ref.popular_domains}
        for dom, name in known.items():
            if f".{dom}." in dotted or dotted.endswith(f".{dom}."):
                findings.append(fnd(S.HIGH, "embedded_domain", f"“{dom}” appears as part of the subdomain, but the real site is {u.registrable}.", Looks_like=name, Real_root_domain=u.registrable))
                break
        for label in list(subs) + [u.label]:
            for brand in ref.brands:
                for token in brand.tokens:
                    if len(token) < 5:
                        continue
                    hyphen_dom = re.search(rf"(^|-){token}-(?:{'|'.join(_TLD_WORDS)})(-|$)", label)
                    if hyphen_dom and label != u.label:
                        findings.append(fnd(S.HIGH, "dotted_name_with_hyphens", f"“{label}” spells {token}.com with hyphens to look like a real address.", Looks_like=brand.name))
                    elif label in subs and (label == token or label.startswith(token + "-") or label.endswith("-" + token)):
                        findings.append(fnd(S.MEDIUM, "brand_in_subdomain", f"The name {brand.name} is used as a subdomain of an unrelated domain ({u.registrable}).", Brand=brand.name))
        if len(subs) >= 5:
            findings.append(fnd(S.MEDIUM, "very_deep", f"{len(subs)} nested subdomains push the real domain out of sight.", Depth=len(subs)))
        elif len(subs) == 4:
            findings.append(fnd(S.LOW, "deep", "Four nested subdomains are unusual for a normal site.", Depth=len(subs)))
        words = [w for s in subs for w in re.split(r"[-_]", s) if w in ref.sensitive_words]
        if words and not ref.is_popular(u.registrable):
            findings.append(fnd(S.MEDIUM if len(set(words)) >= 2 else S.LOW, "sensitive_words",
                                f"Words like {pretty_list(set(words))} sit in the subdomain, but the root domain is unfamiliar.", Words=pretty_list(set(words))))
        if sum(s.count("-") for s in subs) + u.label.count("-") >= 4:
            findings.append(fnd(S.LOW, "hyphens", "Lots of hyphens, which is common in throw-away phishing domains."))
        seen, unique = set(), []
        for f in findings:
            if f.code not in seen or f.code in ("brand_in_subdomain",):
                seen.add(f.code); unique.append(f)
        if not unique:
            return Outcome.clear("The subdomains look ordinary for this root domain.", **facts)
        return Outcome.flagged(unique, **facts)


# ----------------------------------------------------------------------------------------------- 8 obfuscation
_B64 = re.compile(r"[A-Za-z0-9+/_\-]{40,}={0,2}")
_UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _try_b64(token: str) -> str | None:
    t = token.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        raw = base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None
    text = raw.decode("utf-8", "ignore")
    printable = sum(c.isprintable() for c in text)
    return text if text and printable / len(text) > 0.9 else None


class ObfuscationCheck:
    spec = CheckSpec("obfuscation", 8, "URL Obfuscation & Encoding Check", Category.ADDRESS,
                     "Flags heavy percent-encoding (%xx), hex/octal sequences, Base64 blobs, or unusual character escapes used to hide payloads or real targets.")

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u = ctx.url
        if u.host_kind == "none":
            return Outcome.clear("Not a web address, so there is nothing to decode.")
        rest = f"{u.path}?{u.query}#{u.fragment}"
        findings = []
        pct = re.findall(r"%[0-9A-Fa-f]{2}", rest)
        needless = [m for m in pct if chr(int(m[1:], 16)) in _UNRESERVED]
        if len(needless) >= 3:
            findings.append(fnd(S.HIGH, "needless_encoding", f"{len(needless)} plain letters or digits are percent-encoded. That only serves to hide words from filters.", Example="".join(unquote(m) for m in needless[:20])))
        if re.search(r"%25[0-9A-Fa-f]{2}", rest):
            findings.append(fnd(S.MEDIUM, "double_encoding", "Double percent-encoding (%25xx) is used to slip past decoders."))
        delims = re.findall(r"%(?:2[eEfF]|5[cC]|40|3[aA])", rest)
        if len(delims) >= 2:
            findings.append(fnd(S.MEDIUM, "encoded_delimiters", f"Dots, slashes, colons or @ signs are hidden as %xx codes ({len(delims)} times)."))
        if len(pct) >= 8 and len(pct) * 3 / max(1, len(rest)) > 0.3:
            findings.append(fnd(S.MEDIUM, "heavy_encoding", f"{round(100 * len(pct) * 3 / len(rest))}% of the path and query is percent-encoded."))
        if re.search(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|&#x?[0-9a-fA-F]+;|\\[0-7]{3}", rest):
            findings.append(fnd(S.MEDIUM, "escape_sequences", "Hex, octal or HTML escape sequences are embedded in the address."))
        for token in _B64.findall(unquote(rest))[:5]:
            decoded = _try_b64(token)
            if decoded and re.search(r"https?://|<script|<html|javascript:|@[\w-]+\.", decoded, re.I):
                findings.append(fnd(S.HIGH, "base64_payload", "A Base64 blob decodes to a hidden web address or markup.", Decoded=decoded[:120]))
            elif len(token) >= 80 and decoded:
                findings.append(fnd(S.LOW, "base64_blob", "A long Base64-style value is packed into the link.", Length=len(token)))
        notes = {
            "nonstandard_ip_notation": (S.HIGH, f"The host is written as a hidden number ({u.host_raw}) that really means {u.host}."),
            "percent_encoded_host": (S.MEDIUM, "The host name itself is percent-encoded."),
            "encoded_delimiter_in_host": (S.HIGH, "The host contains an encoded delimiter such as %2f or %40."),
            "fullwidth_dots": (S.HIGH, "Look-alike dot characters are used in the host name."),
            "compat_characters_in_host": (S.MEDIUM, "Full-width or special characters in the host get silently converted by browsers."),
            "control_characters": (S.HIGH, "Control characters are hidden inside the link."),
            "inner_whitespace_removed": (S.MEDIUM, "Tabs or line breaks inside the link are silently removed by browsers."),
            "invisible_characters": (S.HIGH, "Invisible characters are hidden in the link."),
            "backslashes": (S.MEDIUM, "Backslashes are used where a normal link has slashes; browsers quietly fix them."),
            "nonstandard_slashes": (S.LOW, "An odd number of slashes after the scheme, which browsers quietly repair."),
        }
        for flag, (sev, msg) in notes.items():
            if flag in u.flags:
                findings.append(fnd(sev, flag, msg, Host_as_written=u.host_raw if "host" in msg else None))
        n = len(u.raw)
        if n > 2000:
            findings.append(fnd(S.MEDIUM, "very_long", f"The link is {n} characters long.", Length=n))
        elif n > 500:
            findings.append(fnd(S.LOW, "long", f"The link is unusually long ({n} characters).", Length=n))
        if not findings:
            return Outcome.clear("The address is written plainly - no hidden encoding.", Length=n)
        return Outcome.flagged(findings, Length=n)


# ---------------------------------------------------------------------------------------------- 9 scheme
class DangerousSchemeCheck:
    spec = CheckSpec("dangerous_scheme", 9, "Dangerous Scheme & Protocol Check", Category.ADDRESS,
                     "Blocks or flags non-browsing or risky schemes like javascript:, data:, file:, or unusual custom protocol handlers.")

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u = ctx.url
        findings = []
        if u.scheme in ("http", "https"):
            if "scheme_assumed" in u.flags:
                findings.append(fnd(S.INFO, "assumed", "No scheme was given, so https:// was assumed."))
            if u.scheme == "http":
                findings.append(fnd(S.INFO, "plain_http", "The link uses plain http:// (not encrypted)."))
            return Outcome.flagged(findings, "A normal web address (http/https).", Scheme=u.scheme) if findings else Outcome.clear("A normal https web address.", Scheme=u.scheme)
        if "unc_path" in u.flags or "windows_path" in u.flags:
            findings.append(fnd(S.HIGH, "local_path", "This is a file path, not a web link; it would open something on a computer or network share."))
        sev_text, why = ctx.ref.dangerous_schemes.get(u.scheme, ("medium", f"“{u.scheme}:” is a custom protocol handler, not a normal web link."))
        findings.append(fnd(_SEV[sev_text], "scheme", f"{u.scheme}: links are not normal web pages. {why}", Scheme=u.scheme))
        return Outcome.flagged(findings, f"{u.scheme}: is not a normal web link.", Scheme=u.scheme)


# ------------------------------------------------------------------------------------------ 13 port & path
class PortPathAnomalyCheck:
    spec = CheckSpec("port_path_anomaly", 13, "Port & Path Anomaly Check", Category.ADDRESS,
                     "Flags non-standard ports, misleading file extensions in paths (like .pdf or .docx paths that actually serve web pages/downloads), or suspicious query parameters.",
                     frozenset({"journey"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u = ctx.url
        if u.host_kind in ("none", "invalid"):
            return Outcome.clear("Not a web address, so there is no port or path to inspect.")
        findings = []
        default = DEFAULT_PORTS.get(u.scheme)
        if u.port is not None and u.port != default:
            if u.port in (21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5900):
                findings.append(fnd(S.HIGH, "service_port", f"Port {u.port} belongs to a non-web service.", Port=u.port))
            elif u.port in (8080, 8443, 8000, 8888, 8081):
                findings.append(fnd(S.LOW, "alt_port", f"Port {u.port} is a common alternative web port, but normal public sites rarely need one.", Port=u.port))
            else:
                findings.append(fnd(S.MEDIUM, "odd_port", f"The link uses an unusual port ({u.port}).", Port=u.port))
        path, ext = u.path.lower(), extension_of(u.path)
        if re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(exe|scr|js|vbs|bat|cmd|com|lnk|html?|hta|jar|msi)$", path):
            findings.append(fnd(S.HIGH, "double_extension", f"Double file extension (…{path[-14:]}) disguises a program or web page as a document."))
        elif ext in EXEC_EXT:
            findings.append(fnd(S.MEDIUM, "program_in_path", f"The link points straight at a program or script file (.{ext})."))
        ev = ctx.evidence("journey")
        if ev.available and ev.value.hops:
            last = ev.value.hops[-1]
            if ext in DOC_EXT and last.status and 200 <= last.status < 300 and last.sniffed:
                if last.sniffed in ("html",):
                    findings.append(fnd(S.HIGH, "doc_is_webpage", f"The path ends in .{ext} but the server returns a web page, not a document.", Served_as=last.content_type))
                elif last.sniffed in ("executable", "script", "archive"):
                    findings.append(fnd(S.CRITICAL, "doc_is_program", f"The path ends in .{ext} but the file is really a {last.sniffed}.", Served_as=last.content_type))
        if "//" in path.replace("://", ""):
            findings.append(fnd(S.LOW, "double_slash", "Repeated slashes in the path."))
        if len(u.path) > 200:
            findings.append(fnd(S.LOW, "long_path", f"Very long path ({len(u.path)} characters)."))
        if re.search(r"/wp-(content|includes|admin)/", path) and (re.search(r"login|verify|signin|secure|account", path) or ext in ("php", "html", "htm")):
            findings.append(fnd(S.LOW, "wordpress_path", "A WordPress folder serving a login-style page, a pattern seen on hacked sites hosting phishing kits."))
        text = unquote(u.query + "&" + u.fragment)
        email = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]{2,}", text)
        if email:
            findings.append(fnd(S.MEDIUM, "victim_email", "The link carries an email address, typical of phishing links personalised for one victim.", Address=email.group()))
        for _, value in parse_qsl(u.query, keep_blank_values=True):
            dec = _try_b64(value) if len(value) >= 16 else None
            if dec and re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.-]{2,}", dec.strip()):
                findings.append(fnd(S.MEDIUM, "victim_email_b64", "A query value is a Base64-encoded email address (victim tracking).")); break
        if re.search(r"https?:|//", u.fragment) or "@" in u.fragment:
            findings.append(fnd(S.MEDIUM, "fragment_payload", "The part after # contains a web address or email, which phishing kits read with scripts."))
        if u.query.count("&") >= 15:
            findings.append(fnd(S.LOW, "many_params", f"{u.query.count('&') + 1} query parameters."))
        if not findings:
            return Outcome.clear("Standard port and an ordinary path.", Port=u.effective_port, Extension=ext or "none")
        return Outcome.flagged(findings, Port=u.effective_port, Extension=ext or "none")

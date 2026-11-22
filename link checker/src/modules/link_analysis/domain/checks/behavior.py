"""Checks 14-19 - what the destination page does. Pages are parsed, never rendered or executed."""
from __future__ import annotations

import re

from modules.link_analysis.domain.checks._helpers import (SENSITIVE_KINDS, best_fetch, css_flags, css_props, form_kinds, kind_phrase,
                                                          page_kinds, pretty_list, resolve, short)
from modules.link_analysis.domain.checks.base import Category, CheckContext, CheckSpec, Outcome, Severity as S, fnd
from modules.link_analysis.domain.evidence import ElementInfo, FetchResult, PageSnapshot
from modules.link_analysis.domain.reference import norm_text
from modules.link_analysis.domain.sniff import ARCHIVE_EXT, EXEC_EXT, EXEC_TYPES, ARCHIVE_TYPES, DOC_EXT, extension_of
from modules.link_analysis.domain.url_model import parse_url

JS_NOTE = "The page is read, not run: fields or overlays that only appear after JavaScript executes are not seen."


def _no_page(ctx: CheckContext) -> Outcome:
    for key in ("journey", "journey_browser"):
        if key in ctx.allowed:
            ev = ctx.evidence(key)
            if ev.available:
                return Outcome.missing("The page could not be opened: " + (ev.value.detail or ev.value.outcome.replace("_", " ")).rstrip(".") + ".")
    ev = ctx.evidence("journey")
    return Outcome.missing("The page could not be opened: " + (ev.reason or "not fetched").rstrip(".") + ".")


def _scripts(page: PageSnapshot) -> str:
    return "\n".join(page.inline_scripts)[:300_000]


def _final_reg(ctx: CheckContext, fr: FetchResult) -> tuple[str, str]:
    p = parse_url(fr.final_url) if fr.final_url else ctx.url
    return p.registrable, p.host


def _brand_claims(ctx: CheckContext, page: PageSnapshot, reg: str):
    ref = ctx.ref
    strong = ref.brands_in_text(" ".join([page.title, page.og_site_name, page.og_title, *page.headings, *page.image_alts]))
    claimed = list(strong)
    low = norm_text(page.visible_text)
    for b in ref.brands_in_text(page.visible_text):
        names = [norm_text(n) for n in (b.name, *b.aliases) if len(n) >= 4]
        if b not in claimed and sum(low.count(n) for n in names) >= 3:
            claimed.append(b)
    official = ref.official_brand(reg)
    return [b for b in claimed if b is not official]


# --------------------------------------------------------------------------------------------- 14 login forms
class LoginFormCheck:
    spec = CheckSpec("login_form", 14, "Login & Credential Form Detection", Category.BEHAVIOR,
                     "Checks if the destination page asks for passwords, PINs, OTP codes, or payment cards—especially on unfamiliar or newly created domains.",
                     frozenset({"journey", "journey_browser", "registration"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        fr = best_fetch(ctx)
        if fr is None or fr.page is None:
            return _no_page(ctx)
        page, ref = fr.page, ctx.ref
        reg, host = _final_reg(ctx, fr)
        kinds = page_kinds(page)
        sensitive = kinds & SENSITIVE_KINDS
        facts = dict(Forms_found=len(page.forms), Input_fields=page.input_count, Asks_for=pretty_list(sorted(kinds)) or "nothing sensitive")
        if not sensitive:
            return Outcome.clear("No password, code or payment fields found on the page." if page.forms or page.input_count else "No forms or input fields found on the page.", JS_NOTE, **facts)
        trusted = ref.is_trusted(reg) and not ref.is_ugc_host(host)
        label = kind_phrase(sensitive)
        if trusted:
            name = (ref.official_brand(reg).name if ref.official_brand(reg) else reg)
            return Outcome.flagged([fnd(S.INFO, "official_login", f"Asks for {label}, on {name}'s own domain.")], f"Asks for {label} on a well-known domain ({reg}).", JS_NOTE, **facts)
        findings, extras = [], []
        age_days = None
        reg_ev = ctx.evidence("registration")
        if reg_ev.available:
            for rec in reg_ev.value.records:
                if rec.domain == reg and rec.created:
                    age_days = (ctx.now - rec.created).days
        mismatch = _brand_claims(ctx, page, reg)
        if "seed" in sensitive:
            findings.append(fnd(S.CRITICAL, "seed_phrase", "The page asks for a crypto recovery (seed) phrase or private key. No honest website ever needs it.", Domain=reg))
        base = S.MEDIUM if sensitive & {"card", "cvv", "pin", "identity", "bank"} else S.LOW
        findings.append(fnd(base, "credentials_requested", f"The page asks for {label} on a domain we have no reason to trust ({reg}).", Domain=reg))
        if age_days is not None and age_days <= 30:
            findings.append(fnd(S.HIGH, "new_domain_login", f"The domain asking for {label} was registered only {max(age_days, 0)} days ago.", Age_days=age_days))
            extras.append(f"a domain registered {max(age_days, 0)} days ago")
        if mismatch:
            names = pretty_list(b.name for b in mismatch)
            findings.append(fnd(S.HIGH, "brand_login", f"The page presents itself as {names} while asking for {label}.", Presenting_as=names))
            extras.append(f"presenting itself as {names}")
        if ref.is_ugc_host(host):
            findings.append(fnd(S.MEDIUM, "ugc_login", f"The page sits on a free hosting platform ({reg}) where anyone can publish content."))
            extras.append("on a free hosting platform")
        summary = f"Asks for {label} on {reg}" + (f" ({', '.join(extras)})." if extras else ".")
        return Outcome.flagged(findings, summary, JS_NOTE, **facts)


# ------------------------------------------------------------------------------------------ 15 form actions
_EXFIL_PATTERNS = (
    (re.compile(r"api\.telegram\.org/bot[\w:-]*", re.I), "a Telegram bot"), (re.compile(r"discord(?:app)?\.com/api/webhooks/\d+", re.I), "a Discord webhook"),
    (re.compile(r"hooks\.slack\.com/services/", re.I), "a Slack webhook"), (re.compile(r"script\.google\.com/macros/s/", re.I), "a Google Apps Script"),
    (re.compile(r"(?:formspree\.io|getform\.io|formsubmit\.co|web3forms\.com|webhook\.site|pipedream\.net|requestbin\.com)/", re.I), "a form-collection service"),
)


class FormActionMismatchCheck:
    spec = CheckSpec("form_action_mismatch", 15, "Form Action Destination Mismatch", Category.BEHAVIOR,
                     "Checks where a form actually submits data (<form action=\"...\">); a phishing page may look like Brand A while sending credentials to an unrelated domain.",
                     frozenset({"journey", "journey_browser"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        fr = best_fetch(ctx)
        if fr is None or fr.page is None or not fr.final_url:
            return _no_page(ctx)
        page, ref = fr.page, ctx.ref
        reg, host = _final_reg(ctx, fr)
        base = resolve(fr.final_url, page.base_href) if page.base_href else fr.final_url
        findings = []
        if page.base_href:
            bp = parse_url(base or "")
            if bp.registrable and bp.registrable != reg:
                findings.append(fnd(S.MEDIUM, "foreign_base", f"A <base> tag points relative links and form targets at {bp.registrable}.", Base=bp.host))
        sensitive_page = bool(page_kinds(page) & SENSITIVE_KINDS)
        facts: dict[str, object] = dict(Page_domain=reg, Forms_checked=len(page.forms))
        for i, form in enumerate(page.forms[:12], 1):
            kinds = form_kinds(form)
            secret = bool(kinds & SENSITIVE_KINDS)
            action = (form.action or "").strip()
            if action.lower().startswith("mailto:"):
                findings.append(fnd(S.HIGH if secret else S.MEDIUM, "mailto_action", "A form sends what is typed by email instead of to a server.", Action=short(action)))
                continue
            if action.lower().startswith(("javascript:", "data:")):
                findings.append(fnd(S.MEDIUM, "script_action", "A form is submitted by script, so its real target is hidden in code.", Action=short(action)))
                continue
            target = resolve(base or fr.final_url, action) if action else fr.final_url
            t = parse_url(target or "")
            if not t.is_web:
                continue
            facts[f"Form {i} sends to"] = short(t.host + t.path, 100)
            exfil_host = t.registrable in ref.exfil_hosts or t.host in ref.exfil_hosts
            if t.host_kind in ("ipv4", "ipv6"):
                findings.append(fnd(S.CRITICAL if secret else S.HIGH, "ip_action", f"A form submits to a bare IP address ({t.host}).", Target=t.host))
            elif t.registrable != reg:
                if exfil_host and secret:
                    findings.append(fnd(S.CRITICAL, "exfil_action", f"A form asking for {kind_phrase(kinds & SENSITIVE_KINDS)} sends it to {t.host}, a free collection service.", Target=t.host))
                elif secret:
                    findings.append(fnd(S.HIGH, "cross_domain_secret", f"A form that asks for {kind_phrase(kinds & SENSITIVE_KINDS)} sends it to {t.registrable}, not to {reg}.", Target=t.registrable, Page=reg))
                else:
                    findings.append(fnd(S.LOW, "cross_domain_form", f"A form sends its data to {t.registrable} rather than {reg}.", Target=t.registrable))
            if fr.final_url.startswith("https://") and t.scheme == "http":
                findings.append(fnd(S.HIGH if secret else S.MEDIUM, "https_downgrade", "A form on a secure page submits over plain http.", Target=short(target or "")))
        script = _scripts(page)
        for rx, name in _EXFIL_PATTERNS:
            if rx.search(script):
                findings.append(fnd(S.HIGH if sensitive_page else S.MEDIUM, "script_exfil", f"Page code sends data to {name}, a favourite drop-box for stolen form entries."))
        if not findings:
            if not page.forms:
                return Outcome.clear("The page has no forms, so nothing can be submitted.", JS_NOTE, **facts)
            return Outcome.clear("Every form submits to the same site that serves the page.", JS_NOTE, **facts)
        return Outcome.flagged(findings, limitation=JS_NOTE, **facts)


# ----------------------------------------------------------------------------------------- 16 brand + urgency
class BrandUrgencyCheck:
    spec = CheckSpec("brand_urgency", 16, "Brand Impersonation & Urgency Clues", Category.BEHAVIOR,
                     "Looks for mismatched brand logos/names combined with high-pressure lures (\"account suspended\", \"urgent verification\", \"claim reward\").",
                     frozenset({"journey", "journey_browser"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u, ref = ctx.url, ctx.ref
        fr = best_fetch(ctx)
        findings = []
        url_text = re.sub(r"[^a-z0-9]", "", (u.path + u.query).lower())
        if not ref.is_trusted(u.registrable):
            for b in ref.brands:
                if any(len(t) >= 5 and t in url_text for t in b.tokens):
                    findings.append(fnd(S.LOW, "brand_in_path", f"The name {b.name} appears in the link's path or parameters on an unrelated domain ({u.registrable}).", Brand=b.name))
                    break
        if fr is None or fr.page is None:
            if findings:
                return Outcome.flagged(findings, limitation="The page could not be opened, so only the link itself was checked.")
            return _no_page(ctx)
        page = fr.page
        reg, host = _final_reg(ctx, fr)
        trusted = ref.is_trusted(reg) and not ref.is_ugc_host(host)
        if trusted and not findings:
            return Outcome.clear(f"Served from a well-known domain ({reg}), where brand names and account notices are expected.", JS_NOTE)
        mismatch = [] if trusted else _brand_claims(ctx, page, reg)
        text = norm_text(" ".join((page.title, page.description, page.visible_text)))
        hits = [e for e in ref.urgency if e.phrase in text]
        strong = [e for e in hits if not e.weak]
        cats = {e.category for e in strong}
        secret = bool(page_kinds(page) & SENSITIVE_KINDS)
        facts = dict(Brands_mentioned=pretty_list(b.name for b in ref.brands_in_text(page.title + " " + page.visible_text[:4000])) or "none",
                     Lure_types=pretty_list(sorted(cats)) or "none")
        if mismatch:
            names = pretty_list(b.name for b in mismatch)
            if strong or secret:
                findings.append(fnd(S.HIGH, "brand_plus_pressure", f"The page presents itself as {names} but is served from {reg}, and it " + ("pressures the visitor." if strong else "asks for sensitive details."), Brand=names, Served_from=reg))
            else:
                findings.append(fnd(S.LOW, "brand_mismatch", f"The page mentions {names} prominently but is not on {names}'s domain ({reg}).", Brand=names, Served_from=reg))
        if len(cats) >= 3:
            findings.append(fnd(S.MEDIUM, "pressure_language", f"The page uses high-pressure language ({pretty_list(sorted(cats))}).", Examples=pretty_list([e.phrase for e in strong], 5)))
        elif strong and (secret or mismatch):
            findings.append(fnd(S.LOW, "urgency", f"Urgency wording such as “{strong[0].phrase}”.", Examples=pretty_list([e.phrase for e in strong], 5)))
        elif strong:
            findings.append(fnd(S.INFO, "mild_urgency", f"Some urgency wording (“{strong[0].phrase}”), which is common on legitimate sites too."))
        if not findings:
            return Outcome.clear("No brand impersonation or pressure tactics found.", JS_NOTE, **facts)
        return Outcome.flagged(findings, limitation=JS_NOTE, **facts)


# -------------------------------------------------------------------------------------------- 17 hidden stuff
_SIMPLE_SEL = re.compile(r"^([a-z][a-z0-9]*)?((?:[.#][\w-]+)*)$", re.I)


def _matches(sel: str, el: ElementInfo) -> bool:
    m = _SIMPLE_SEL.match(sel.strip())
    if not m or not (m.group(1) or m.group(2)):
        return False
    if m.group(1) and m.group(1).lower() != el.tag:
        return False
    classes = set(el.classes.split())
    return all((part[1:] in classes) if part[0] == "." else (part[1:] == el.id) for part in re.findall(r"[.#][\w-]+", m.group(2)))


def _flags(el: ElementInfo, rules: tuple[tuple[str, str], ...]) -> set[str]:
    props: dict[str, str] = {}
    for sel, decl in rules:
        if any(_matches(s, el) for s in sel.split(",")):
            props.update(css_props(decl))
    props.update(css_props(el.style))
    flags = css_flags(props)
    if el.hidden_attr:
        flags.add("hidden")
    return flags


class HiddenElementsCheck:
    spec = CheckSpec("hidden_elements", 17, "Hidden Elements & Clickjacking/Overlay Clues", Category.BEHAVIOR,
                     "Detects invisible elements, full-screen overlays, or deceptive UI traps designed to trick users into clicking or entering info by mistake.",
                     frozenset({"journey", "journey_browser"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        fr = best_fetch(ctx)
        if fr is None or fr.page is None:
            return _no_page(ctx)
        page = fr.page
        reg, _ = _final_reg(ctx, fr)
        findings = []
        overlays = hidden_inputs = link_farms = 0
        for el in page.elements:
            flags = _flags(el, page.style_rules)
            if "overlay" in flags and ("transparent" in flags or "hidden" in flags):
                overlays += 1
            elif "hidden" in flags and el.has_input:
                hidden_inputs += 1
            elif "hidden" in flags and el.link_count >= 5:
                link_farms += 1
        if overlays:
            findings.append(fnd(S.HIGH, "invisible_overlay", f"{overlays} invisible full-screen layer{'s' if overlays > 1 else ''} {'sit' if overlays > 1 else 'sits'} on top of the page and can capture clicks (clickjacking).", Layers=overlays))
        if hidden_inputs:
            findings.append(fnd(S.MEDIUM, "hidden_inputs", f"{hidden_inputs} hidden element{'s' if hidden_inputs > 1 else ''} {'contain' if hidden_inputs > 1 else 'contains'} input fields the visitor cannot see.", Elements=hidden_inputs))
        if link_farms:
            findings.append(fnd(S.LOW, "hidden_links", f"{link_farms} hidden block{'s' if link_farms > 1 else ''} stuffed with links."))
        for form in page.forms:
            if "hidden" in css_flags(css_props(form.style)) and (form_kinds(form) & SENSITIVE_KINDS):
                findings.append(fnd(S.HIGH, "hidden_form", "A form that collects sensitive details is hidden from view."))
        for fr_info in page.iframes:
            props = css_props(fr_info.style)
            flags = css_flags(props)
            tiny = all(re.fullmatch(r"0(px)?", (v or "").strip()) for v in (fr_info.width, fr_info.height) if v)
            hidden = "hidden" in flags or fr_info.hidden_attr or (tiny and (fr_info.width or fr_info.height))
            t = parse_url(fr_info.src) if fr_info.src.startswith(("http", "//")) else None
            foreign = bool(t and t.registrable and t.registrable != reg)
            if hidden:
                findings.append(fnd(S.HIGH if foreign else S.MEDIUM, "hidden_iframe", "An invisible frame is embedded" + (f" from {t.registrable}." if foreign else "."), Source=short(fr_info.src)))
            elif foreign and any(v.strip() in ("100%", "100vw", "100vh") for v in (fr_info.width, fr_info.height, props.get("width", ""), props.get("height", ""))):
                findings.append(fnd(S.MEDIUM, "framed_site", f"The page is a full-size frame around another site ({t.registrable}).", Source=short(fr_info.src)))
        script = _scripts(page)
        if re.search(r"(?:\.submit\(\)|requestSubmit\()", script) and re.search(r"DOMContentLoaded|onload|setTimeout", script):
            findings.append(fnd(S.MEDIUM, "auto_submit", "Page code submits a form automatically, without the visitor pressing anything."))
        if re.search(r"onbeforeunload|window\.open\([^)]*(?:_blank|popup)", script):
            findings.append(fnd(S.LOW, "popup_trap", "The page tries to open pop-ups or block leaving it."))
        if re.search(r"oncontextmenu\s*=\s*(?:\"|')?return false|addEventListener\(\s*['\"]contextmenu['\"]", script):
            findings.append(fnd(S.LOW, "no_right_click", "Right-click is disabled, which stops visitors from inspecting the page."))
        if not findings:
            return Outcome.clear("No invisible elements, overlays or hidden frames found.", JS_NOTE, Elements_examined=len(page.elements), Frames=len(page.iframes))
        return Outcome.flagged(findings, limitation=JS_NOTE, Elements_examined=len(page.elements), Frames=len(page.iframes))


# ------------------------------------------------------------------------------------------- 18 auto-download
_DL_SCRIPT = (
    (re.compile(r"(?:window\.|document\.)?location(?:\.href)?\s*=\s*['\"][^'\"]+\.(?:exe|msi|apk|iso|zip|rar|7z|js|vbs|hta|ps1|bat|cmd|scr|lnk|jar|dmg)(?:\?[^'\"]*)?['\"]", re.I), S.HIGH, "Page code redirects the browser straight to a program or archive file."),
    (re.compile(r"createObjectURL[\s\S]{0,400}download|new\s+Blob\([\s\S]{0,600}(?:\.download\s*=|msSaveOrOpenBlob)", re.I), S.HIGH, "Page code builds a file inside the browser and saves it (“HTML smuggling”), a way to slip malware past scanners."),
    (re.compile(r"createElement\(\s*['\"]a['\"]\s*\)[\s\S]{0,300}\.download\s*=[\s\S]{0,300}\.click\(\)", re.I), S.MEDIUM, "Page code creates a download link and clicks it automatically."),
    (re.compile(r"data:application/(?:octet-stream|x-msdownload|zip|x-zip)", re.I), S.HIGH, "A file is embedded in the page as a data: address."),
)


class AutoDownloadCheck:
    spec = CheckSpec("auto_download", 18, "Auto-Download & Malicious File Trigger Check", Category.BEHAVIOR,
                     "Warns if visiting the link immediately triggers executable, archive, script, or suspicious file downloads (exe, msi, apk, iso, zip, js, vbs).",
                     frozenset({"journey", "journey_browser"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        evs = [ctx.evidence(k) for k in ("journey", "journey_browser")]
        avail = [e.value for e in evs if e.available]
        findings, seen = [], set()
        ext0 = extension_of(ctx.url.path)

        def add(f):
            key = (f.code, f.message)
            if key not in seen:
                seen.add(key); findings.append(f)

        if ext0 in EXEC_EXT:
            add(fnd(S.MEDIUM, "program_url", f"The link itself ends in .{ext0}, a program or script file.", Extension=ext0))
        elif ext0 in ARCHIVE_EXT:
            add(fnd(S.LOW, "archive_url", f"The link itself ends in .{ext0}, an archive.", Extension=ext0))
        for j in avail:
            for h in j.hops:
                ext = extension_of(parse_url(h.url).path)
                ct = (h.content_type or "").split(";")[0].strip().lower()
                attach = bool(h.disposition and "attachment" in h.disposition.lower())
                ok = h.status is not None and 200 <= h.status < 300
                if ok and h.sniffed in ("executable",):
                    add(fnd(S.CRITICAL, "serves_executable", "Opening the link downloads a program (its first bytes are an executable).", Type=ct or "unknown", File=short(h.url, 80)))
                elif ok and (ct in EXEC_TYPES or (ext in EXEC_EXT and (attach or h.sniffed in (None, "unknown", "archive", "script")))):
                    add(fnd(S.HIGH, "serves_program", f"Opening the link downloads a program or script ({ct or '.' + ext}).", Type=ct or ext, File=short(h.url, 80)))
                elif ok and (h.sniffed == "archive" or ct in ARCHIVE_TYPES or ext in ARCHIVE_EXT) and (attach or ext in ARCHIVE_EXT or ct in ARCHIVE_TYPES):
                    add(fnd(S.HIGH if ext in ("iso", "img", "cab") else S.MEDIUM, "serves_archive", f"Opening the link downloads an archive ({ct or '.' + ext}).", Type=ct or ext))
                elif ok and attach and h.sniffed != "pdf":
                    add(fnd(S.LOW, "forced_download", f"The server forces a file download ({ct or 'unknown type'}).", Type=ct))
                if ok and ext in DOC_EXT and h.sniffed in ("executable", "script", "archive"):
                    add(fnd(S.CRITICAL, "disguised_file", f"The file is named like a document (.{ext}) but its contents are a {h.sniffed}.", Named=f".{ext}", Really=h.sniffed))
            page = j.page
            if page is None:
                continue
            if page.meta_refresh:
                m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", page.meta_refresh, re.I)
                e = extension_of(parse_url(m.group(1)).path) if m else ""
                if e in EXEC_EXT or e in ARCHIVE_EXT:
                    add(fnd(S.HIGH, "refresh_download", f"The page automatically redirects to a .{e} file."))
            script = _scripts(page)
            for rx, sev, msg in _DL_SCRIPT:
                if rx.search(script):
                    add(fnd(sev, "script_download", msg))
            for f in page.iframes:
                e = extension_of(parse_url(f.src).path) if f.src else ""
                if e in EXEC_EXT or e in ARCHIVE_EXT:
                    add(fnd(S.HIGH, "iframe_download", f"A hidden frame loads a .{e} file.", Source=short(f.src)))
        if not any(h.status for j in avail for h in j.hops) and not findings:
            return Outcome.missing("The page could not be opened, so downloads could not be checked.")
        limitation = "Files are never downloaded or opened: only the headers and the first bytes of a response are inspected."
        if not findings:
            return Outcome.clear("Visiting the link does not trigger a file download.", limitation)
        return Outcome.flagged(findings, limitation=limitation)


# ------------------------------------------------------------------------------------------- 19 cloaking
_CHALLENGE = re.compile(r"just a moment|attention required|checking your browser|verify you are human|are you a robot|enable javascript and cookies|ddos protection by|وقت قصير|تحقق من أنك إنسان", re.I)
_CHALLENGE_SRC = ("challenges.cloudflare.com", "recaptcha", "hcaptcha", "turnstile", "captcha")
_EVASION = (
    (re.compile(r"navigator\.webdriver|headless|phantomjs|selenium|puppeteer|playwright", re.I), "tests whether it is being driven by an automated browser"),
    (re.compile(r"userAgent[^;]{0,120}(?:bot|crawl|spider|curl|wget|python)", re.I), "checks the visitor's user-agent for bots"),
    (re.compile(r"ipapi\.co|ip-api\.com|ipinfo\.io|geoplugin|api\.ipify|ipgeolocation", re.I), "looks up the visitor's IP or country before deciding what to show"),
    (re.compile(r"debugger\s*;|console\.clear\(\)|devtools", re.I), "tries to detect or disturb browser developer tools"),
    (re.compile(r"keyCode\s*==\s*(?:123|85)\b|key\s*===?\s*['\"]F12['\"]", re.I), "blocks the keys used to inspect a page"),
)
_OBFUSCATED = re.compile(r"eval\(\s*(?:atob|unescape|function\(p,a,c,k,e)|document\.write\(\s*unescape|(?:String\.fromCharCode\([^)]{80,})|(?:\\x[0-9a-f]{2}){20,}", re.I)


def _jaccard(a: frozenset[int], b: frozenset[int]) -> float:
    return len(a & b) / len(a | b) if a and b else 1.0


class CloakingCheck:
    spec = CheckSpec("cloaking", 19, "Cloaking & Bot-Evasion Detection", Category.BEHAVIOR,
                     "Notices when a link behaves differently for scanners vs. browsers or blocks inspection in ways commonly used to hide phishing pages from security checks.",
                     frozenset({"journey", "journey_browser"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        ea, eb = ctx.evidence("journey"), ctx.evidence("journey_browser")
        if not ea.available and not eb.available:
            return Outcome.missing(ea.reason or "The link could not be fetched.")
        a, b = (ea.value if ea.available else None), (eb.value if eb.available else None)
        findings, facts = [], {}
        ok = lambda r: bool(r and r.outcome == "ok" and r.final_status and r.final_status < 400)  # noqa: E731
        if a and b:
            facts["Scanner view"] = f"HTTP {a.final_status or '—'} · {a.outcome}"
            facts["Browser view"] = f"HTTP {b.final_status or '—'} · {b.outcome}"
            if not ok(a) and ok(b):
                findings.append(fnd(S.MEDIUM, "scanner_refused", f"The server refuses our scanner (HTTP {a.final_status or a.outcome}) but serves ordinary browsers. Some honest sites do this to stop bots; phishing kits do it to stay hidden.", Scanner_status=a.final_status))
            if a.final_url and b.final_url and ok(a) and ok(b):
                ra, rb = parse_url(a.final_url).registrable, parse_url(b.final_url).registrable
                if ra != rb:
                    findings.append(fnd(S.HIGH, "different_destination", f"Scanners end up on {ra} but browsers end up on {rb}.", Scanner=ra, Browser=rb))
            if ok(a) and ok(b) and a.page and b.page:
                sim = _jaccard(a.fingerprint, b.fingerprint)
                facts["Content similarity"] = f"{round(sim * 100)}%"
                ka, kb = page_kinds(a.page) & SENSITIVE_KINDS, page_kinds(b.page) & SENSITIVE_KINDS
                if kb - ka:
                    findings.append(fnd(S.HIGH, "form_only_for_browsers", f"A form asking for {pretty_list(sorted(kb - ka))} is shown to browsers but not to our scanner."))
                if sim < 0.35:
                    findings.append(fnd(S.HIGH, "content_differs", f"The page content differs sharply between scanner and browser ({round(sim * 100)}% alike).", Similarity=f"{round(sim * 100)}%"))
                elif sim < 0.6:
                    findings.append(fnd(S.MEDIUM, "content_varies", f"The page content differs noticeably between scanner and browser ({round(sim * 100)}% alike).", Similarity=f"{round(sim * 100)}%"))
        for r in (x for x in (a, b) if x and x.page):
            page = r.page
            script = _scripts(page)
            tricks = [desc for rx, desc in _EVASION if rx.search(script)]
            if tricks:
                findings.append(fnd(S.MEDIUM if len(tricks) == 1 else S.HIGH, "evasion_code", "Page code " + pretty_list(tricks, 3) + ".", Profile=r.profile))
            if _OBFUSCATED.search(script):
                findings.append(fnd(S.MEDIUM, "obfuscated_script", "Page code is deliberately scrambled (eval/unescape/char-code tricks) to hide what it does.", Profile=r.profile))
            text = f"{page.title} {page.visible_text[:600]}"
            if _CHALLENGE.search(text) or any(s in src.lower() for src in page.script_srcs for s in _CHALLENGE_SRC):
                findings.append(fnd(S.LOW, "challenge_gate", "The page sits behind a CAPTCHA or browser check. Many honest sites use these; phishing kits use them to keep scanners out.", Profile=r.profile))
            if r.page is not None:
                break
        seen, unique = set(), []
        for f in findings:
            if f.code not in seen:
                seen.add(f.code); unique.append(f)
        viewed = [r for r in (a, b) if r and r.page is not None]
        limitation = None if (a and b and len(viewed) == 2) else "Only one view of the page was available, so scanner and browser behaviour could not be compared."
        if not viewed and not unique:
            return Outcome.missing("The page could not be opened, so scanner and browser behaviour could not be compared.")
        if not unique:
            if len(viewed) == 2:
                return Outcome.clear("The page looks the same to scanners and to browsers, and shows no bot-evasion tricks.", limitation, **facts)
            return Outcome.clear("No bot-evasion tricks found in the page, but it was only seen from one point of view.", limitation, **facts)
        return Outcome.flagged(unique, limitation=limitation, **facts)

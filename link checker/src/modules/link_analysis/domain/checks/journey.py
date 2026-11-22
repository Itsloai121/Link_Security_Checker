"""Checks 4, 5, 20 - where the link really goes."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote

from modules.link_analysis.domain.checks._helpers import best_fetch, parsed_final, short
from modules.link_analysis.domain.checks.base import Category, CheckContext, CheckSpec, Outcome, Severity as S, fnd
from modules.link_analysis.domain.url_model import parse_url

IP_LOGGERS = frozenset({"grabify.link", "iplogger.org", "iplogger.com", "2no.co", "yip.su"})
_OUTCOME_TEXT = {"blocked": "The scanner refused to connect to this destination.", "dns_failed": "The domain name does not resolve.",
                 "connect_failed": "The server could not be reached.", "tls_failed": "A secure connection could not be set up.",
                 "timeout": "The server took too long to answer.", "not_fetchable": "Only http and https links can be followed."}


class RedirectChainCheck:
    spec = CheckSpec("redirect_chain", 4, "URL Shortener & Redirect Unwrapping", Category.JOURNEY,
                     "Expands short links and follows redirect chains (hop 1 → hop 2 → final URL) to expose hidden destinations behind clean-looking links.",
                     frozenset({"journey"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u, ref = ctx.url, ctx.ref
        findings = []
        is_short = u.host_kind == "domain" and (u.registrable in ref.shorteners or u.host in ref.shorteners)
        if u.registrable in IP_LOGGERS:
            findings.append(fnd(S.HIGH, "ip_logger", "This is a link-tracking service that records the visitor's IP address and device, not a plain short link.", Service=u.registrable))
        elif is_short:
            findings.append(fnd(S.LOW, "shortener", f"{u.registrable} is a link shortener, so the real destination is hidden until it is expanded.", Service=u.registrable))
        ev = ctx.evidence("journey")
        if not ev.available:
            reason = ev.reason or "unknown"
            return Outcome.flagged(findings, limitation=f"Could not follow the link: {reason}") if findings else Outcome.missing(reason)
        j = ev.value
        redirects = [h for h in j.hops if h.via != "initial"]
        if not redirects and j.outcome != "ok":
            text = _OUTCOME_TEXT.get(j.outcome, j.detail or j.outcome)
            return Outcome.flagged(findings, limitation=f"Could not follow the link: {text}") if findings else Outcome.missing(text)
        facts: dict[str, object] = {}
        for h in j.hops[:12]:
            facts[f"Hop {h.index + 1}"] = f"{h.status or '—'} {'(' + h.via.replace('_', ' ') + ') ' if h.via != 'initial' else ''}{short(h.url, 110)}"
        n = len(redirects)
        if n:
            findings.append(fnd(S.INFO, "followed", f"Followed {n} redirect{'s' if n != 1 else ''} to reach the final page."))
        if n >= 5:
            findings.append(fnd(S.MEDIUM, "long_chain", f"The link bounces through {n} redirects before landing.", Redirects=n))
        elif n >= 3:
            findings.append(fnd(S.LOW, "chain", f"The link passes through {n} redirects.", Redirects=n))
        client_side = [h for h in redirects if h.via in ("meta_refresh", "javascript")]
        if client_side:
            findings.append(fnd(S.MEDIUM, "client_side", "Some hops are done by page code (meta refresh or JavaScript), a way to dodge scanners that only follow normal redirects.", Hops=len(client_side)))
        regs = []
        for h in j.hops:
            p = parse_url(h.url)
            if p.registrable and (not regs or regs[-1] != p.registrable):
                regs.append(p.registrable)
        distinct = [r for r in dict.fromkeys(regs) if r not in ref.shorteners]
        if len(distinct) >= 3:
            findings.append(fnd(S.MEDIUM, "many_sites", f"The journey crosses {len(distinct)} different sites: {' → '.join(distinct[:5])}.", Sites=" → ".join(distinct[:6])))
        for a, b in zip(j.hops, j.hops[1:], strict=False):
            if a.url.lower().startswith("https://") and b.url.lower().startswith("http://"):
                findings.append(fnd(S.MEDIUM, "downgrade", "A redirect drops from https to plain http.", From=short(a.url, 80), To=short(b.url, 80))); break
        if j.outcome == "too_many_redirects":
            findings.append(fnd(S.HIGH, "too_many", "The scanner gave up: the link keeps redirecting past the safety limit."))
        elif j.outcome == "redirect_loop":
            findings.append(fnd(S.HIGH, "loop", "The link redirects in a circle."))
        elif j.outcome not in ("ok",):
            findings.append(fnd(S.INFO, "ended_early", _OUTCOME_TEXT.get(j.outcome, j.detail or j.outcome)))
        facts["Final destination"] = short(j.final_url or j.hops[-1].url, 120)
        summary = None
        if not [f for f in findings if f.severity >= S.LOW]:
            summary = "The link goes straight to its destination." if not n else f"Followed {n} ordinary redirect{'s' if n != 1 else ''} to the final page."
        return Outcome.flagged(findings, summary, **facts) if findings else Outcome.clear(summary or "No redirects.", **facts)


class OpenRedirectCheck:
    spec = CheckSpec("open_redirect", 5, "Open Redirect & Cross-Domain Jump Check", Category.JOURNEY,
                     "Flags URLs that start on a trusted domain and bounce the user to an unrelated or suspicious external site.",
                     frozenset({"journey"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u, ref = ctx.url, ctx.ref
        if u.host_kind != "domain":
            return Outcome.clear("No domain name, so there is no trusted site to bounce from.")
        trusted_start = ref.is_trusted(u.registrable)
        findings, targets = [], []
        for name, value in parse_qsl(u.query + "&" + u.fragment.lstrip("?"), keep_blank_values=True):
            if name.lower() not in ref.redirect_params:
                continue
            v = unquote(unquote(value)).strip()
            if re.match(r"^(?:https?:)?//", v, re.I) or re.match(r"^[\w-]+(\.[\w-]+)+(/|$)", v):
                t = parse_url(v)
                if t.is_web and t.registrable != u.registrable:
                    targets.append((name, t))
        ev = ctx.evidence("journey")
        final = parsed_final(ctx)
        confirmed = bool(ev.available and final and len(ev.value.hops) > 1)
        for name, t in targets:
            hit = confirmed and final is not None and final.registrable == t.registrable
            sev = (S.CRITICAL if trusted_start else S.HIGH) if hit else (S.HIGH if trusted_start else S.MEDIUM)
            verb = "does send visitors" if hit else "can send visitors"
            findings.append(fnd(sev, "confirmed_open_redirect" if hit else "redirect_parameter",
                                f"The “{name}” parameter {verb} from {u.registrable} to {t.host}.", Parameter=name, Target=t.host))
        if ev.available:
            regs = [(h, parse_url(h.url)) for h in ev.value.hops]
            seen_trusted = None
            for _, p in regs:
                if p.registrable and ref.is_trusted(p.registrable) and not ref.is_ugc_host(p.host):
                    seen_trusted = seen_trusted or p.registrable
                elif seen_trusted and p.registrable and p.registrable != seen_trusted and not ref.is_trusted(p.registrable) and p.registrable not in ref.shorteners:
                    if not any(f.code == "confirmed_open_redirect" for f in findings):
                        findings.append(fnd(S.HIGH, "trusted_to_unknown", f"The link starts on {seen_trusted}, a trusted site, but ends on the unrelated site {p.registrable}.", From=seen_trusted, To=p.registrable))
                    break
        elif trusted_start:
            return Outcome.flagged(findings, limitation=f"Could not follow the link to see whether it leaves the trusted site ({ev.reason}).") if findings else Outcome.missing(ev.reason or "link not followed")
        if not findings:
            return Outcome.clear("The link never jumps from a trusted site to an unrelated one.", Starts_on=u.registrable, Trusted_start="yes" if trusted_start else "no")
        return Outcome.flagged(findings, Starts_on=u.registrable)


class DisplayMismatchCheck:
    spec = CheckSpec("display_mismatch", 20, "Final Destination vs. Display Text Mismatch", Category.JOURNEY,
                     "Compares the visible link label/text or preview against where the link actually lands so disguised links (\"Click here for official portal\" going elsewhere) are exposed.",
                     frozenset({"journey", "journey_browser"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u, ref = ctx.url, ctx.ref
        final = parsed_final(ctx) or u
        landing = final.registrable or final.host
        text = (ctx.display_text or "").strip()
        findings = []
        if text:
            facts = dict(Link_label=text[:120], Lands_on=final.host or u.display_url)
            for tok in re.findall(r"(?:https?://)?(?:[\w-]+\.)+[a-z]{2,}(?::\d+)?(?:/[^\s]*)?", text, re.I)[:5]:
                t = parse_url(tok)
                if t.host_kind == "domain" and t.registrable and t.registrable not in {landing, u.registrable}:
                    findings.append(fnd(S.CRITICAL if ref.is_trusted(t.registrable) else S.HIGH, "label_domain_mismatch",
                                        f"The label shows {t.host}, but the link leads to {final.host}.", Label_shows=t.host, Lands_on=final.host))
            for b in ref.brands_in_text(text):
                official = ref.official_brand(landing)
                if official is not b and not any(f.code == "label_domain_mismatch" for f in findings):
                    findings.append(fnd(S.HIGH if not ref.is_trusted(landing) else S.MEDIUM, "label_brand_mismatch",
                                        f"The label mentions {b.name}, but the link leads to {landing}, which is not {b.name}'s domain.", Brand=b.name, Lands_on=landing))
            if not findings:
                return Outcome.clear("The label does not contradict where the link lands.", **facts)
            return Outcome.flagged(findings, **facts)
        fr = best_fetch(ctx)
        if fr is None or fr.page is None:
            return Outcome.missing("No link label was provided and the page could not be read for a preview.")
        page = fr.page
        facts = dict(Page_title=page.title[:120], Lands_on=final.host)
        for field_name, value in (("og:url", page.og_url), ("canonical link", page.canonical)):
            t = parse_url(value) if value else None
            if t is not None and t.host_kind == "domain" and t.registrable and t.registrable != landing:
                findings.append(fnd(S.MEDIUM, "claims_other_site", f"The page's {field_name} says it belongs to {t.registrable}, yet it is served from {landing}.", Claimed=t.registrable, Served_from=landing))
        preview = " ".join((page.title, page.og_site_name, page.og_title))
        for b in ref.brands_in_text(preview):
            if ref.official_brand(landing) is not b:
                findings.append(fnd(S.MEDIUM if ref.is_trusted(landing) else S.HIGH, "preview_brand_mismatch",
                                    f"The page presents itself as {b.name} but is served from {landing}.", Brand=b.name, Served_from=landing))
                break
        if not findings:
            return Outcome.clear("The page preview matches the site it is served from.", "No link label was given, so only the page's own title and metadata were compared.", **facts)
        return Outcome.flagged(findings, limitation="No link label was given, so only the page's own title and metadata were compared.", **facts)

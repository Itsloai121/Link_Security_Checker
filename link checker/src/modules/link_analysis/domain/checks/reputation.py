"""Checks 1, 10, 11, 12 - who is behind the link."""
from __future__ import annotations

from modules.link_analysis.domain.checks._helpers import SENSITIVE_KINDS, best_fetch, page_kinds, parsed_final, pretty_list
from modules.link_analysis.domain.checks.base import Category, CheckContext, CheckSpec, Outcome, Severity as S, fnd

TUNNELS = frozenset({"trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "loca.lt", "serveo.net"})
CDN_WORDS = ("CLOUDFLARE", "AKAMAI", "FASTLY", "CLOUDFRONT", "AMAZON-02", "GOOGLE", "MICROSOFT")


class BlocklistCheck:
    spec = CheckSpec("blocklist", 1, "Threat & Phishing Blocklist Check", Category.REPUTATION,
                     "Compares the URL, domain, and final destination against known phishing, malware, and scam lists to catch confirmed bad links immediately.",
                     frozenset({"blocklist"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        ev = ctx.evidence("blocklist")
        if not ev.available:
            return Outcome.missing(ev.reason or "No blocklist could be queried.")
        rep = ev.value
        if not rep.checked:
            return Outcome.missing("No blocklist could be queried: " + "; ".join(f"{p} ({r})" for p, r in rep.failed))
        facts = dict(Lists_checked=pretty_list(rep.checked, 6), Lists_unreachable=pretty_list([p for p, _ in rep.failed]) or None,
                     Newest_list_update=max((t for _, t in rep.freshness), default=None))
        if rep.hits:
            findings = [fnd(S.CRITICAL, "listed", f"Listed as {h.category} by {h.provider}: {h.matched}.", Matched=h.matched, Kind=h.kind, List=h.provider, Category=h.category)
                        for h in rep.hits[:6]]
            return Outcome.flagged(findings, **facts)
        note = "Not being on a list does not prove a link is safe: brand-new attacks take hours or days to be reported."
        if rep.failed:
            note += f" {len(rep.failed)} list(s) could not be reached."
        return Outcome.clear(f"Not found on {len(rep.checked)} known phishing, malware or scam list{'s' if len(rep.checked) != 1 else ''}.", note, **facts)


class DomainAgeCheck:
    spec = CheckSpec("domain_age", 10, "Domain Age & Freshness Check", Category.REPUTATION,
                     "Checks how recently the domain was registered; brand-new domains are frequently spun up for short-lived phishing campaigns.",
                     frozenset({"registration", "journey"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u, ref = ctx.url, ctx.ref
        final = parsed_final(ctx) or u
        if u.host_kind in ("ipv4", "ipv6") and final.host_kind != "domain":
            return Outcome.missing("The link uses a bare IP address, so there is no domain registration to date.")
        if u.host_kind == "none":
            return Outcome.missing("Not a web address, so there is no domain to look up.")
        ev = ctx.evidence("registration")
        if not ev.available:
            return Outcome.missing(ev.reason or "Registration data was not available.")
        rep = ev.value
        findings, facts = [], {}
        for rec in rep.records:
            if rec.created is None:
                findings.append(fnd(S.INFO, "no_date", f"The registry did not publish a creation date for {rec.domain}."))
                continue
            days = (ctx.now - rec.created).days
            facts[f"{rec.domain} registered"] = f"{rec.created:%Y-%m-%d} ({days} days ago)" if days < 400 else f"{rec.created:%Y-%m-%d} ({days // 365} years ago)"
            if rec.registrar:
                facts[f"{rec.domain} registrar"] = rec.registrar
            trusted = ref.is_trusted(rec.domain)
            if days <= 7 and not trusted:
                findings.append(fnd(S.HIGH, "brand_new", f"{rec.domain} was registered only {max(days, 0)} day{'s' if days != 1 else ''} ago, typical of throw-away phishing domains.", Domain=rec.domain, Age_days=days))
            elif days <= 30 and not trusted:
                findings.append(fnd(S.MEDIUM, "very_new", f"{rec.domain} was registered {days} days ago.", Domain=rec.domain, Age_days=days))
            elif days <= 90 and not trusted:
                findings.append(fnd(S.LOW, "new", f"{rec.domain} is less than three months old ({days} days).", Domain=rec.domain, Age_days=days))
            else:
                findings.append(fnd(S.INFO, "established", f"{rec.domain} has been registered for {days // 365 if days >= 365 else days // 30} {'years' if days >= 365 else 'months'}."))
            if rec.expires and 0 <= (rec.expires - ctx.now).days <= 30 and not trusted:
                findings.append(fnd(S.LOW, "expiring", f"{rec.domain} expires in {(rec.expires - ctx.now).days} days."))
        tld = (final.suffix or u.suffix).rsplit(".", 1)[-1]
        if tld in ref.suspicious_tlds:
            findings.append(fnd(S.LOW, "risky_tld", f".{tld} domains are cheap or free and heavily used for short-lived scam sites.", TLD="." + tld))
        if not rep.records:
            reasons = "; ".join(f"{d}: {r}" for d, r in rep.errors)
            return Outcome.flagged(findings, limitation=f"No registration date could be retrieved ({reasons}).") if findings else Outcome.missing(reasons or "No registration data.")
        limitation = ("Some domains could not be looked up: " + "; ".join(f"{d} ({r})" for d, r in rep.errors)) if rep.errors else None
        return Outcome.flagged(findings, limitation=limitation, **facts)


class TlsCertificateCheck:
    spec = CheckSpec("tls_certificate", 11, "SSL/TLS Certificate & HTTPS Check", Category.REPUTATION,
                     "Verifies whether HTTPS is active, valid, not expired, and matches the domain—while noting that attackers also use free SSL on phishing pages.",
                     frozenset({"tls", "journey"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        ev = ctx.evidence("tls")
        if not ev.available:
            return Outcome.missing(ev.reason or "The connection could not be inspected.")
        t = ev.value
        findings, facts = [], dict(Host=t.host, Port=t.port)
        fr = best_fetch(ctx)
        asks_secrets = bool(fr and fr.page and (page_kinds(fr.page) & SENSITIVE_KINDS))
        if not t.https:
            findings.append(fnd(S.HIGH if asks_secrets else S.MEDIUM, "no_https",
                                "The destination page is not protected by HTTPS" + (" yet asks for passwords or payment details: anything typed can be read in transit." if asks_secrets else ": traffic can be read or changed in transit.")))
            return Outcome.flagged(findings, **facts)
        if not t.handshake_ok:
            if t.error and any(w in t.error.lower() for w in ("timed out", "could not connect", "refused", "unreachable", "does not resolve", "dns lookup", "private, local or reserved", "not on the scanner")):
                return Outcome.missing(t.error)
            findings.append(fnd(S.MEDIUM, "handshake_failed", f"A secure connection could not be established: {t.error or t.verify_error}."))
            return Outcome.flagged(findings, **facts)
        facts.update(Protocol=t.protocol)
        if t.cert:
            c = t.cert
            facts.update(Issued_to=c.subject, Issuer=c.issuer, Valid_from=f"{c.not_before:%Y-%m-%d}", Valid_until=f"{c.not_after:%Y-%m-%d}")
        if t.verified:
            findings.append(fnd(S.INFO, "valid", f"The certificate is valid and matches {t.host}."))
        else:
            err = (t.verify_error or "certificate could not be verified").lower()
            if "hostname mismatch" in err or "ip address mismatch" in err:
                sev, msg = S.HIGH, "The certificate was issued for a different domain than the one you are visiting."
            elif "expired" in err:
                sev, msg = S.HIGH, "The certificate has expired."
            elif "self-signed" in err or "self signed" in err:
                sev, msg = S.HIGH, "The certificate is self-signed, so nobody independent vouches for this site."
            elif "revoked" in err:
                sev, msg = S.HIGH, "The certificate has been revoked."
            else:
                sev, msg = S.MEDIUM, f"The certificate could not be verified ({t.verify_error})."
            findings.append(fnd(sev, "invalid_cert", msg, Reason=t.verify_error))
        if t.cert:
            age = (ctx.now - t.cert.not_before).days
            if age <= 7:
                findings.append(fnd(S.LOW, "fresh_cert", f"The certificate was issued only {max(age, 0)} day{'s' if age != 1 else ''} ago.", Age_days=age))
            left = (t.cert.not_after - ctx.now).days
            if 0 <= left <= 7:
                findings.append(fnd(S.LOW, "expiring_cert", f"The certificate expires in {left} days."))
            if any(w in t.cert.issuer.lower() for w in ctx.ref.free_cert_issuers):
                findings.append(fnd(S.INFO, "free_ca", "Issued by a free certificate authority (very common for honest sites too)."))
        if t.protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(fnd(S.MEDIUM, "old_protocol", f"The server negotiated the outdated protocol {t.protocol}."))
        findings.append(fnd(S.INFO, "https_note", "HTTPS only proves the connection is encrypted and the certificate matches the domain. Attackers get free certificates for phishing pages too."))
        summary = ("Valid HTTPS certificate. This shows encryption, not honesty." if t.verified and not [f for f in findings if f.severity >= S.LOW] else None)
        return Outcome.flagged(findings, summary, **facts)


class HostingRiskCheck:
    spec = CheckSpec("hosting_risk", 12, "Hosting IP, ASN & Geo Risk Check", Category.REPUTATION,
                     "Evaluates the underlying server IP, hosting provider/ASN, and reputation history for high abuse or bulletproof-hosting patterns.",
                     frozenset({"dns", "hosting", "journey"}))

    def evaluate(self, ctx: CheckContext) -> Outcome:
        u, ref = ctx.url, ctx.ref
        final = parsed_final(ctx) or u
        dns, host_ev = ctx.evidence("dns"), ctx.evidence("hosting")
        if u.host_kind in ("none", "invalid"):
            return Outcome.missing("Not a web address, so there is no server to look up.")
        findings, facts = [], {}
        for p in {u.host_kind: u, final.host_kind: final}.values():
            if p.host_kind in ("ipv4", "ipv6"):
                findings.append(fnd(S.HIGH, "ip_host", f"The link points at a bare IP address ({p.host}) instead of a registered domain name.", Address=p.host))
                break
        for host in {u.host, final.host} - {""}:
            if ref.is_dynamic_dns(host):
                findings.append(fnd(S.MEDIUM, "dynamic_dns", f"{host} is a free dynamic-DNS name, normally used for temporary or home-hosted servers.", Host=host))
            elif any(host == t or host.endswith("." + t) for t in TUNNELS):
                findings.append(fnd(S.MEDIUM, "tunnel", f"{host} is a temporary tunnel to somebody's own computer.", Host=host))
            elif ref.is_ugc_host(host):
                findings.append(fnd(S.LOW, "free_hosting", f"{host} is on a platform where anyone can publish pages, so the platform's good name does not vouch for this page.", Host=host))
        if dns.available:
            for host, (kind, _reason) in dns.value.errors.items():
                if kind == "blocked":
                    findings.append(fnd(S.HIGH, "internal_address", f"{host} points at a private or reserved network address. A public link should never do that.", Host=host))
                elif kind == "nxdomain":
                    findings.append(fnd(S.LOW, "no_dns", f"{host} does not exist in DNS (a dead or not-yet-active link).", Host=host))
            ips = sorted({ip for addrs in dns.value.addresses.values() for ip in addrs})
            if ips:
                facts["Server addresses"] = pretty_list(ips, 4)
        if host_ev.available:
            entries = host_ev.value.entries
            for e in entries[:4]:
                label = f"AS{e.asn} {e.as_name or ''}".strip() if e.asn else "unknown network"
                facts[f"IP {e.ip}"] = f"{label} · {e.country or '??'}"
                if e.listed_in:
                    findings.append(fnd(S.HIGH, "abuse_network", f"{e.ip} sits in a network on {pretty_list(e.listed_in)}, lists of hijacked or criminal-controlled hosting.", IP=e.ip, Lists=pretty_list(e.listed_in)))
                if e.asn in ref.risky_asns:
                    findings.append(fnd(S.HIGH, "risky_asn", f"AS{e.asn} is on this installation's high-abuse network list.", ASN=e.asn))
                if e.country and e.country in ref.risky_countries:
                    findings.append(fnd(S.LOW, "risky_country", f"Hosted in {e.country}, which this installation lists as higher risk.", Country=e.country))
                if e.as_name and any(w in e.as_name.upper() for w in CDN_WORDS):
                    findings.append(fnd(S.INFO, "cdn", f"Served through {e.as_name.split(',')[0]}: the real server is hidden behind a large provider, which is normal for honest and malicious sites alike."))
            if len({e.ip for e in entries}) >= 6 and len({e.asn for e in entries if e.asn}) >= 3:
                findings.append(fnd(S.MEDIUM, "fast_flux", "The name resolves to many addresses across several networks, a pattern called fast-flux.", Addresses=len(entries)))
        if not dns.available and not host_ev.available and not findings:
            return Outcome.missing(dns.reason or host_ev.reason or "No hosting data was available.")
        limitation = None if host_ev.available else f"Network ownership could not be looked up ({host_ev.reason})."
        if not findings:
            return Outcome.clear("The server sits on an ordinary network with no abuse history on the lists used.", limitation, **facts)
        return Outcome.flagged(findings, limitation=limitation, **facts)

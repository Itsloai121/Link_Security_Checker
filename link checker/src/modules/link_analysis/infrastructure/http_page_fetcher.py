"""Follows a link like a browser would - HTTP redirects, meta-refresh and simple JavaScript redirects - recording every hop.

All traffic goes through the SSRF-guarded client; each hop is re-validated. Bodies are size-capped, never executed or stored.
"""
from __future__ import annotations

import hashlib
import time
from urllib.parse import urljoin

from infrastructure.external_services.guarded_http import USER_AGENTS, FetchError, GuardedHttpClient
from infrastructure.external_services.network_policy import BlockedDestination
from modules.link_analysis.domain.evidence import FetchResult, Hop
from modules.link_analysis.domain.sniff import sniff
from modules.link_analysis.domain.url_model import ParsedUrl
from modules.link_analysis.infrastructure.html_snapshot import build_snapshot, detect_client_redirect, text_fingerprint

_KIND_TO_OUTCOME = {"dns": "dns_failed", "connect": "connect_failed", "tls": "tls_failed", "timeout": "timeout", "protocol": "connect_failed"}
HTML_LIMIT, OTHER_LIMIT = 1_500_000, 4096


def _body_limit(headers: dict[str, str]) -> int:
    ct = headers.get("content-type", "").lower()
    return HTML_LIMIT if ("html" in ct or ct == "" or "xml" in ct) else OTHER_LIMIT


class HttpPageFetcher:
    def __init__(self, client: GuardedHttpClient, *, max_redirects: int = 8, total_timeout: float = 30.0, request_timeout: float = 10.0):
        self.client, self.max_redirects, self.total_timeout, self.request_timeout = client, max_redirects, total_timeout, request_timeout

    async def fetch_journey(self, url: ParsedUrl, profile: str) -> FetchResult:
        if not url.is_web:
            return FetchResult(profile, "not_fetchable", "Only http and https links can be followed.")
        headers = {"User-Agent": USER_AGENTS[profile], "Accept-Language": "en-US,en;q=0.9"}
        current, via = url.fetch_url, "initial"
        hops: list[Hop] = []
        seen: set[str] = set()
        started = time.monotonic()
        outcome, detail, page, digest, fingerprint = "ok", None, None, None, frozenset()
        for i in range(self.max_redirects + 2):
            if i > self.max_redirects:
                outcome, detail = "too_many_redirects", f"More than {self.max_redirects} redirects."
                break
            if current in seen:
                outcome, detail = "redirect_loop", "The link redirects in a circle."
                break
            seen.add(current)
            remaining = self.total_timeout - (time.monotonic() - started)
            if remaining <= 1:
                outcome, detail = "timeout", "The overall time budget for following the link ran out."
                break
            try:
                resp = await self.client.request("GET", current, headers=headers, total_timeout=min(self.request_timeout, remaining), body_limit=_body_limit)
            except BlockedDestination as exc:
                hops.append(Hop(i, current, None, via, error=exc.reason))
                outcome, detail = "blocked", exc.reason
                break
            except FetchError as exc:
                hops.append(Hop(i, current, None, via, error=exc.detail))
                outcome, detail = _KIND_TO_OUTCOME.get(exc.kind, "connect_failed"), exc.detail
                break
            ct = resp.headers.get("content-type")
            sniffed = sniff(resp.body[:512], ct)
            try:
                clen = int(resp.headers["content-length"]) if "content-length" in resp.headers else (len(resp.body) if not resp.truncated else None)
            except ValueError:
                clen = None
            location = resp.headers.get("location")
            hops.append(Hop(i, current, resp.status, via, location, ct, clen, resp.headers.get("content-disposition"), sniffed, None, resp.insecure_tls))
            if 300 <= resp.status < 400 and location:
                nxt = urljoin(current, location.strip())
                if not nxt.lower().startswith(("http://", "https://")):
                    hops.append(Hop(i + 1, nxt[:300], None, "http_redirect", error="The redirect points to a non-web address."))
                    outcome, detail = "not_fetchable", "The link redirects to a non-web address (" + (nxt.split(":", 1)[0].lower()[:20]) + ":)."
                    break
                current, via = nxt, "http_redirect"
                continue
            if sniffed == "html" and resp.body:
                page = build_snapshot(resp.body, ct, resp.truncated)
                digest = hashlib.sha256(resp.body).hexdigest()
                fingerprint = text_fingerprint(page.visible_text)
                client_side = detect_client_redirect(page)
                if client_side:
                    kind, target = client_side
                    nxt = urljoin(current, target)
                    if nxt.lower().startswith(("http://", "https://")) and nxt != current:
                        current, via = nxt, kind
                        continue
            break
        final = hops[-1] if hops else None
        return FetchResult(profile, outcome, detail, tuple(hops), final.url if final else None, final.status if final else None, page, digest, fingerprint)

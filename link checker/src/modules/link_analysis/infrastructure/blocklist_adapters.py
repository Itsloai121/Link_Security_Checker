"""BlocklistProvider implementations: downloaded feeds (default) and two optional key-gated online services."""
from __future__ import annotations

import asyncio
import json
from urllib.parse import quote, urlencode

from infrastructure.external_services.guarded_http import FetchError, GuardedHttpClient
from infrastructure.external_services.network_policy import BlockedDestination
from modules.link_analysis.domain.evidence import BlocklistHit
from modules.link_analysis.ports.evidence_sources import BlocklistAnswer, BlocklistQuery
from modules.threat_intel.application.use_cases import LookupIndicators
from shared.errors import DependencyFailure


class ThreatIntelBlocklist:
    """Consults the threat_intel module's public interface (never its tables)."""

    name = "Downloaded threat feeds"

    def __init__(self, lookup: LookupIndicators, titles: dict[str, str]):
        self.lookup, self.titles = lookup, titles

    def _title(self, source: str) -> str:
        return self.titles.get(source, source)

    async def check(self, query: BlocklistQuery) -> BlocklistAnswer:
        result = await self.lookup.execute(urls=query.urls, hosts=query.hosts)
        usable = {s: t for s, t in result.freshness.items() if s in self.titles}
        url_sources = {s: t for s, t in usable.items()}
        if not url_sources:
            raise DependencyFailure("No threat feeds have been downloaded yet (run `update-feeds`).")
        hits = tuple(BlocklistHit(self._title(h.source), h.value, h.kind, h.category, h.loaded_at) for h in result.hits if h.kind in ("url", "host"))
        return BlocklistAnswer(hits, tuple(self._title(s) for s in usable), tuple((self._title(s), t) for s, t in usable.items()))


class GoogleSafeBrowsingBlocklist:
    """Optional. Sends the checked URLs to Google (disclosed in the docs); enabled only when an API key is configured."""

    name = "Google Safe Browsing"
    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    CATEGORY = {"SOCIAL_ENGINEERING": "phishing", "MALWARE": "malware", "UNWANTED_SOFTWARE": "malware", "POTENTIALLY_HARMFUL_APPLICATION": "malware"}

    def __init__(self, client: GuardedHttpClient, api_key: str):
        self.client, self._key = client, api_key

    async def check(self, query: BlocklistQuery) -> BlocklistAnswer:
        body = json.dumps({"client": {"clientId": "unmask", "clientVersion": "1.0"}, "threatInfo": {
            "threatTypes": list(self.CATEGORY), "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in query.urls[:50]]}}).encode()
        try:
            resp = await self.client.request("POST", f"{self.ENDPOINT}?key={quote(self._key)}", headers={"Content-Type": "application/json"},
                                             body=body, max_bytes=500_000, total_timeout=8, allow_insecure_retry=False)
        except (FetchError, BlockedDestination) as exc:  # never include the request URL: it contains the key
            raise DependencyFailure("Google Safe Browsing could not be reached.") from exc
        if resp.status != 200:
            raise DependencyFailure(f"Google Safe Browsing answered HTTP {resp.status}.")
        try:
            matches = json.loads(resp.body).get("matches", [])
        except ValueError as exc:
            raise DependencyFailure("Google Safe Browsing sent an unreadable answer.") from exc
        hits = tuple(BlocklistHit(self.name, m.get("threat", {}).get("url", "?"), "url", self.CATEGORY.get(m.get("threatType", ""), "unknown")) for m in matches)
        return BlocklistAnswer(hits, (self.name,))


class UrlhausBlocklist:
    """Optional. URLhaus (abuse.ch) lookup API; requires a free Auth-Key and sends the checked URLs/hosts to abuse.ch."""

    name = "URLhaus"
    BASE = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, client: GuardedHttpClient, auth_key: str):
        self.client, self._key = client, auth_key

    async def _post(self, path: str, field: str, value: str) -> dict:
        try:
            resp = await self.client.request("POST", f"{self.BASE}/{path}/", headers={"Auth-Key": self._key, "Content-Type": "application/x-www-form-urlencoded"},
                                             body=urlencode({field: value}).encode(), max_bytes=300_000, total_timeout=8, allow_insecure_retry=False)
        except (FetchError, BlockedDestination) as exc:
            raise DependencyFailure("URLhaus could not be reached.") from exc
        if resp.status in (401, 403):
            raise DependencyFailure("URLhaus rejected the configured Auth-Key.")
        if resp.status != 200:
            raise DependencyFailure(f"URLhaus answered HTTP {resp.status}.")
        try:
            return json.loads(resp.body)
        except ValueError as exc:
            raise DependencyFailure("URLhaus sent an unreadable answer.") from exc

    async def check(self, query: BlocklistQuery) -> BlocklistAnswer:
        urls, hosts = query.urls[:6], query.hosts[:4]
        answers = await asyncio.gather(*(self._post("url", "url", u) for u in urls), *(self._post("host", "host", h) for h in hosts))
        hits: list[BlocklistHit] = []
        for value, data in zip([*urls, *hosts], answers, strict=True):
            if data.get("query_status") != "ok":
                continue
            if "urls_online" in data and int(data.get("urls_online") or 0) == 0:
                continue  # host known to URLhaus but with nothing currently online
            hits.append(BlocklistHit(self.name, value, "url" if value in urls else "host", "malware"))
        return BlocklistAnswer(tuple(hits), (self.name,))

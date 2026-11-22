"""Catalog loader + HTTPS downloader for threat feeds. Downloads go through the SSRF-guarded client (https only, size-capped)."""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from infrastructure.external_services.guarded_http import FetchError, GuardedHttpClient
from infrastructure.external_services.network_policy import BlockedDestination
from modules.threat_intel.domain.indicators import CATEGORIES, FORMATS, KINDS, FeedDefinition
from shared.errors import DependencyFailure


class FeedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9_]{2,40}$")
    title: str
    url: str = Field(pattern=r"^https://")
    format: str
    kind: str
    category: str
    min_expected: int = Field(default=1, ge=0)
    max_bytes: int = Field(default=10_000_000, ge=1_000, le=100_000_000)
    terms: str = ""
    terms_url: str = ""
    attribution: str = ""

    @field_validator("format")
    @classmethod
    def _f(cls, v: str) -> str:
        if v not in FORMATS:
            raise ValueError(f"format must be one of {FORMATS}")
        return v

    @field_validator("kind")
    @classmethod
    def _k(cls, v: str) -> str:
        if v not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        return v

    @field_validator("category")
    @classmethod
    def _c(cls, v: str) -> str:
        if v not in CATEGORIES:
            raise ValueError(f"category must be one of {CATEGORIES}")
        return v


class FeedsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    description: str = ""
    feeds: list[FeedModel]


class JsonFeedCatalog:
    def __init__(self, path: Path):
        data = FeedsFile.model_validate(json.loads(path.read_text(encoding="utf-8")))
        names = [f.name for f in data.feeds]
        if len(set(names)) != len(names):
            raise ValueError("duplicate feed names in feeds.json")
        self._feeds = [FeedDefinition(**f.model_dump()) for f in data.feeds]

    def feeds(self) -> list[FeedDefinition]:
        return list(self._feeds)


class HttpFeedDownloader:
    def __init__(self, client: GuardedHttpClient):
        self.client = client

    async def download(self, feed: FeedDefinition) -> str:
        try:
            resp = await self.client.request("GET", feed.url, headers={"User-Agent": "UnmaskFeedUpdater/1.0", "Accept": "text/plain,application/json,*/*"},
                                             max_bytes=feed.max_bytes, total_timeout=60.0, allow_insecure_retry=False)
        except (FetchError, BlockedDestination) as exc:
            raise DependencyFailure(f"download failed: {getattr(exc, 'detail', None) or getattr(exc, 'reason', 'blocked')}", "FEED_DOWNLOAD_FAILED") from exc
        if resp.status != 200:
            raise DependencyFailure(f"download failed: HTTP {resp.status}", "FEED_DOWNLOAD_FAILED")
        if resp.truncated:
            raise DependencyFailure("download rejected: larger than the configured size limit", "FEED_TOO_LARGE")
        return resp.body.decode("utf-8", errors="replace")

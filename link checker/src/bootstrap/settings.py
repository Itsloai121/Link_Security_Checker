"""Typed, validated configuration (USBA §14, USSA pillar 10: secrets). Invalid or unsafe values stop the app at startup.

Every value comes from an UNMASK_* environment variable (or a local .env file, which is never committed).
Secrets are `SecretStr`, so they cannot leak through repr() or logs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
APP_VERSION = "1.0.0"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="UNMASK_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: Literal["development", "production", "test"] = "development"
    host: str = Field("127.0.0.1", min_length=1)
    port: int = Field(8000, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True

    # storage & files
    database_path: Path = ROOT / "var" / "unmask.db"
    migrations_dir: Path = ROOT / "migrations"
    config_dir: Path = ROOT / "config" / "defaults"
    web_dir: Path = ROOT / "src" / "interfaces" / "web"
    assets_dir: Path = ROOT / "assets"
    auto_migrate: bool = False

    # analysis behaviour
    scan_retention_hours: int = Field(24, ge=1, le=24 * 30)
    scan_deadline_seconds: float = Field(45.0, ge=10, le=300)
    max_redirects: int = Field(8, ge=1, le=15)
    max_url_length: int = Field(2048, ge=64, le=8192)
    worker_concurrency: int = Field(3, ge=1, le=16)
    queue_size: int = Field(100, ge=1, le=10_000)
    enable_cloaking_probe: bool = True
    enable_registration_lookup: bool = True
    enable_ip_intelligence: bool = True

    # outbound safety (SSRF)
    allowed_fetch_ports: str = "80,443,8080,8443"
    allow_private_networks: bool = False  # for automated tests only

    # abuse protection
    rate_limit_submit_per_minute: int = Field(10, ge=1, le=1000)
    rate_limit_read_per_minute: int = Field(240, ge=1, le=10_000)
    per_host_scans_per_minute: int = Field(6, ge=1, le=1000)
    trusted_proxy_hops: int = Field(0, ge=0, le=5)
    max_body_bytes: int = Field(8192, ge=1024, le=1_048_576)
    hsts: bool = False

    # optional integrations (secrets)
    gsb_api_key: SecretStr | None = None
    urlhaus_auth_key: SecretStr | None = None
    metrics_token: SecretStr | None = None

    # threat feeds and housekeeping
    enabled_feeds: str = "openphish,spamhaus_drop,spamhaus_drop_v6,spamhaus_asndrop"
    feed_refresh_hours: int = Field(0, ge=0, le=168)  # 0 = refresh only via the CLI / cron
    purge_interval_minutes: int = Field(30, ge=1, le=1440)

    @field_validator("allowed_fetch_ports")
    @classmethod
    def _ports(cls, v: str) -> str:
        ports = [p.strip() for p in v.split(",") if p.strip()]
        if not ports or any(not p.isdigit() or not 1 <= int(p) <= 65535 for p in ports):
            raise ValueError("must be a comma-separated list of port numbers")
        return ",".join(ports)

    @model_validator(mode="after")
    def _safety(self) -> "Settings":
        if self.environment == "production" and self.allow_private_networks:
            raise ValueError("UNMASK_ALLOW_PRIVATE_NETWORKS must be false in production (it disables SSRF protection)")
        return self

    @property
    def fetch_ports(self) -> frozenset[int]:
        return frozenset(int(p) for p in self.allowed_fetch_ports.split(","))

    @property
    def enabled_feed_names(self) -> list[str]:
        return [n.strip() for n in self.enabled_feeds.split(",") if n.strip()]

    @property
    def is_dev(self) -> bool:
        return self.environment != "production"

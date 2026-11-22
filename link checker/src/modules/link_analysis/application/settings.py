from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisPolicy:
    """Behavioural limits for the analysis workflow (all injected from validated configuration)."""

    engine_version: str = "1.0.0"
    retention_hours: int = 24
    scan_deadline_seconds: float = 45.0
    max_input_length: int = 2048
    max_label_length: int = 300
    cloaking_probe: bool = True
    registration_lookup: bool = True
    ip_intelligence: bool = True
    max_registration_domains: int = 3
    max_hosts_resolved: int = 4
    max_ips_enriched: int = 6
    running_scan_stale_seconds: int = 300

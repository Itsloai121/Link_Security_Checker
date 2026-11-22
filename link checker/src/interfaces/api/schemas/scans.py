"""Request/response contracts (USBA §4.3). Responses never expose internal types or stack traces."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
CheckStatusT = Literal["clear", "notice", "warning", "danger", "unavailable"]
VerdictT = Literal["safe", "caution", "suspicious", "dangerous", "inconclusive"]
ScanStatusT = Literal["queued", "running", "completed", "failed"]
CategoryT = Literal["address", "journey", "reputation", "behavior"]


class SubmitScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=4096, description="The link to analyse, exactly as received. Any string is accepted, including javascript: and data: links; it is analysed, never executed.")
    display_text: str | None = Field(default=None, max_length=1000, description="Optional: the visible label the link had (e.g. 'Click here for the official portal').")


class KeyValue(BaseModel):
    key: str
    value: str


class FindingOut(BaseModel):
    severity: Severity
    code: str
    message: str
    evidence: list[KeyValue] = []


class CheckResultOut(BaseModel):
    id: str
    position: int
    title: str
    category: CategoryT
    category_label: str
    explanation: str
    status: CheckStatusT
    risk_points: int = Field(ge=0, le=100)
    summary: str
    findings: list[FindingOut] = []
    facts: list[KeyValue] = []
    limitation: str | None = None
    duration_ms: int = 0


class Progress(BaseModel):
    done: int
    total: int


class Counts(BaseModel):
    flagged: int
    clear: int
    unverified: int


class ScanOut(BaseModel):
    id: str
    status: ScanStatusT
    submitted_input: str
    display_text: str | None = None
    normalized_url: str | None = None
    final_url: str | None = None
    verdict: VerdictT | None = None
    headline: str | None = None
    reasons: list[str] = []
    risk_score: int | None = None
    coverage_percent: int | None = None
    progress: Progress
    counts: Counts
    created_at: datetime
    expires_at: datetime
    completed_at: datetime | None = None
    error_code: str | None = None
    engine_version: str
    checks: list[CheckResultOut] = []


class CheckCatalogItem(BaseModel):
    id: str
    position: int
    title: str
    category: CategoryT
    category_label: str
    explanation: str


class CheckCatalogOut(BaseModel):
    checks: list[CheckCatalogItem]
    categories: dict[str, str]


class ErrorDetail(BaseModel):
    field: str | None = None
    issue: str


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str
    details: list[ErrorDetail] = []


class ErrorResponse(BaseModel):
    error: ErrorBody


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    checks: dict[str, str] = {}

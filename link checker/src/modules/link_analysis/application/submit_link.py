from __future__ import annotations

import logging
from dataclasses import dataclass

from infrastructure.messaging.in_process_queue import QueueFull
from infrastructure.observability.logging import event
from infrastructure.observability.metrics import Metrics
from modules.link_analysis.application.settings import AnalysisPolicy
from modules.link_analysis.domain.scan import Scan, ScanStatus
from modules.link_analysis.ports.job_queue import ScanJobQueue
from modules.link_analysis.ports.scan_repository import ScanRepository
from shared.contracts.clock import Clock, IdGenerator
from shared.errors import ServiceBusy, ValidationFailed
from shared.utilities.redaction import redact_url

log = logging.getLogger("unmask.submit")


@dataclass(frozen=True)
class SubmitLink:
    url: str
    display_text: str | None = None


class SubmitLinkForAnalysis:
    """Validate -> persist (queued) -> enqueue. Returns immediately; analysis runs in a worker (USBA §9)."""

    def __init__(self, repo: ScanRepository, queue: ScanJobQueue, clock: Clock, ids: IdGenerator, policy: AnalysisPolicy, metrics: Metrics):
        self.repo, self.queue, self.clock, self.ids, self.policy, self.metrics = repo, queue, clock, ids, policy, metrics

    async def execute(self, cmd: SubmitLink) -> Scan:
        raw = (cmd.url or "").strip()
        label = (cmd.display_text or "").strip() or None
        problems: list[dict[str, str]] = []
        if not raw:
            problems.append({"field": "url", "issue": "Enter the link you want to check."})
        elif len(raw) > self.policy.max_input_length:
            problems.append({"field": "url", "issue": f"The link is too long (maximum {self.policy.max_input_length} characters)."})
        elif "\x00" in raw:
            problems.append({"field": "url", "issue": "The link contains an invalid character."})
        if label is not None and (len(label) > self.policy.max_label_length or "\x00" in label):
            problems.append({"field": "display_text", "issue": f"The link text must be at most {self.policy.max_label_length} characters."})
        if problems:
            raise ValidationFailed("Please check what you entered.", problems)
        now = self.clock.now()
        from datetime import timedelta
        scan = Scan(id=self.ids.new_scan_id(), submitted_input=raw, display_text=label, status=ScanStatus.QUEUED, created_at=now,
                    expires_at=now + timedelta(hours=self.policy.retention_hours), engine_version=self.policy.engine_version)
        await self.repo.add(scan)
        try:
            self.queue.enqueue_nowait(scan.id)
        except QueueFull as exc:
            await self.repo.delete(scan.id)
            self.metrics.inc("unmask_scans_rejected_total", {"reason": "queue_full"})
            raise ServiceBusy() from exc
        self.metrics.inc("unmask_scans_submitted_total")
        event(log, "scan_submitted", scan_id=scan.id, target=redact_url(raw))
        return scan

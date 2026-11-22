"""SQLite adapter for ScanRepository. Only this class reads or writes the scans/scan_checks tables."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from infrastructure.persistence.sqlite import SqliteDatabase
from modules.link_analysis.domain.checks.base import CheckResult, CheckStatus, Finding, Severity
from modules.link_analysis.domain.scan import Scan, ScanStatus, Verdict
from shared.utilities.time import from_iso, to_iso

_HEADER_COLUMNS = ("status", "normalized_url", "final_url", "verdict", "risk_score", "coverage_percent", "headline", "reasons_json",
                   "error_code", "started_at", "completed_at")


def _detail_json(r: CheckResult) -> str:
    return json.dumps({"v": 1, "findings": [{"severity": f.severity.name.lower(), "code": f.code, "message": f.message, "evidence": [list(e) for e in f.evidence]} for f in r.findings],
                       "facts": [list(f) for f in r.facts], "limitation": r.limitation}, ensure_ascii=False)


def _result_from_row(row: sqlite3.Row) -> CheckResult:
    d = json.loads(row["detail_json"])
    findings = tuple(Finding(Severity[f["severity"].upper()], f["code"], f["message"], tuple((a, b) for a, b in f["evidence"])) for f in d["findings"])
    return CheckResult(row["check_id"], row["position"], CheckStatus(row["status"]), row["risk_points"], row["summary"], findings,
                       tuple((a, b) for a, b in d["facts"]), d.get("limitation"), row["duration_ms"])


class SqliteScanRepository:
    def __init__(self, db: SqliteDatabase):
        self.db = db

    async def add(self, scan: Scan) -> None:
        def _do(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO scans (id, status, submitted_input, display_text, engine_version, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
                (scan.id, scan.status.value, scan.submitted_input, scan.display_text, scan.engine_version, to_iso(scan.created_at), to_iso(scan.expires_at)))
        await self.db.run(_do)

    async def get(self, scan_id: str) -> Scan | None:
        def _do(conn: sqlite3.Connection):
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None, []
            return row, conn.execute("SELECT * FROM scan_checks WHERE scan_id = ? ORDER BY position", (scan_id,)).fetchall()
        row, checks = await self.db.run(_do, write=False)
        if row is None:
            return None
        return Scan(id=row["id"], submitted_input=row["submitted_input"], display_text=row["display_text"], status=ScanStatus(row["status"]),
                    created_at=from_iso(row["created_at"]), expires_at=from_iso(row["expires_at"]), engine_version=row["engine_version"],
                    normalized_url=row["normalized_url"], final_url=row["final_url"], verdict=Verdict(row["verdict"]) if row["verdict"] else None,
                    risk_score=row["risk_score"], coverage_percent=row["coverage_percent"], headline=row["headline"],
                    reasons=json.loads(row["reasons_json"]), error_code=row["error_code"], started_at=from_iso(row["started_at"]),
                    completed_at=from_iso(row["completed_at"]), results=[_result_from_row(c) for c in checks])

    async def save(self, scan: Scan) -> None:
        values = (scan.status.value, scan.normalized_url, scan.final_url, scan.verdict.value if scan.verdict else None, scan.risk_score,
                  scan.coverage_percent, scan.headline, json.dumps(scan.reasons, ensure_ascii=False), scan.error_code,
                  to_iso(scan.started_at), to_iso(scan.completed_at), scan.id)
        sql = "UPDATE scans SET " + ", ".join(f"{c} = ?" for c in _HEADER_COLUMNS) + " WHERE id = ?"
        await self.db.run(lambda conn: conn.execute(sql, values))

    async def save_result(self, scan_id: str, r: CheckResult) -> None:
        def _do(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO scan_checks (scan_id, check_id, position, status, risk_points, summary, detail_json, duration_ms) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT (scan_id, check_id) DO UPDATE SET status=excluded.status, risk_points=excluded.risk_points, summary=excluded.summary, "
                "detail_json=excluded.detail_json, duration_ms=excluded.duration_ms",
                (scan_id, r.check_id, r.position, r.status.value, r.risk_points, r.summary, _detail_json(r), r.duration_ms))
        try:
            await self.db.run(_do)
        except sqlite3.IntegrityError:  # scan deleted by its owner while still running: drop the result silently
            pass

    async def delete(self, scan_id: str) -> bool:
        return await self.db.run(lambda conn: conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount > 0)

    async def purge_expired(self, now: datetime) -> int:
        return await self.db.run(lambda conn: conn.execute("DELETE FROM scans WHERE expires_at <= ?", (to_iso(now),)).rowcount)

    async def ids_with_status(self, status: ScanStatus, limit: int = 500) -> list[str]:
        return await self.db.run(lambda conn: [r["id"] for r in conn.execute("SELECT id FROM scans WHERE status = ? ORDER BY created_at LIMIT ?", (status.value, limit))], write=False)

    async def fail_stale_running(self, before: datetime, now: datetime) -> int:
        return await self.db.run(lambda conn: conn.execute(
            "UPDATE scans SET status = 'failed', error_code = 'INTERRUPTED', completed_at = ? WHERE status = 'running' AND started_at <= ?",
            (to_iso(now), to_iso(before))).rowcount)

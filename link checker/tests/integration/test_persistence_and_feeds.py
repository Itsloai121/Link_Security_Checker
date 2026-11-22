import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from infrastructure.persistence.migrator import MigrationError, migrate, schema_is_current
from infrastructure.persistence.sqlite import SqliteDatabase
from infrastructure.observability.metrics import Metrics
from modules.link_analysis.domain.checks.base import CheckResult, CheckStatus, Severity, fnd
from modules.link_analysis.domain.scan import Scan, ScanStatus
from modules.link_analysis.infrastructure.sqlite_scan_repository import SqliteScanRepository
from modules.threat_intel.application.use_cases import GetFeedStatus, LookupIndicators, RefreshFeeds
from modules.threat_intel.infrastructure.feed_adapters import JsonFeedCatalog
from modules.threat_intel.infrastructure.sqlite_indicator_repository import SqliteIndicatorRepository
from shared.errors import DependencyFailure
from shared.utilities.time import SystemClock
from tests.unit.conftest import NOW

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def db(tmp_path):
    d = SqliteDatabase(tmp_path / "t.db")
    migrate(d, ROOT / "migrations")
    return d


def mkscan(i="a" * 22, status=ScanStatus.QUEUED, expires=None):
    return Scan(i, "https://example.com/?x=1", "label", status, NOW, expires or NOW + timedelta(hours=24), "1.0.0")


def test_migrations_are_repeatable_and_tamper_evident(tmp_path):
    d = SqliteDatabase(tmp_path / "m.db")
    assert migrate(d, ROOT / "migrations") == ["0001_scans", "0002_threat_intel"]
    assert migrate(d, ROOT / "migrations") == []
    assert schema_is_current(d, ROOT / "migrations")[0]
    copy = tmp_path / "mig"; copy.mkdir()
    for f in (ROOT / "migrations").glob("*.sql"):
        (copy / f.name).write_text(f.read_text() + ("\n-- edited after apply" if f.name.startswith("0001") else ""))
    with pytest.raises(MigrationError):
        migrate(d, copy)                                    # an applied migration must never be edited
    assert not schema_is_current(SqliteDatabase(tmp_path / "empty.db"), ROOT / "migrations")[0]


async def test_scan_round_trip_and_constraints(db):
    repo = SqliteScanRepository(db)
    s = mkscan(); await repo.add(s)
    s.start(NOW, "https://example.com/?x=1"); await repo.save(s)
    r = CheckResult("lookalike", 2, CheckStatus.DANGER, 35, "sum", (fnd(Severity.HIGH, "c", "msg", Brand="PayPal"),), (("Domain", "x.com"),), "lim", 12)
    await repo.save_result(s.id, r); await repo.save_result(s.id, r)          # idempotent upsert
    got = await repo.get(s.id)
    assert got.status is ScanStatus.RUNNING and len(got.results) == 1 and got.results[0].findings[0].evidence == (("Brand", "PayPal"),)
    with pytest.raises(sqlite3.IntegrityError):                                # the database refuses a verdict on an unfinished scan
        await db.run(lambda c: c.execute("UPDATE scans SET verdict='safe' WHERE id=?", (s.id,)))
    with pytest.raises(sqlite3.IntegrityError):
        await db.run(lambda c: c.execute("INSERT INTO scan_checks VALUES (?,?,?,?,?,?,?,?)", (s.id, "x", 99, "clear", 0, "s", "{}", 1)))
    assert await repo.delete(s.id) and await repo.get(s.id) is None
    assert await db.run(lambda c: c.execute("SELECT COUNT(*) FROM scan_checks").fetchone()[0], write=False) == 0   # cascade


async def test_retention_purge_and_crash_recovery(db):
    repo = SqliteScanRepository(db)
    await repo.add(mkscan("a" * 22, expires=NOW - timedelta(minutes=1)))
    await repo.add(mkscan("b" * 22))
    stale = mkscan("c" * 22); await repo.add(stale); stale.start(NOW - timedelta(hours=1), "x"); await repo.save(stale)
    assert await repo.purge_expired(NOW) == 1
    assert await repo.ids_with_status(ScanStatus.QUEUED) == ["b" * 22]
    assert await repo.fail_stale_running(NOW, NOW) == 1 and (await repo.get("c" * 22)).error_code == "INTERRUPTED"


class FakeDownloader:
    def __init__(self, bodies):
        self.bodies = bodies

    async def download(self, feed):
        body = self.bodies[feed.name]
        if isinstance(body, Exception):
            raise body
        return body


async def test_feed_refresh_lookup_and_safety(db):
    repo, cat = SqliteIndicatorRepository(db), JsonFeedCatalog(ROOT / "config" / "defaults" / "feeds.json")
    phish = "\n".join(f"http://p{i}.example/x" for i in range(30)) + "\nhttp://evil.example/login.php\n"
    dl = FakeDownloader({"openphish": phish, "spamhaus_drop": "\n".join(f'{{"cidr":"198.51.{i}.0/24"}}' for i in range(120)) + '\n{"cidr":"203.0.113.0/24"}',
                         "spamhaus_asndrop": "\n".join(f'{{"asn":{64500 + i}}}' for i in range(10))})
    refresh = RefreshFeeds(repo, dl, cat, SystemClock(), ["openphish", "spamhaus_drop", "spamhaus_asndrop"], Metrics())
    results = {r.source: r for r in await refresh.execute()}
    assert results["openphish"].status == results["spamhaus_drop"].status == "succeeded" and results["spamhaus_drop_v6"].status == "skipped"
    look = LookupIndicators(repo)
    res = await look.execute(urls=["http://evil.example/login.php?email=v@x.com"], ips=["203.0.113.9", "8.8.8.8"], asns=[64503])
    assert {(h.source, h.kind) for h in res.hits} == {("openphish", "url"), ("spamhaus_drop", "cidr"), ("spamhaus_asndrop", "asn")}
    # a truncated download must not destroy the good data we already have
    refresh_bad = RefreshFeeds(repo, FakeDownloader({"openphish": "http://only-one.example/"}), cat, SystemClock(), ["openphish"], Metrics())
    assert (await refresh_bad.execute("openphish"))[0].status == "rejected" and await repo.count("openphish") == 31
    broken = RefreshFeeds(repo, FakeDownloader({"openphish": DependencyFailure("download failed: HTTP 503")}), cat, SystemClock(), ["openphish"], Metrics())
    assert (await broken.execute("openphish"))[0].status == "failed" and await repo.count("openphish") == 31
    status = {s["name"]: s for s in await GetFeedStatus(repo, cat, ["openphish"]).execute()}
    assert status["openphish"]["last_status"] == "failed" and status["openphish"]["indicators"] == 31

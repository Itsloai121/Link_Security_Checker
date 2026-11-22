# Project data architecture specification (USDA §26)

**Version:** 1.0 · **Storage:** SQLite (WAL) · **Schema:** `/migrations` (0001 scans, 0002 threat intel)

## 1. Data overview
- **Purpose and use cases:** let a person analyse a suspicious link and read the report; keep the report just long enough to be useful, then delete it.
- **Main data domains:** *scans* (a submitted link and its 20 results), *threat indicators* (derived from public feeds), *reference data* (brands, word lists, lure phrases), *feed update history*.
- **Volume and growth:** tiny. A scan is about 5 to 30 KB (20 result rows with JSON detail). At 24-hour retention, 10 000 scans a day is roughly 100 to 300 MB at the peak. Threat indicators: tens of thousands of rows (about 20 MB).
- **Sources and consumers:** sources are the person submitting the link, the analysed website, DNS/TLS/RDAP/ASN lookups, and public threat feeds. Consumers are the web UI, the API, and the CLI.

## 2. Data ownership
| Domain | Owner (module) | Authoritative source |
|---|---|---|
| Scans, check results | `link_analysis` (only `SqliteScanRepository` touches the tables) | the database row |
| Threat indicators, feed updates | `threat_intel` (only `SqliteIndicatorRepository`) | the downloaded feed; the DB copy is derived and rebuildable |
| Reference data | the maintainer, in `config/defaults/reference/*.json` | the JSON files in git |
| Rate-limit windows | in-memory, per process | none (disposable) |

Master/reference data: brands and their official domains, shorteners, risky TLDs, free-hosting platforms, dangerous schemes, lure phrases. **Stewardship:** the maintainer reviews these lists; the loader validates them at start-up (`config/schemas/*.json`, generated from the same models) and refuses to start on bad data.

## 3. Classification and lifecycle
| Data | Class | Purpose | Retention | Deletion |
|---|---|---|---|---|
| Submitted link, optional label | **Confidential** (links can carry tokens or personal data) | show the report to the submitter | 24 h (`UNMASK_SCAN_RETENTION_HOURS`) | automatic purge every 30 min; user can delete any time (`DELETE /api/v1/scans/{id}`); cascade removes results |
| Check results (findings, evidence strings) | Confidential (may quote page text) | the report | same row lifetime | cascade |
| Page bodies, downloaded files | never stored | only parsed in memory | none | n/a |
| Threat indicators | Public (third-party data) | blocklist and abuse-network tests | until the next refresh replaces them | replaced atomically |
| Logs | Internal | operations | per operator | log host and scan id only, never paths, queries or credentials |
| Secrets (API keys, tokens) | Restricted | optional integrations | n/a | environment only, never in the database or logs |

Collected: only what the test needs. Not collected: accounts, cookies, device identifiers, client IP addresses (the rate limiter keeps a *hash* in memory only).

## 4. Data model
**Conceptual:** a *Scan* has many *CheckResults* (exactly one per test, 20 in total); a *Scan* is addressed by an unguessable id. Separately, *ThreatIndicators* are listed by *Source* and refreshed by *FeedUpdates*.

**Physical (see `migrations/`):**
- `scans(id PK 22 chars, status, submitted_input, display_text, normalized_url, final_url, verdict, risk_score, coverage_percent, headline, reasons_json, error_code, engine_version, created_at, started_at, completed_at, expires_at)`: `STRICT` table with `CHECK`s: status and verdict vocabularies, score ranges, **a verdict exists exactly when status is `completed`**, a failed scan has an error code, `json_valid` on JSON columns.
- `scan_checks(scan_id FK ON DELETE CASCADE, check_id, position 1..20, status, risk_points 0..100, summary, detail_json, duration_ms, PK(scan_id, check_id), UNIQUE(scan_id, position))`. `detail_json` holds the variable part (findings, facts, limitation), shaped by `{"v": 1, …}` and `scans.engine_version`.
- `threat_indicators(source, kind url|host|cidr|asn, value, category, loaded_at, PK(source, kind, value))`, `WITHOUT ROWID`, indexed by `(kind, value)`.
- `feed_updates(id, source, started_at, finished_at, status running|succeeded|rejected|failed, indicators_loaded, previous_count, note)`.

**Identifiers:** scan ids are 128-bit random (`secrets.token_urlsafe(16)`), so possession of the id is the access right (ADR 0006). **History:** results are not versioned; `engine_version` records which release produced a report. **Time:** every timestamp is UTC ISO-8601 with `Z`; naive datetimes are rejected at the boundary (`shared/utilities/time.py`).

## 5. Storage design
- **Selected store:** one SQLite database file. Justification: one writer, small data, no network hop, transactional, trivially backed up; matches the single-deployable decision (ADR 0001/0002).
- **File/object storage:** none. **Search index / analytical store:** none.
- **Caches:** the in-memory rate-limit windows and a 5-minute CIDR list rebuilt from `threat_indicators`. Both are derived and safe to lose.
- **Source-of-truth map:** see section 2.
- **Permissions:** the data directory is created `0700` on POSIX; the process uses one database file with no separate users (SQLite has none). The application never runs DDL: only `python -m interfaces.cli migrate` does, and startup refuses to run against a schema that is not current.
- **Move to PostgreSQL when:** more than one application node is needed, or sustained write contention appears (`SQLITE_BUSY` in logs). The repositories are the only code that would change.

## 6. Data access and query patterns
- **Writes:** insert a scan; update its header at start and end; upsert one result row per test (≈20 per scan); delete by id; bulk delete by `expires_at`; replace one feed source in a single transaction.
- **Reads:** by primary key (`GET /scans/{id}`, polled about once per second, always indexed); `scan_checks` by `scan_id` (primary key prefix); indicator lookups by `(kind, value IN (…))` (chunks of 500); startup scans by `status`.
- **Pagination / listing:** none by design: there is no "list all scans" endpoint, which also removes an enumeration risk.
- **Consistency:** read-your-writes within one process. Poll results may lag a write by at most one poll interval. Feed data is "as fresh as the last refresh" and the report shows its timestamp.

## 7. Data ingestion and integration (threat feeds)
- **Source contracts:** `config/defaults/feeds.json`: URL (HTTPS only), format (`urls`, `hosts`, `cidr_json_lines`, `cidr_text`, `asn_json_lines`, `asn_text`), kind, category, minimum expected size, maximum bytes, licence text. Validated by `config/schemas/feeds.schema.json`.
- **Modes:** `update-feeds` (CLI/cron), optional in-process schedule (`UNMASK_FEED_REFRESH_HOURS`), `import-feed` from a local file.
- **Validation and deduplication:** size cap, line-by-line parsing, normalisation (lower-case host, default ports and fragments removed), duplicates collapsed by the primary key. Unreadable lines are counted and reported; metadata lines are ignored.
- **Quarantine / replay:** a download that parses to fewer than `min_expected` indicators, or that would shrink the list by more than 80%, is **rejected** and the old data stays; the rejection is recorded in `feed_updates`. Replay = run the command again.
- **Reconciliation:** each update records loaded and previous counts.

## 8. Data quality
| Dimension | Rule | Where enforced |
|---|---|---|
| Validity | vocabularies, ranges, `json_valid`, id length | `CHECK` constraints |
| Completeness | a scan completes only with all 20 results; a verdict only when completed | `Scan` aggregate + `CHECK` |
| Uniqueness | one result per test per scan; one indicator per (source, kind, value) | primary/unique keys |
| Accuracy of reference data | lists validated; reviewed by the maintainer | loader at start-up |
| Freshness | feed timestamps shown in the blocklist test; a never-downloaded feed makes the test "not verified" | `ThreatIntelBlocklist` |

## 9. Metadata and lineage
- **Data dictionary:** this document plus the column comments in `migrations/0001_scans.sql` and `0002_threat_intel.sql`; JSON Schemas for the config files in `config/schemas/`; the API schema in `docs/api/openapi.json`.
- **Lineage:** every finding carries its check id and evidence; every indicator carries its `source` and `loaded_at`; every scan carries `engine_version`. Operational metadata: `schema_migrations` (version, name, SHA-256 checksum, applied_at) and `feed_updates`.

## 10. Consistency and transactions
- **Boundaries:** one repository call = one transaction (`BEGIN IMMEDIATE`; readers use `BEGIN`; WAL gives concurrent readers).
- **Concurrency:** `busy_timeout` 5 s; workers never write the same row except via the check upsert (idempotent `ON CONFLICT DO UPDATE`).
- **Idempotency:** a job whose scan is not `queued` is skipped; results are upserts; a deleted scan's late results are dropped silently.
- **Conflicts:** last write wins is safe because each row has a single writer (the one worker analysing that scan).

## 11. Schema change management
- Numbered, checksummed SQL files; applied files are immutable (editing one makes `migrate` refuse). The migrator is repeatable and runs each file in a transaction.
- Additive-first: add columns/tables, deploy code, then remove old ones later (backfill via a new migration). `scan_checks.detail_json` is versioned with `{"v": 1}` so readers can handle older shapes.
- Rollback: forward-fix (new migration); restore from backup for catastrophic cases.

## 12. Backup and recovery
- **Scope:** the SQLite file (`UNMASK_DATABASE_PATH`) is the only state worth keeping, and even that is short-lived: **reports expire in 24 hours, so a lost database costs at most one day of reports.** Threat indicators are re-downloadable. Configuration is in git; secrets live in the operator's secret store.
- **Method:** `sqlite3 unmask.db ".backup 'backup.db'"` (consistent while running) or snapshot the volume; copy off-host.
- **RPO / RTO:** RPO: up to the backup interval (daily is enough for this data). RTO: minutes: restore the file, run `migrate`, run `update-feeds`.
- **Tests:** restore-test quarterly (see `docs/operations/runbook.md`).

## 13. Performance and scale
- **Workload:** a few scans per second at most; each scan writes about 25 small rows.
- **Index strategy:** `idx_scans_expires_at` (purge), `idx_scans_status_created` (recovery), `idx_threat_indicators_lookup (kind, value)`; the primary keys serve everything else.
- **Growth and triggers:** watch DB size, `SQLITE_BUSY` log lines and queue depth. Scale triggers: second node → PostgreSQL; indicator count above a few million → store indicators in a dedicated lookup structure.

## 14. Data observability
Metrics: `unmask_scans_completed_total{verdict}`, `unmask_scan_duration_seconds`, `unmask_checks_total{check,status}` (watch the `unavailable` rate per check: a spike means a dependency is failing), `unmask_evidence_total{source,outcome}`, `unmask_feed_updates_total{feed,status}`, `unmask_queue_depth`. Alerts (suggested): feed `failed` or `rejected` twice in a row; any check at over 50% `unavailable`; queue depth above 50 for 5 minutes. Owner: the operator. Incident process: `docs/operations/runbook.md`.

## 15. Verification
| Area | Tests |
|---|---|
| Model and constraints | `tests/integration/test_persistence_and_feeds.py` (CHECK, cascade, uniqueness) |
| Migrations | repeatability, checksum tamper detection, "schema current" gate |
| Contract / integration | `tests/contract`, repository round trips, feed refresh and lookup |
| Quality | feed rejection on shrinkage, metadata lines ignored, reference-data validation |
| Recovery | purge and crash recovery; end-to-end "new process over the same database file" test |
| Performance | not automated: see the runbook for a simple load recipe |

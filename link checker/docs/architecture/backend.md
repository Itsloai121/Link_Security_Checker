# Backend architecture decisions (USBA §19)

Answers to the 14 questions the backend architecture asks before implementation, plus the status of its implementation checklist.

1. **Business capabilities as modules.** `link_analysis` (submit links, run the 20 tests, hold reports) and `threat_intel` (download and serve public threat lists). They are separate because they own different data, change for different reasons, and `link_analysis` only needs a narrow question answered ("is any of these on a list?"). Cross-module calls go through `threat_intel`'s public application classes (`LookupIndicators`), never through its tables.
2. **Entry points.** HTTP (JSON API plus the three static pages), a CLI, and in-process workers. No webhooks or message consumers are needed.
3. **Commands and queries.** Commands: `SubmitLinkForAnalysis`, `RunLinkAnalysis`, `DeleteScan`, `PurgeExpiredScans`, `RecoverInterruptedScans`, `RefreshFeeds`. Queries: `GetScanResult`, `ListCheckCatalog`, `LookupIndicators`, `GetFeedStatus`.
4. **Domain entities, rules, consistency boundary.** The `Scan` aggregate (id, status, results) enforces its lifecycle: `queued → running → completed | failed`, results only while running, completion only when all 20 results exist. `ParsedUrl` is a value object; `CheckResult` and `Finding` are immutable. Scoring and the 20 checks are pure domain logic.
5. **Persistence.** SQLite: one writer, many readers, a single deployable. Reports are small and short-lived. See `data.md` and ADR 0002.
6. **Transactions.** One unit of work per repository call (`BEGIN IMMEDIATE … COMMIT`). Replacing a threat feed is one transaction, so readers see the old list or the new one, never a mix. A scan's header and each check result are written separately on purpose: results appear progressively and a crash leaves a recoverable `running` row.
7. **Asynchronous and scheduled work.** Analysis runs in a bounded worker pool fed by an in-process queue (the database row is the durable record). Scheduled: retention purge every 30 minutes, optional feed refresh. Startup recovery re-enqueues `queued` scans and fails abandoned `running` ones with `INTERRUPTED`. Jobs are idempotent: a scan that is no longer `queued` is skipped.
8. **External systems.** Target websites (fetch), DNS, TLS endpoints, RDAP (domain age), Team Cymru DNS (ASN), threat feeds (HTTPS download), optional Google Safe Browsing and URLhaus. All sit behind ports; each has a timeout and failure mapping (`DependencyFailure` → "not verified").
9. **API contracts and compatibility.** Versioned under `/api/v1`. One error shape for every failure. Within v1 only additive changes (new optional fields). `docs/api/openapi.json` is generated and checked in CI so it cannot drift.
10. **Caching.** None, deliberately: no measurements justify it. The only in-memory state is derived and disposable: rate-limit windows and a 5-minute CIDR list loaded from the database.
11. **Workload and targets.** Single node, a few scans per second at most. Latency target: a typical scan completes in 3 to 10 s; hard deadline 45 s. Availability: best effort, with crash-safe recovery.
12. **Observability.** JSON logs with request and scan IDs (never URLs, see `security.md`); Prometheus metrics at `/internal/metrics` (token-protected, off by default); `/health/live` and `/health/ready`.
13. **Tests that prove the critical workflows.** 188 tests: parser and all 20 checks (flag and no-flag cases), scoring and lifecycle, SQLite and migrations, feed safety, the real fetcher against a local server, a real TLS handshake, failure isolation in the collector, end-to-end scans through the HTTP API, API contract, and security regressions (SSRF, headers, CSP, privacy, limits).
14. **One deployable.** Everything stays in one process. Evidence that would justify splitting: sustained queue delay with CPU-bound parsing (split workers), or multiple nodes needing shared state (move SQLite → PostgreSQL and the queue → a broker). See ADR 0001 and 0002.

## Implementation checklist status (USBA §20)

**Before implementation:** [x] capabilities and module boundaries · [x] domain concepts and rules · [x] entry points · [x] API and internal contracts (ports) · [x] persistence and transactions · [x] async and scheduled work · [x] integrations · [x] workload targets

**During implementation:** [x] transport logic out of business rules · [x] focused use cases · [x] domain independent of frameworks and vendors · [x] infrastructure behind interfaces · [x] transaction boundaries · [x] standard errors (`shared/errors`) · [x] idempotent handlers · [x] bounded timeouts, retries (none: failures are reported, not hidden), resources · [x] structured logs and metrics · [x] tests at module boundaries

**Before release:** [x] contract tests · [x] unit, integration, contract, workflow tests · [x] dependency-failure and timeout tests · [x] migrations verified (repeatable, checksummed, tamper-evident) · [x] queue recovery verified (restart test; no dead-letter queue is needed because failures are persisted on the scan row) · [x] health and readiness · [ ] performance review under realistic load (not done: see `docs/operations/runbook.md` for how to measure) · [x] useful metrics

**After release:** monitor latency, errors, queue depth and failed jobs via `/internal/metrics`; re-assess module boundaries as usage grows; record changes as ADRs.

## Error contract

```json
{ "error": { "code": "VALIDATION_FAILED", "message": "…", "request_id": "req_ab12…", "details": [{"field": "url", "issue": "…"}] } }
```

| Code | HTTP | Meaning |
|---|---|---|
| `VALIDATION_FAILED` | 422 | Input rejected (never echoes the input) |
| `SCAN_NOT_FOUND` / `NOT_FOUND` | 404 | Unknown, malformed or expired id (indistinguishable on purpose) |
| `RATE_LIMITED` | 429 | Per-client or per-target-site limit; `Retry-After` set |
| `SERVICE_BUSY` | 503 | Queue full; `Retry-After` set |
| `PAYLOAD_TOO_LARGE` | 413 | Body above `UNMASK_MAX_BODY_BYTES` |
| `METHOD_NOT_ALLOWED` | 405 | |
| `INTERNAL_ERROR` | 500 | Generic message; details only in logs, correlated by `request_id` |

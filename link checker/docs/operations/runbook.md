# Operations runbook

## Health
- Liveness `GET /api/v1/health/live`; readiness `GET /api/v1/health/ready` (database reachable and schema current; shows queue depth).
- Metrics (when `UNMASK_METRICS_TOKEN` is set): `curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/internal/metrics`.
- Logs: JSON on stdout. Every line has `request_id` and `scan_id`. Useful events: `scan_submitted`, `scan_completed`, `scan_failed`, `evidence_source_crashed`, `check_crashed`, `scan_deadline_reached`, `feed_updated`, `scans_purged`, `scans_recovered`.

## Suggested alerts
| Signal | Threshold | Likely cause |
|---|---|---|
| `unmask_checks_total{status="unavailable"}` for one `check` | over 50% for 15 min | a dependency is down or blocked (see below) |
| `unmask_queue_depth` | above 50 for 5 min | workers saturated, or a slow target; raise `WORKER_CONCURRENCY` or investigate |
| `unmask_feed_updates_total{status=~"failed\|rejected"}` | two in a row | feed URL changed, network blocked, or the publisher's list shrank |
| `unmask_http_requests_total{status="500"}` | any sustained | bug: search logs for `unhandled_exception` with the request id |
| `unmask_rate_limited_total` | sudden surge | abuse or a misconfigured client |

## Symptom → cause → action
| Symptom | Cause | Action |
|---|---|---|
| Blocklist test "not verified: no threat feeds downloaded" | first run | `update-feeds` (or `import-feed`) |
| Blocklist test "not verified: … unreachable" | optional provider down or key wrong | check the key; the downloaded feeds still apply |
| Domain-age test "not verified" for some domains | registry has no RDAP data (some country TLDs), or `rdap.org` unreachable | expected for some TLDs; check outbound HTTPS if it is every domain |
| Hosting test lacks network names | Team Cymru DNS lookups blocked | allow outbound DNS (UDP/TCP 53) or set `UNMASK_ENABLE_IP_INTELLIGENCE=false` |
| Most page tests "not verified: could not be opened" | outbound blocked, target blocks scanners, or the link points at a private address | check egress; try the scan from the CLI; the redirect test explains the reason |
| `503 SERVICE_BUSY` | queue full | scale workers or throttle clients; the scan was not stored |
| `429 RATE_LIMITED` | per-client or per-site limit | expected; tune limits if legitimate |
| Start-up: `Database is not ready` | migrations pending | `python -m interfaces.cli migrate` |
| Scans stuck in `running` after a crash | process died mid-scan | restart: they are marked `failed (INTERRUPTED)` automatically |

## Backup and restore
```bash
sqlite3 /var/lib/unmask/unmask.db ".backup '/backups/unmask-$(date +%F).db'"    # safe while running
# restore: stop the app, copy the file back, then
python -m interfaces.cli migrate && python -m interfaces.cli update-feeds && python -m interfaces.cli check-config
```
Reports expire after 24 hours, so a lost database costs at most a day of reports; feeds re-download. Test a restore at least quarterly.

## Measuring load (the one thing the test suite does not do)
Run the demo or a staging instance and submit scans at a steady rate with `examples/api_usage.py` in a loop (respect the rate limits or raise them for the test). Watch `unmask_scan_duration_seconds`, queue depth and CPU. Typical bottleneck: HTML parsing of large pages; first lever is `UNMASK_WORKER_CONCURRENCY`.

## Incident response
1. **Suspected abuse of the scanner** (outbound traffic to a victim, or SSRF attempt): look for `scan_submitted` bursts by `target` host; tighten `PER_HOST_SCANS_PER_MINUTE`, set `UNMASK_QUEUE_SIZE=1` or stop the service; block the source at the proxy.
2. **Suspected SSRF success** (should be impossible): check egress logs for private-range connections from the host; stop the service, preserve logs, rotate any credentials reachable from the host (cloud metadata roles first), review `network_policy.py` and the proxy, then report privately (see `CONTRIBUTING.md`).
3. **Leaked API key or token:** revoke at the provider, set a new value, restart; search logs for use of the old one.
4. **Poisoned or bad feed data (false positives):** `update-feeds --status`, disable the feed in `UNMASK_ENABLED_FEEDS`, delete its rows (`DELETE FROM threat_indicators WHERE source='…'`), restart.
5. **After any incident:** record what happened and what changed; update the threat model (`docs/architecture/security.md`).

## Routine
Monthly: update dependencies (`pip-audit`, regenerate the lock files, run the tests). Quarterly: review brand and word lists, review rate limits against real traffic, test a restore, review accepted risks in the security profile.

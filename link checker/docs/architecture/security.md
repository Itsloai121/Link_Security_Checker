# Project security profile (USSA §8)

Threat model date: 2026-11-22 · Scope: the web app, API, CLI, workers and their outbound connections.

## 1. Assets and data

| Asset | Sensitivity | Why it matters |
|---|---|---|
| Submitted links and optional label | Confidential | May contain reset tokens, session ids, email addresses |
| Scan reports (findings, evidence) | Confidential | Quote text from analysed pages |
| The scanner's network position | **High** | Anything the server can reach, an attacker would like to reach *through* it (SSRF) |
| Optional API keys (Safe Browsing, URLhaus), metrics token | Restricted | Spend, quota, operational data |
| Threat-feed data | Public, integrity-sensitive | A poisoned feed could hide or invent detections |
| Reference data (brands, lists) | Internal, integrity-sensitive | Same: tampering weakens detection |
| Availability of the service | Medium | A public utility that can be exhausted |
| Source code and dependencies | High | Supply chain |

Not held: passwords, accounts, payment data, uploaded files, downloaded malware, page bodies.

## 2. Identities and access

- **Anyone** can submit a link and read *their own* report. There are no accounts (ADR 0006).
- A report is readable and deletable by whoever holds its 128-bit id; there is no listing endpoint; unknown/malformed/expired ids are indistinguishable (404).
- **Operator** (deployer): controls configuration through environment variables, runs migrations and feed updates through the CLI on the host. There is deliberately **no admin web interface**. The only privileged HTTP endpoint, `/internal/metrics`, is off unless a bearer token is configured and is compared in constant time.
- **Workers/scheduler** run in-process with the app's permissions; they hold no extra credentials.
- Actions needing extra approval: none exposed over HTTP.

## 3. Trust boundaries and attack surfaces

| # | Boundary | Untrusted data entering | Controls |
|---|---|---|---|
| B1 | Internet → API/pages | the link, label, headers, request size and rate | validation, body limit, rate limits, strict CSP, error contract |
| B2 | Server → analysed websites | **everything**: headers, redirects, HTML, scripts, certificates | guarded client (SSRF policy), size/time caps, parse-only (never execute), sniff first bytes only |
| B3 | Server → DNS / RDAP / Team Cymru | answers | timeouts, https-only redirects for RDAP, input pattern check before building a URL, errors become "not verified" |
| B4 | Server → threat feeds / reference files | list content | https only, size cap, parse and reconcile, reject shrinkage, schema-validated files |
| B5 | Browser (our UI) ← report data | page titles, form targets, evidence strings (attacker-written) | `textContent` only, no inline script/style, CSP without `unsafe-*`, invisible/bidi characters made visible |
| B6 | Operator → host | configuration, secrets | typed settings, secrets in env, refuse unsafe production values |
| B7 | Build → release | dependencies, CI | pinned lock files, `pip-audit`, `bandit`, tests |

Privileged operations: migrations and feed refresh (CLI/host only); nothing privileged is reachable from B1.

## 4. Threats and risks (STRIDE)

| ID | Threat | Entry | Controls | Verified by | Residual |
|---|---|---|---|---|---|
| S1 | A report impersonating another (id guessing) | `GET /scans/{id}` | 128-bit CSPRNG ids, uniform 404, no listing | `test_scan_ids_are_unguessable…`, contract 404 tests | Low: whoever is *given* the link has access (by design) |
| S2 | Phishing page disguises itself from the scanner (cloaking) | B2 | second fetch with a browser identity, content comparison, evasion-code detection | `test_page_that_hides_from_scanners…` | Medium: a well-made kit may still evade; reported as limitation |
| T1 | **SSRF**: link targets `127.0.0.1`, `169.254.169.254`, internal names, IPv6 mapped/NAT64, decimal/hex IPs | B2 | resolve-then-pin, refuse if *any* answer is non-public, port allow-list, per-hop re-check, redirects never auto-followed, production refuses `ALLOW_PRIVATE_NETWORKS` | `tests/security`: 7 internal targets never reach the server; rebinding test; policy unit tests (15 address families) | Low. Add network egress rules as defence in depth (below) |
| T2 | Redirect chain bounces into private space | B2 | every hop validated by the same client | redirect tests + SSRF e2e | Low |
| T3 | Tampered or poisoned threat feed | B4 | https only, size cap, reconcile (reject <20% of previous), licence-aware catalogue | feed tests | Medium: trust in the feed publisher remains |
| T4 | Tampered reference data/migrations | B6 | schema validation at start-up; migration checksums | loader and migrator tests | Low (file system access = already compromised) |
| T5 | Parser differential: link reads differently in browsers and tools (`\@`, `%2e`, numeric IPs, tabs) | B1 | browser-faithful (WHATWG) parser; flags for every quirk | 30 parser tests | Medium: new quirks appear over time |
| R1 | Operator cannot reconstruct what happened | all | request id in every response/log; security-relevant events logged | contract test (id in header and body) | Low |
| I1 | Submitted links leak through logs or metrics | logs | log host only (`redact_url`), no paths/queries/credentials/client IPs; secrets are `SecretStr` | `test_submitted_paths_queries_and_credentials_never_reach_the_logs` | Low |
| I2 | Report data leaks via cache/sharing | responses | `Cache-Control: no-store` on API; `no-referrer`; reports expire in 24 h; delete button | header tests | Low |
| I3 | Stack traces / internals in errors | API | one generic message; details only in logs | contract tests assert no traceback | Low |
| I4 | Optional integrations disclose links to a third party | B3 | off by default; documented; key never logged or put in error text | design review, unit tests | Accepted when enabled |
| D1 | Resource exhaustion: huge bodies, decompression bombs, slow servers, deep HTML | B2 | 1.5 MB HTML cap, 4 KB for non-HTML, bounded gzip decode, connect/read/total timeouts, 45 s scan deadline, hop limit, safe parse fallback for hostile markup | fetcher and snapshot tests | Low |
| D2 | API flooding | B1 | per-client and per-target rate limits, bounded queue (503), bounded limiter memory, 8 KB body cap | `tests/security` limits | Medium: per-IP limits do not stop a large botnet; use a CDN/WAF if exposed widely |
| D3 | Using the scanner to hammer a victim site | B2 | per-registrable-domain limit (6/min), identifiable scanner user-agent | `test_one_victim_site_cannot_be_hammered…` | Medium |
| D4 | ReDoS in our regexes | B1/B2 | inputs length-bounded before matching (URL ≤ 2048, text ≤ 8000 chars, scripts ≤ 6000 chars each) | review; bounded fixtures | Low |
| E1 | Attacker script runs in a viewer's browser via report data (XSS) | B5 | `textContent` only; CSP `script-src 'self'` with no unsafe-inline/eval; test forbids `innerHTML` etc. in all JS | `test_javascript_never_renders…`, header/CSP tests, browser run with zero CSP violations | Low |
| E2 | Clickjacking / UI redress of our own pages | B1 | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | header tests | Low |
| E3 | Display spoofing in our UI with bidi/zero-width characters in a submitted link | B5 | invisible and bidirectional control characters are shown as `⟦U+202E⟧` markers | `safe-text` test | Low |
| E4 | Command execution via analysed content | B2 | content is parsed, never executed; nothing written to disk; no subprocesses | architecture (ADR 0005) | Low |
| E5 | Dependency compromise | B7 | lock files, `pip-audit` + `bandit` in CI, small dependency set | CI | Medium (any supply chain) |

## 5. Security controls: USSA pillars

| Pillar | Applies? | Implementation | Owner |
|---|---|---|---|
| 01 Identity and authentication | Minimal | No accounts. Bearer token for metrics only | Operator |
| 02 Authorization and access control | Yes | Capability ids; no listing; no admin HTTP surface; server-side checks in use cases | Maintainer |
| 03 Input validation and output protection | **Core** | Pydantic schemas (`extra=forbid`, length limits), NUL rejection, browser-faithful parser, output via `textContent`, JSON only | Maintainer |
| 04 API and communication security | Yes | Versioned API, uniform errors, body limit, rate limits, same-origin only (no CORS), HTTPS via reverse proxy + HSTS option | Maintainer/Operator |
| 05 Data storage security | Yes | Parameterised SQL only, constraints, `0700` data dir, retention, app never runs DDL | Maintainer |
| 06 Encryption and cryptography | Limited | TLS verification on all outbound HTTPS; CSPRNG ids; no custom crypto; at-rest encryption is the host/volume's job | Operator |
| 07 Application and business-logic security | Yes | State machine on `Scan`, idempotent jobs, abuse limits, per-target throttle | Maintainer |
| 08 Client-side and interface security | **Core** | Strict CSP, no inline script/style, security headers, `textContent`, self-hosted fonts, no third-party requests, accessible controls | Maintainer |
| 09 Network and infrastructure security | **Core** | SSRF policy (see T1), port allow-list, container hardening (non-root, read-only FS, dropped capabilities), recommended egress rules | Maintainer/Operator |
| 10 Secrets management | Yes | Environment only, `SecretStr`, never logged, `.env` git-ignored, secret-file check in CI | Operator |
| 11 Logging, monitoring, detection | Yes | JSON logs with request/scan ids, redaction, metrics, health | Operator |
| 12 File and data handling security | **Core** | Hostile content handling: size caps, magic-byte sniffing, no execution, no storage, safe parser fallback | Maintainer |
| 13 Backup, resilience, disaster recovery | Light | Short-lived data; backup recipe; crash recovery | Operator |
| 14 Secure development and supply chain | Yes | Pinned locks, lint with security rules (ruff `S`), `bandit`, `pip-audit`, PR checklist, 188 tests | Maintainer |
| 15 Incident response and recovery | Yes | `docs/operations/runbook.md`: containment switches, rotation, recovery | Operator |

**Recommended deployment hardening (defence in depth for T1):** run the container on a network that allows outbound only to the public internet on ports 53, 80, 443, 8080, 8443 and **denies** RFC 1918, link-local (169.254.0.0/16 including cloud metadata), loopback and ULA ranges at the network layer. Where the cloud provider supports it, require IMDSv2/metadata hop limit 1.

**Behaviours worth knowing:**
- The "scanner" view identifies itself (`UnmaskLinkScanner/1.0`). The "browser" view deliberately sends a common browser user-agent: that is how cloaking is detected.
- With the default settings, a link's *host name* is sent to your DNS resolver, to `rdap.org` and the registry (domain age), and the destination server's *IP address* to Team Cymru (ASN). Switch off with `UNMASK_ENABLE_REGISTRATION_LOOKUP=false` / `UNMASK_ENABLE_IP_INTELLIGENCE=false`.
- Google Safe Browsing and URLhaus, when enabled, receive the full URLs being checked.

## 6. Verification

Evidence is in `tests/` (run `scripts/test.ps1`): `tests/security/test_security.py` (SSRF, rate limits, headers, CSP-compatibility of the HTML, no-`innerHTML` in JS, privacy of logs, metrics protection, static-file traversal), `tests/unit/test_infrastructure_units.py` (address policy, redaction, settings guards), `tests/contract` (error contract, no leaks), plus a headless-browser run of the whole flow that produced no console or CSP errors. Findings that must be fixed before release: any failing test above; any critical `pip-audit` or `bandit -ll` finding.

## 7. Operations and response

- **Monitor:** `unmask_rate_limited_total`, `unmask_evidence_total{outcome="error"}`, `unmask_check_failures_total`, queue depth, feed update failures, 5xx rate.
- **Respond:** see the runbook. Containment options without redeploying: set `UNMASK_QUEUE_SIZE=1` (throttle), stop the container, or block at the reverse proxy; `UNMASK_ENABLE_CLOAKING_PROBE=false` halves outbound traffic.
- **Revoke credentials:** rotate `UNMASK_GSB_API_KEY`, `UNMASK_URLHAUS_AUTH_KEY`, `UNMASK_METRICS_TOKEN` at the provider/host and restart.
- **Recover data:** restore the database file, `migrate`, `update-feeds`.

## 8. Residual risk

| Risk | Why it remains | Owner | Review |
|---|---|---|---|
| Detection is heuristic; a well-crafted new attack can score low | No tool can prove safety. Mitigated by honest wording, "not verified" states and the limits page | Maintainer | each release |
| JavaScript-built pages are only partly visible | ADR 0005 | Maintainer | when adding a sandboxed renderer |
| Per-IP rate limits are weak against distributed abuse | In-memory limiter, single node | Operator | before public launch: add CDN/WAF |
| Trust in third-party feeds and registries | Data comes from outside | Maintainer | quarterly |
| Anyone with a report URL can read it | Capability model | Product owner | if accounts are added |
| Performance under real load not measured | No benchmark in the suite | Operator | before production |

## Release gates (USSA §6) status

**Gate 1 before development:** [x] assets · [x] classification · [x] boundaries · [x] threat model · [x] authn/authz requirements · [x] acceptance criteria (the tests).
**Gate 2 during development:** [x] server-side authorization (capability ids) · [x] input validation and output protection · [x] secure data access · [x] secrets outside code · [x] safe errors and security logging.
**Gate 3 before staging:** [x] static analysis (ruff `S` rules, `bandit` in CI) · [x] dependency scan (`pip-audit` in CI) · [x] secret scan (CI check) · [x] API tests · [x] data-store permissions reviewed · [ ] container scan (run Trivy/Grype on your built image).
**Gate 4 before production:** [x] requirements tested, results recorded in CI · [ ] production secrets configured by the operator · [ ] logging/alerting wired to your platform · [ ] backup restore tested by the operator · [x] incident and rollback notes (runbook) · [ ] release approval by the owner.
**Gate 5 after production:** monitor, patch dependencies monthly, review access and limits, re-run this threat model when features or boundaries change.

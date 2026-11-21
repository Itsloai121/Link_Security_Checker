# Security architecture

## Assets and classification

- Report bearer token: Restricted. It grants access to a report and is never stored in plaintext or logged.
- Hostname and findings: Confidential. They can reveal a user's browsing intent; retention is bounded.
- Submitted URL: potentially sensitive because path/query may carry account identifiers or one-time tokens. It is processed in memory only and is neither persisted nor logged. The destination and PhishTank receive the exact URL during their respective checks.
- Database and backups: Confidential/Restricted according to contents; runtime file is private and Git-ignored.
- Reputation provider credentials: `PHISHTANK_APP_KEY` is optional and no key is committed. Production keys belong in a deployment secret manager.

## Controls in the current backend

- Secure defaults: loopback binding in development, no CORS, no cookie auth, no forwarding-header trust. Live outbound checks accept only HTTP/HTTPS on ports 80/443 and public IP addresses. IPv4-mapped IPv6, 6to4, Teredo, and NAT64 addresses that embed non-public IPv4 destinations are rejected.
- Request boundary: JSON only, body cap, URL length cap, server-side URL parsing, strict static asset allowlist, method checks, bounded timeouts, and per-socket-IP rate limit.
- HTTP headers: CSP, frame denial, no-referrer, MIME sniffing disabled, restrictive permissions policy, same-origin resource policy; HSTS is emitted only in production, which assumes HTTPS termination.
- Persistence: prepared statements, SQLite defensive mode, foreign keys, transaction boundary, data retention, report-token hashing, constant-time token comparison. On POSIX, the database and SQLite sidecars are restricted to owner-only mode (0600), and the process uses a restrictive umask. The local SQLite file is not application-encrypted; production requires encrypted storage/volume and protected backups.
- Destination fetch: DNS answers must all be public; each connection pins to a resolved address. Redirects are revalidated at each hop (maximum five), response headers/body are capped, requests have short deadlines, and no page script, cookie, or authentication is sent or executed.
- Third-party lookups: domain/IP metadata is sent to IANA/RIR RDAP and Team Cymru. The original URL is sent to PhishTank for phishing reputation checks.
- Errors/logging: stable error codes and request IDs; logs contain route label, method, duration, status, error type, and request ID. No URL, body, token, client IP, or query string is logged.
- Web UI boundary: server-authoritative analysis; report access is capability-based and requires the bearer token on retrieval.

## Threat model (initial STRIDE pass)

| Threat | Example | Current control | Residual risk |
|---|---|---|---|
| Spoofing | Guessing or stealing report access | 256-bit random token, SHA-256 digest, bearer required | Whoever receives the token can read the report |
| Tampering | Malformed URL or SQL injection | Type/length validation, prepared statements, DB constraints | Analyzer heuristics need regression review as they evolve |
| Repudiation | Denying report creation | Server request IDs and timestamp, privacy-minimized log | No durable audit store or account identity |
| Information disclosure | URL query/token appears in DB/logs | Raw URL not persisted/logged; access token hash only | URL is present in request memory and API response while needed |
| Denial of service | Oversized or repeated requests | Request/time limits, byte cap, in-process rate limit | Single-process limiter is bypassable across instances and can be evicted on restart |
| Elevation of privilege | Read another scan report | Token check on every report read; no client-side authorization | No account roles/admin surface exists yet |
| SSRF | Submitted URL reaches private network | Reject non-public DNS answers, pin the validated IP, restrict scheme/port, revalidate redirects, cap bytes and time | No OS-level egress firewall; a compromised dependency/process still has the host network permissions |

## Explicitly not implemented

No user accounts, MFA, tenant authorization, metrics exporter, centralized logging, production backup, or restore testing is present. PhishTank lookups can be rate-limited or unavailable, especially without a registered application key. Page checks inspect a bounded HTML response only; they do not run JavaScript or render a browser DOM, and the heuristics can miss behavior. The in-process SSRF controls are an application guard, not an egress firewall. Production inspection requires a separately isolated worker, strict network egress rules, and an updated threat model.

## Release gates before public production

1. Define users, ownership, authentication, report sharing, and privacy/retention policy.
2. Add shared edge rate limiting, TLS, DDoS protection, and deployment hardening.
3. Select production relational storage; define least-privilege runtime/migration identities.
4. Configure secrets management, backup encryption, RPO/RTO, tested restore, and incident response.
5. Run security analysis, dependency review, API abuse testing, authorization tests, and an independent remote-inspection threat model before public deployment.
6. Add actionable monitoring/alerts and vulnerability response ownership.

This document is a project-specific starting point based on the supplied USSA reference. It is not a certification or production security approval.


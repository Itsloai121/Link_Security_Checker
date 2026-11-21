# Python backend architecture

## Runtime shape

The backend is a small Python modular monolith. `server.py` is the process entry point; `backend/link_safety/` contains the HTTP adapter, configuration, URL analysis, remote-inspection policy, and SQLite repository. The bundled browser interface remains HTML, CSS, and JavaScript under `public/`.

## Modules and responsibilities

- `server.py`: applies a restrictive POSIX umask and starts Uvicorn with proxy-header trust and access logging disabled.
- `backend/link_safety/api.py`: FastAPI routes, JSON validation, request-size limits, rate limiting, response security headers, report authorization, and the compatibility contract used by the current GUI.
- `backend/link_safety/config.py`: parses `.env` without shell expansion, applies process-environment precedence, and validates runtime settings.
- `backend/link_safety/url_analysis.py`: URL parsing/normalization, static signals, and final score/verdict calculation.
- `backend/link_safety/live_checks.py`: bounded RDAP/ASN, PhishTank, TLS, redirect, and static HTML checks.
- `backend/link_safety/network.py`: public DNS resolution, address-pinned HTTP(S) connections, redirect handling, and outbound request limits.
- `backend/link_safety/ip_policy.py`: shared public-address classification, including IPv4-mapped IPv6 and transition-address handling.
- `backend/link_safety/database.py`: SQLite connection policy, ordered migrations, transactions, report-token hashing, and report retention.
- `backend/link_safety/errors.py`: stable application and outbound-inspection error types.
- `migrations/`: ordered SQL schema migrations.
- `tests/test_python_backend.py`: URL, network, database, configuration, HTML-inspection, rate-limit, and API contract tests.

## Request lifecycle

1. The HTTP middleware assigns a request ID, enforces the accepted Host names and per-process API limit, and adds response security headers.
2. The API checks the content type, bounds the request body, rejects duplicate JSON keys/non-standard constants, and validates the submitted URL.
3. Static URL analysis runs before any outbound inspection.
4. Live checks use HTTP(S) only, standard ports only, public DNS answers only, pinned destination IPs, redirect revalidation, bounded response sizes, and time limits. Remote page scripts are never executed.
5. Report metadata and check rows are written atomically to SQLite. The raw URL path/query/fragment are not persisted; the one-time bearer token is hashed before storage.
6. The legacy `/api/analyze` route retains the response shape used by the existing GUI. Versioned report retrieval requires the bearer token.

## Persistence and concurrency

SQLite is the current single-process store. The schema and migration history are kept unchanged for compatibility with the existing local database. On POSIX, database and SQLite sidecar files are restricted to owner-only permissions; `server.py` sets a restrictive process umask before startup. The in-process rate limiter and SQLite file are not intended for multiple application replicas.

## Deployment boundary

Application-level DNS checks and address pinning reduce SSRF risk but do not replace an OS/container egress firewall. Before public deployment, remote URL inspection should run in a separately isolated worker with network egress rules that deny private, loopback, link-local, metadata, and internal destinations. Configure TLS ingress, edge rate limiting, encrypted backups, monitoring, and independent security review before production use.

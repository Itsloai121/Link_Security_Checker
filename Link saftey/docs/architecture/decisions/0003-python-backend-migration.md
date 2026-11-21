# ADR 0003: Python backend migration

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

The project needs a maintainable backend for URL analysis, bounded remote inspection, report access, and SQLite persistence. The frontend is already a standalone HTML/CSS/JavaScript client, so it can stay unchanged while the server moves to Python.

## Decision

Replace the active Node.js backend with Python 3.13+, FastAPI, Uvicorn, dnspython, and a public-suffix list. Keep a modular monolith with separate URL analysis, outbound network policy, live checks, HTTP adapter, and SQLite repository. Preserve the current `/api/analyze`, `/api/v1/scans`, report token, health endpoints, migration files, and SQLite table layout. Keep a copy of the former Node backend under `archive/node-backend-before-python/` for reference.

## Security choices

- Parse and normalize URLs before inspection; accept only HTTP/HTTPS, standard ports, and public website hostnames.
- Resolve A and AAAA records, reject the host if any resolved address is non-public, and open sockets directly to a validated IP while preserving HTTPS hostname validation.
- Reapply those checks at every redirect, with response byte, wall-clock, hop, and concurrent scan limits.
- Avoid proxy environment variables, forwarding-header trust, CORS, remote scripts, cookies, and destination credentials.
- Keep URL paths and queries out of SQLite and logs; hash the one-time report token and compare its digest in constant time.
- Keep SQLite migrations and schema stable so existing reports remain available.

## Consequences

- Start with `uv sync --locked` and `uv run python server.py`.
- The bundled browser interface still uses JavaScript; only the backend and its security/data code move to Python.
- SQLite and the in-memory rate limiter remain single-process choices.
- Application-level SSRF controls still need an OS-enforced network egress boundary before public deployment.
- The archived Node code is historical and is not loaded by the current application.

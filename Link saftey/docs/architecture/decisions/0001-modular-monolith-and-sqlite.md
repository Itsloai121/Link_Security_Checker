# ADR 0001: Modular monolith and SQLite starting point

- **Status:** Runtime choice superseded by [ADR 0003](0003-python-backend-migration.md); modular-monolith and SQLite decisions remain in effect.
- **Date:** 2026-11-20

## Context

The project needs URL-analysis APIs, persistent report records, and a backend foundation. It is currently a single-user/local prototype with no account model, provider keys, or declared traffic/availability target. The existing analyzer performs local URL parsing and makes no network requests.

## Decision

Use one Node.js modular monolith with explicit API, application, domain, port, and infrastructure boundaries. Use one SQLite database as the initial authoritative store, ordered SQL migrations, and a short transaction for each scan and its checks. Keep static analysis isolated from persistence. Store only host/scheme/report findings and a digest of a random report credential; do not store the submitted URL or log client address. Expire reports after a configurable period.

## Alternatives considered

- **PostgreSQL immediately:** more suitable for multi-instance production, but requires a managed database and operational configuration not yet provided.
- **JSON files:** simpler but lacks relational constraints, atomic multi-row writes, and reliable migrations.
- **Microservices, queue, cache:** premature because scans are synchronous local computation and there are no remote checks to isolate yet.

## Consequences

- Local startup has no third-party npm dependencies.
- SQLite's synchronous API and single-file deployment limit throughput and horizontal scaling.
- Node documents `node:sqlite` as a release candidate in current Node 26 documentation; keep the adapter behind a repository boundary and consider a maintained PostgreSQL driver before production ([Node SQLite docs](https://nodejs.org/api/sqlite.html)).
- The in-process limiter is not shared between replicas.
- Production readiness requires a storage migration or proven single-node operating model, backups, recovery targets, monitoring, TLS, and a separate threat-model review before public live scanning.


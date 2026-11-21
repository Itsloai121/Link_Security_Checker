# Changelog

## 0.3.0 — Python backend migration and hardening

- Replaced the active Node.js server with a Python 3.13+, FastAPI, and Uvicorn backend while preserving the browser GUI contract.
- Preserved the SQLite schema, migration history, existing local reports, and token-protected versioned report API.
- Added public-only DNS validation, pinned outbound sockets, redirect revalidation, bounded outbound requests, URL normalization, and safer HTML inspection.
- Added owner-only POSIX SQLite file permissions, isolated environment parsing, JSON duplicate-key rejection, and regression tests for API, database, and network policy.
- Archived the previous Node backend under `archive/node-backend-before-python/`.


## 0.2.0 — Backend foundation

- Added modular API/application/domain/persistence boundaries.
- Added SQLite migrations, scan/check schema, bounded report retention, and token-protected report retrieval.
- Added request validation, request/body limits, rate limiting, security headers, structured privacy-minimized logs, and health checks.
- Kept `/api/analyze` for the existing GUI and added the versioned `/api/v1/scans` contract.
- Moved the seven supplied design inputs into `project engineering ideas/`.
- Documented the project-specific architecture, data lifecycle, threat model, API, and operations.

## 0.1.0 — UI MVP

- Initial landing, link scan, and analysis views with static URL checks.

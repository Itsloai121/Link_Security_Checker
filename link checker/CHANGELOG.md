# Changelog

All notable changes to this project are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/), versioning: [SemVer](https://semver.org/).

## [1.0.0] - 2026-11-22

### Added
- Link analysis engine with the 20 tests from the project brief: blocklists, look-alike domains, homograph/punycode, redirect unwrapping, open redirects, `@` masking, subdomain spoofing, URL obfuscation, dangerous schemes, domain age, TLS, hosting/ASN, port and path anomalies, credential forms, form-action mismatch, brand and urgency clues, hidden elements and overlays, auto-downloads, cloaking, and label-versus-destination mismatch.
- Browser-faithful URL parser (WHATWG rules): backslashes, decimal/hex/octal IPs, percent-encoded hosts, IDNA, userinfo.
- SSRF-guarded outbound HTTP client (validated-IP pinning, port allow-list, per-hop re-validation, bounded reads).
- Three-page web GUI (index, process, analysis) with the requested visual language and effects; pause-animations switch; `prefers-reduced-motion` support.
- REST API v1 (`/api/v1/scans`, `/api/v1/checks`, health endpoints), error contract, rate limiting, request IDs, strict CSP and security headers.
- Threat-feed ingestion (OpenPhish community feed, Spamhaus DROP/ASN-DROP) with shrinkage rejection; optional Google Safe Browsing and URLhaus providers.
- SQLite storage with versioned, checksummed migrations; 24-hour retention; crash recovery of interrupted scans.
- CLI: `serve`, `migrate`, `scan`, `update-feeds`, `import-feed`, `purge`, `check-config`.
- Demo mode with a local fixture "internet" for offline exploration.
- 188 automated tests (unit, integration, contract, end-to-end, security).

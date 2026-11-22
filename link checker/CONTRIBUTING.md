# Contributing

## Ground rules
1. Follow the structure in `docs/architecture/overview.md`: business rules live in `src/modules/<module>/domain`, I/O lives behind ports in `infrastructure`, entry points live in `src/interfaces`. A check never performs I/O: it reads evidence and returns findings.
2. Every change comes with tests. `scripts/test.ps1` (Windows) or `scripts/test.sh` runs lint, schema checks and the whole suite. The suite must stay green and offline.
3. A new check needs a case that must be flagged **and** a case that must not be (false positives destroy trust). See `docs/development/adding-a-check.md`.
4. Never log or store more than needed: no full URLs, queries or credentials in logs (`shared/utilities/redaction.py`).
5. Anything that fetches a URL must go through `infrastructure/external_services/guarded_http.py`. Do not import `httpx`, `requests` or `urllib.request` in `src/`.
6. Record significant decisions as a short ADR in `docs/architecture/decisions/`.

## Reporting a vulnerability
Please do not open a public issue for a security problem. Contact the maintainer privately, include steps to reproduce, and allow reasonable time for a fix before disclosure.

## Pull requests
Use the checklist in `.github/PULL_REQUEST_TEMPLATE.md`. Keep changes focused; update `CHANGELOG.md` for user-visible changes.

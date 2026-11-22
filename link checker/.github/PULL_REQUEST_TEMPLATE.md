## What and why


## Checklist (from the backend, data and security architecture files)
- [ ] Business rules stay in `domain/`; I/O stays behind ports; no framework imports in the domain
- [ ] New or changed behaviour has tests, including a failure/timeout case
- [ ] New check: has a "must flag" and a "must not flag" test, an explanation, and is registered in `domain/checks/catalog.py`
- [ ] Schema change: new numbered file in `migrations/` (never edit an applied one) and the data spec (`docs/architecture/data.md`) is updated
- [ ] Outbound requests use the guarded client; untrusted text is rendered with `textContent` only
- [ ] No secrets, real URLs or personal data in code, fixtures, logs or test output
- [ ] `scripts/test.ps1` / `scripts/test.sh` passes; `CHANGELOG.md` updated if user-visible

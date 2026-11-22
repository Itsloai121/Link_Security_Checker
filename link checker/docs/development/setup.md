# Development setup

**Needs:** Python 3.11 or newer (developed and tested on 3.12), and nothing else: no database server, no Node.js, no build step for the web UI.

## Windows (PowerShell)

```powershell
.\scripts\setup.ps1        # virtualenv, pinned dependencies, .env, database schema
.\scripts\run.ps1          # http://127.0.0.1:8000
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.lock   # once, for tests
.\scripts\test.ps1         # lint + schema checks + all tests
```
If PowerShell blocks the scripts: `Set-ExecutionPolicy -Scope Process Bypass`.

## macOS / Linux

```bash
./scripts/setup.sh && ./scripts/run.sh
.venv/bin/pip install -r requirements-dev.lock && ./scripts/test.sh
```

## Try it without internet: demo mode

```powershell
.\.venv\Scripts\python.exe scripts\demo_server.py     # then open http://127.0.0.1:8765
```
It runs the real app against a local fixture "internet" and prints ready-made links (a phishing-style page, a short link with a redirect chain, an open redirect on a "trusted" site, an `invoice.pdf` that is really a program, a page that hides from scanners). DNS, domain-age, TLS and blocklist answers are simulated there; everything else is real.

## Try it from the terminal

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m interfaces.cli scan "https://paypa1-login.example/signin" --details
.\.venv\Scripts\python.exe -m interfaces.cli import-feed openphish data\seeds\dev_threat_feed.txt   # offline blocklist hit
```
Safe practice links are in `data/samples/sample_links.txt`.

## Everyday commands

| Task | Command (`PYTHONPATH=src`, from the repo root) |
|---|---|
| Create/upgrade the database | `python -m interfaces.cli migrate` |
| Validate configuration | `python -m interfaces.cli check-config` |
| Download threat feeds | `python -m interfaces.cli update-feeds` (`--status` to inspect) |
| Delete expired reports | `python -m interfaces.cli purge` |
| Regenerate schemas / OpenAPI | `python scripts/export_schemas.py` · `python scripts/export_openapi.py` |
| One test file | `python -m pytest tests/unit/test_checks.py -q` |

`pyproject.toml` already puts `src` and the repo root on pytest's path. VS Code: open the folder; `.vscode/settings.json` selects the virtualenv and maps the JSON schemas, so editing `config/defaults/reference/*.json` gives you completion and validation.

## Where things live

Start with `docs/architecture/overview.md`. In short: rules in `src/modules/*/domain`, workflows in `application`, anything that touches the outside world in `infrastructure` behind a port, HTTP in `src/interfaces/api`, the UI in `src/interfaces/web`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Database is not ready (pending migrations …)` | Run `python -m interfaces.cli migrate` (or set `UNMASK_AUTO_MIGRATE=true` for development). |
| `ModuleNotFoundError: bootstrap` | `PYTHONPATH` must be `src` (the scripts set it). |
| Many tests show "Not verified" | The server cannot reach the internet or DNS, or a lookup service is down. Check `docs/operations/runbook.md`. |
| Blocklist test "No threat feeds have been downloaded yet" | Run `update-feeds`, or `import-feed` with a local file. |
| `ValidationError` at start-up | A setting is invalid; the message names it. `UNMASK_ALLOW_PRIVATE_NETWORKS` cannot be true in production. |

# Local development setup

## Requirements

- Python 3.13 or newer.
- `uv` for dependency installation and the isolated Python environment.
- PowerShell on Windows, or a shell with `uv` on PATH.

## Run locally

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
uv sync --locked
uv run python server.py
```

Open <http://127.0.0.1:3000>. The server binds to loopback by default. Stop it with Ctrl+C. Python manages the SQLite connection lifecycle and handles normal shutdown.

## Verify

```powershell
uv run python -m unittest discover -s tests -p "test_*.py" -v
```

The unittest suite checks URL validation, public-IP/SSRF policy, redirects, HTML inspection, configuration, SQLite permissions/migrations/token handling, rate limiting, and API contracts. Outbound network calls are mocked in tests. It does not replace security review or penetration testing.

## Environment settings

Settings come from the process environment and the simple `.env` file. Values in the process environment take precedence. Do not commit `.env` or production credentials.

- `NODE_ENV`: `development`, `test`, or `production`. This legacy name is kept so existing local configuration keeps working.
- `PORT`: TCP port, default `3000`.
- `BIND_ADDRESS`: bind interface, default `127.0.0.1`. Only expose `0.0.0.0` behind a secured production ingress.
- `ALLOWED_HOSTS`: explicit comma-separated HTTP Host names; wildcards are rejected.
- `DATABASE_PATH`: SQLite file or `:memory:`, default `./var/link-safety.sqlite`.
- `MAX_BODY_BYTES`, `MAX_URL_LENGTH`: API request limits.
- `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX_REQUESTS`: per-process request limit.
- `MAX_CONCURRENT_SCANS`: active scan limit per process.
- `DATA_RETENTION_DAYS`: report retention, 1 to 3650 days.
- `PHISHTANK_APP_KEY`: optional provider key. The exact submitted URL is sent to PhishTank during each uncached lookup; a key may increase the provider's rate limit. See [PhishTank API information](https://www.phishtank.org/api_info.php).

## Network and privacy boundary

Live checks make bounded DNS, registry, TLS, redirect, reputation, and page requests. The app does not execute remote JavaScript. Do not submit links containing private tokens. The exact submitted URL goes to PhishTank when configured/available, and the destination receives an HTTP request during page inspection.

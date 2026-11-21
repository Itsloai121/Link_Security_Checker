# Operations runbook

## Start and stop

From the project root, run `uv run python server.py`. Stop with Ctrl+C. The app binds to `127.0.0.1:3000` by default, writes compact privacy-minimized logs, and closes normally on shutdown.

## Health checks

- `GET /health/live`: process is accepting HTTP requests.
- `GET /health/ready`: SQLite answered a small query. The response does not reveal database paths or errors.

## Database and retention

SQLite is stored at `var/link-safety.sqlite` by default. On POSIX, the application restricts the database and any SQLite `-wal`/`-shm` sidecars to owner-only mode (0600); the Python server starts with a restrictive umask. WAL mode may create `-wal` and `-shm` files. Stop the app before making a manual copy; do not copy only the main file while WAL is active. The app applies ordered migrations on startup and deletes reports older than `DATA_RETENTION_DAYS` (30 by default) at startup and every six hours. Do not commit or serve `var/`.

If migration fails, preserve the database and record the migration name and error type. Restore from a known-good backup or apply a reviewed forward migration; do not delete the database as a first response.

## Common responses

- `400`: request validation failed.
- `401`: report token was missing or invalid.
- `413`: request body exceeded the size limit.
- `415`: request was not JSON.
- `429`: local per-process request quota was reached. Public hosting needs edge rate limiting and abuse monitoring.
- `pending`: the check could not start or is not configured.
- `blocked`: an outbound safety policy prevented the request.
- `error`: the provider or network did not return usable data.

Unavailable checks are not clean results.

## Backup and recovery

Backups are not automated. Before production, set RPO/RTO, use SQLite's online backup API or a storage-aware snapshot, encrypt and access-control the backup, monitor its freshness, and rehearse restore. Backups include confidential scan metadata and must follow the retention policy.

## Security notes

- Revoke an exposed report token by deleting its report row; the raw token cannot be recovered from its stored hash.
- Rotate exposed provider credentials through the provider or secrets manager.
- Live checks accept public HTTP/HTTPS destinations only. Do not bypass the IP and redirect policy to reach private services.
- Request logs omit URL data, request bodies, client IPs, query strings, and bearer tokens.

## Before public production

Add HTTPS ingress, shared edge limits, an isolated inspection worker with network egress controls, encrypted backups and restore drills, monitoring, incident ownership, and an independent security review. SQLite and the in-memory rate limiter support a single process only.

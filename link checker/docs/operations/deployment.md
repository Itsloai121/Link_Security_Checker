# Deployment

Unmask is one process plus one SQLite file. Run it behind an HTTPS reverse proxy; do not expose uvicorn directly to the internet.

## Container (recommended)
```bash
docker build -f infra/containers/Dockerfile -t unmask:1.0.0 .
cp infra/environments/production.env.template infra/environments/production.env   # then edit
docker compose -f infra/containers/compose.yaml up -d
```
The image runs as an unprivileged user, with a read-only root file system, no capabilities and a data volume at `/data`. The start command applies migrations first (schema changes are always an explicit step, never done silently by the running app). It publishes on `127.0.0.1:8000` only.

## Without containers (systemd example)
```ini
[Service]
User=unmask
WorkingDirectory=/opt/unmask
Environment=PYTHONPATH=src UNMASK_ENVIRONMENT=production UNMASK_DATABASE_PATH=/var/lib/unmask/unmask.db
EnvironmentFile=/etc/unmask/unmask.env
ExecStartPre=/opt/unmask/.venv/bin/python -m interfaces.cli migrate
ExecStart=/opt/unmask/.venv/bin/python -m interfaces.cli serve --host 127.0.0.1 --port 8000
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/unmask
PrivateTmp=true
Restart=on-failure
```

## Reverse proxy (Caddy example: automatic HTTPS)
```caddy
unmask.example.org {
    reverse_proxy 127.0.0.1:8000
}
```
Then set `UNMASK_HSTS=true` and `UNMASK_TRUSTED_PROXY_HOPS=1` so per-client rate limits use the real client address (the proxy appends it to `X-Forwarded-For`). Leave `TRUSTED_PROXY_HOPS=0` if nothing you control is in front, otherwise clients could spoof their address.

## Network egress (important)
The scanner connects to addresses supplied by strangers. The application refuses private, loopback, link-local, ULA and mapped/NAT64 addresses, but also enforce it in the network: allow outbound only to the public internet on ports 53, 80, 443, 8080, 8443 and **deny** 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (cloud metadata), 127.0.0.0/8, fc00::/7, fe80::/10 and ::1. On cloud VMs also require IMDSv2 / metadata hop limit 1.

## Threat feeds and housekeeping
- Initial download, then keep fresh: either `UNMASK_FEED_REFRESH_HOURS=6` (the app refreshes itself, also at start-up) or a cron/Task Scheduler job running `python -m interfaces.cli update-feeds` every 6 to 12 hours. **Read `feeds.md` first: the OpenPhish community feed is non-commercial.**
- Expired reports are purged automatically every 30 minutes (`UNMASK_PURGE_INTERVAL_MINUTES`).

## Upgrades
1. Back up the database file. 2. Deploy the new code/image. 3. `python -m interfaces.cli migrate` (the container does this at start). 4. Check `/api/v1/health/ready`. Applied migrations are checksummed: if `migrate` complains that one "was modified after it was applied", someone edited history; restore the original file and add a *new* migration instead.

## Production checklist
- [ ] `UNMASK_ENVIRONMENT=production` (API docs off, unsafe settings refused)
- [ ] HTTPS in front; `UNMASK_HSTS=true`; trusted-proxy hops set correctly
- [ ] Egress rules in place; container scanned (Trivy/Grype)
- [ ] Secrets only in the environment/secret store; `.env` not in git
- [ ] Feeds downloaded and refreshing; licence terms reviewed
- [ ] Backups of the database volume; restore tested once
- [ ] `/internal/metrics` token set and scraped, alerts configured (see `runbook.md`)
- [ ] Privacy notice matches your configuration (what is sent to RDAP/Team Cymru/optional providers)

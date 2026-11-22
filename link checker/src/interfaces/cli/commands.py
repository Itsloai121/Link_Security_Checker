"""Command-line interface: serve the app, run migrations, scan one link, refresh feeds, purge, check configuration."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import timedelta
from pathlib import Path

from bootstrap.dependency_wiring import build_container
from bootstrap.settings import APP_VERSION, Settings
from infrastructure.persistence.migrator import migrate, schema_is_current
from interfaces.api.handlers.scans import scan_out
from modules.link_analysis.application.run_analysis import RunLinkAnalysis
from modules.link_analysis.domain.scan import Scan, ScanStatus
from modules.link_analysis.infrastructure.in_memory_scan_repository import InMemoryScanRepository

_COLOR = sys.stdout.isatty()
_STATUS = {"clear": ("OK ", "32"), "notice": ("!  ", "33"), "warning": ("!! ", "33"), "danger": ("XX ", "31"), "unavailable": ("?  ", "90")}
_VERDICT_COLOR = {"safe": "32", "caution": "33", "suspicious": "33", "dangerous": "31", "inconclusive": "90"}


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def cmd_serve(args: argparse.Namespace, s: Settings) -> int:
    import uvicorn
    uvicorn.run("bootstrap.main:create_app", factory=True, host=args.host or s.host, port=args.port or s.port, reload=args.reload, log_config=None,
                server_header=False, proxy_headers=False)
    return 0


def cmd_migrate(args: argparse.Namespace, s: Settings) -> int:
    c = build_container(s)
    applied = migrate(c.db, s.migrations_dir)
    print("Applied:", ", ".join(applied) if applied else "nothing to do (schema is current)")
    return 0


async def _scan(args: argparse.Namespace, s: Settings) -> int:
    if args.allow_private:
        s = s.model_copy(update={"allow_private_networks": True, "allowed_fetch_ports": ",".join(str(p) for p in sorted(s.fetch_ports | {args.port_hint}))} if args.port_hint else {"allow_private_networks": True})
    c = build_container(s)
    repo = InMemoryScanRepository()  # nothing is stored: a CLI scan leaves no record
    now = c.clock.now()
    scan = Scan(c.ids.new_scan_id(), args.url, args.label, ScanStatus.QUEUED, now, now + timedelta(hours=1), APP_VERSION)
    await repo.add(scan)
    runner = RunLinkAnalysis(repo, c.run_analysis.collector, c.reference, c.clock, c.policy, c.metrics)
    try:
        await runner.execute(scan.id)
    finally:
        await c.aclose()
    done = await repo.get(scan.id)
    out = scan_out(done)
    if args.json:
        print(out.model_dump_json(indent=2))
        return 0 if done.status is ScanStatus.COMPLETED else 1
    print()
    print(f"  {_c((out.headline or out.status).upper(), _VERDICT_COLOR.get(out.verdict or '', '0'))}   risk {out.risk_score}/100 · {out.coverage_percent}% of tests could verify")
    print(f"  link:  {out.submitted_input}")
    if out.final_url and out.final_url != out.normalized_url:
        print(f"  lands: {out.final_url}")
    for r in out.reasons:
        print(f"   - {r}")
    print()
    for ch in out.checks:
        mark, col = _STATUS[ch.status]
        print(f"  {_c(mark, col)}{ch.position:>2}. {ch.title:<48} {ch.summary[:70]}")
    if args.details:
        for ch in out.checks:
            for f in ch.findings:
                print(f"\n  [{ch.id}] {f.severity.upper()}: {f.message}")
                for kv in f.evidence:
                    print(f"      {kv.key}: {kv.value}")
    print()
    return 0 if done.status is ScanStatus.COMPLETED else 1


async def _feeds(args: argparse.Namespace, s: Settings) -> int:
    c = build_container(s)
    try:
        if args.status:
            for f in await c.feed_status.execute():
                print(f"{'on ' if f['enabled'] else 'off'} {f['name']:<18} {f['indicators']:>8} indicators  last={f['last_status'] or 'never'} {f['last_finished'] or ''}")
                if f["terms"]:
                    print(f"      terms: {f['terms']} ({f['terms_url']})")
            return 0
        print("Downloading enabled threat feeds. Check each feed's licence terms (see docs/operations/feeds.md):")
        for f in await c.feed_status.execute():
            if f["enabled"] and f["terms"]:
                print(f"  - {f['title']}: {f['terms']}")
        rc = 0
        for r in await c.refresh_feeds.execute(args.only):
            print(f"  {r.source:<18} {r.status:<10} loaded={r.loaded} previous={r.previous} {r.note}")
            rc = rc or (1 if r.status in ("failed", "rejected") else 0)
        return rc
    finally:
        await c.aclose()


async def _import_feed(args: argparse.Namespace, s: Settings) -> int:
    c = build_container(s)
    try:
        r = await c.refresh_feeds.import_text(args.name, Path(args.file).read_text(encoding="utf-8", errors="replace"))
        print(f"{r.source}: {r.status} loaded={r.loaded} previous={r.previous} {r.note}")
        return 0 if r.status == "succeeded" else 1
    finally:
        await c.aclose()


async def _purge(args: argparse.Namespace, s: Settings) -> int:
    c = build_container(s)
    try:
        print("Deleted", await c.purge_scans.execute(), "expired report(s)")
    finally:
        await c.aclose()
    return 0


def cmd_check_config(args: argparse.Namespace, s: Settings) -> int:
    c = build_container(s)
    ok, info = schema_is_current(c.db, s.migrations_dir)
    shown = {k: ("***" if "key" in k or "token" in k else str(v)) for k, v in s.model_dump().items() if v not in (None, "")}
    print(json.dumps(shown, indent=2, default=str))
    print(f"\nreference data: {c.reference.version} ({len(c.reference.brands)} brands)")
    print(f"database schema: {'current, version ' + info if ok else 'NOT READY: ' + info}")
    print(f"optional providers: {[p.name for p in c.run_analysis.collector.blocklists]}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="unmask", description="Unmask - link security checker")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("serve", help="run the web app and API")
    sp.add_argument("--host"); sp.add_argument("--port", type=int); sp.add_argument("--reload", action="store_true")
    sub.add_parser("migrate", help="create or upgrade the database schema")
    sc = sub.add_parser("scan", help="analyse one link from the terminal (nothing is stored)")
    sc.add_argument("url"); sc.add_argument("--label", help="the visible link text, to check for label/destination mismatch")
    sc.add_argument("--json", action="store_true"); sc.add_argument("--details", action="store_true", help="print every finding with its evidence")
    sc.add_argument("--allow-private", action="store_true", help="testing only: disable the private-network block"); sc.add_argument("--port-hint", type=int, default=0, help=argparse.SUPPRESS)
    fd = sub.add_parser("update-feeds", help="download the enabled threat feeds")
    fd.add_argument("--only"); fd.add_argument("--status", action="store_true")
    im = sub.add_parser("import-feed", help="load a threat feed from a local file (offline / manual download)")
    im.add_argument("name", help="feed name from config/defaults/feeds.json, e.g. openphish"); im.add_argument("file")
    sub.add_parser("purge", help="delete expired reports now")
    sub.add_parser("check-config", help="validate configuration and show the effective (non-secret) settings")
    args = p.parse_args(argv)
    s = Settings()
    handlers = {"serve": cmd_serve, "migrate": cmd_migrate, "check-config": cmd_check_config}
    if args.cmd in handlers:
        code = handlers[args.cmd](args, s)
    else:
        code = asyncio.run({"scan": _scan, "update-feeds": _feeds, "import-feed": _import_feed, "purge": _purge}[args.cmd](args, s))
    sys.exit(code)

"""Versioned, checksummed, repeatable migrations (USDA §17). SQL files live in /migrations and run in name order."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from infrastructure.persistence.sqlite import SqliteDatabase

_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


@dataclass(frozen=True)
class Migration:
    version: str
    name: str
    sql: str
    checksum: str


class MigrationError(RuntimeError):
    pass


def load_migrations(directory: Path) -> list[Migration]:
    items: list[Migration] = []
    for p in sorted(directory.glob("*.sql")):
        m = _NAME.match(p.name)
        if not m:
            raise MigrationError(f"Bad migration file name: {p.name} (expected NNNN_description.sql)")
        sql = p.read_text(encoding="utf-8")
        items.append(Migration(m.group(1), m.group(2), sql, hashlib.sha256(sql.encode()).hexdigest()))
    versions = [i.version for i in items]
    if len(set(versions)) != len(versions):
        raise MigrationError("Duplicate migration version numbers.")
    return items


_BOOTSTRAP = """CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))"""


def applied(db: SqliteDatabase) -> dict[str, str]:
    def _q(conn):
        conn.execute(_BOOTSTRAP)
        return {r["version"]: r["checksum"] for r in conn.execute("SELECT version, checksum FROM schema_migrations")}
    return db.run_sync(_q)


def migrate(db: SqliteDatabase, directory: Path) -> list[str]:
    """Apply pending migrations. Safe to run repeatedly. Refuses to continue if an applied file was edited."""
    done = applied(db)
    newly: list[str] = []
    for mig in load_migrations(directory):
        if mig.version in done:
            if done[mig.version] != mig.checksum:
                raise MigrationError(f"Migration {mig.version}_{mig.name} was modified after it was applied.")
            continue
        conn = db.connect()
        try:
            conn.executescript(f"BEGIN IMMEDIATE;\n{mig.sql}\n")
            conn.execute("INSERT INTO schema_migrations(version, name, checksum) VALUES (?,?,?)",
                         (mig.version, mig.name, mig.checksum))
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:  # pragma: no cover
                pass
            raise
        finally:
            conn.close()
        newly.append(f"{mig.version}_{mig.name}")
    return newly


def schema_is_current(db: SqliteDatabase, directory: Path) -> tuple[bool, str]:
    """Used by readiness checks and startup: the app never changes schema itself (USSA pillar 5)."""
    try:
        done = applied(db)
    except Exception as exc:  # pragma: no cover - unreadable DB
        return False, f"database unreadable: {exc.__class__.__name__}"
    expected = load_migrations(directory)
    missing = [f"{m.version}_{m.name}" for m in expected if m.version not in done]
    if missing:
        return False, "pending migrations: " + ", ".join(missing)
    return True, expected[-1].version if expected else "0000"

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MIGRATION_FILE = re.compile(r"^\d{4}_[a-z0-9_-]+\.sql$", re.IGNORECASE)


class ScanRepository:
    def __init__(self, database_path: str, migration_directory: Path):
        self.database_path = database_path
        self.migration_directory = migration_directory
        self._memory_uri = f"file:link_safety_{uuid.uuid4().hex}?mode=memory&cache=shared" if database_path == ":memory:" else None
        self._memory_anchor: sqlite3.Connection | None = None

    def _secure_file_permissions(self) -> None:
        """Keep the database and SQLite sidecars private on POSIX systems."""
        if os.name == "nt" or self.database_path == ":memory:":
            return
        database = Path(self.database_path)
        for candidate in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
            try:
                if candidate.exists():
                    if candidate.is_symlink():
                        raise RuntimeError("Database files must not be symbolic links.")
                    candidate.chmod(0o600)
            except OSError as exc:
                raise RuntimeError("Database file permissions could not be restricted.") from exc

    def _connect(self, *, check_same_thread: bool = True) -> sqlite3.Connection:
        if self.database_path != ":memory:":
            database = Path(self.database_path)
            database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            candidates = (database, Path(f"{database}-wal"), Path(f"{database}-shm"))
            if any(candidate.is_symlink() for candidate in candidates):
                raise RuntimeError("Database files must not be symbolic links.")
            if os.name != "nt" and not database.exists():
                try:
                    descriptor = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError:  # Another local process may have created it concurrently.
                    if database.is_symlink():
                        raise RuntimeError("Database path must not be a symbolic link.")
                else:
                    os.close(descriptor)
            # Restrict pre-existing database/sidecar permissions before SQLite opens them.
            self._secure_file_permissions()
        connection = sqlite3.connect(self._memory_uri or self.database_path, timeout=5.0, isolation_level=None,
                                     uri=self._memory_uri is not None, check_same_thread=check_same_thread)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA secure_delete = ON")
        if hasattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE") and hasattr(connection, "setconfig"):
            connection.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        self._secure_file_permissions()
        return connection

    def initialize(self) -> None:
        if self._memory_uri is not None and self._memory_anchor is None:
            # The anchor is created during startup and closed during shutdown;
            # those operations may run on different asyncio worker threads.
            self._memory_anchor = self._connect(check_same_thread=False)
        with closing(self._connect()) as connection:
            if self.database_path != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "name TEXT PRIMARY KEY, applied_at TEXT NOT NULL) STRICT"
            )
            applied = {row[0] for row in connection.execute("SELECT name FROM schema_migrations")}
            migration_files = sorted(
                file for file in self.migration_directory.iterdir()
                if file.is_file() and MIGRATION_FILE.fullmatch(file.name)
            )
            for migration in migration_files:
                if migration.name in applied:
                    continue
                sql = migration.read_text(encoding="utf-8-sig")
                applied_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                # Filenames are constrained to ASCII letters, digits, underscores, and dashes.
                escaped_name = migration.name.replace("'", "''")
                script = (
                    "BEGIN IMMEDIATE;\n" + sql + "\n"
                    + "INSERT INTO schema_migrations(name, applied_at) VALUES ('"
                    + escaped_name + "', '" + applied_at + "');\nCOMMIT;"
                )
                try:
                    connection.executescript(script)
                except sqlite3.Error as exc:
                    if connection.in_transaction:
                        connection.rollback()
                    raise RuntimeError(f"Database migration {migration.name} failed.") from exc
            self._secure_file_permissions()

    def ping(self) -> bool:
        with closing(self._connect()) as connection:
            connection.execute("SELECT 1").fetchone()
        return True

    def create(self, scan: dict[str, Any]) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO scans (id, access_token_hash, host, scheme, score, verdict, summary, analyzer_version, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan["id"], scan["access_token_hash"], scan["host"], scan["scheme"],
                        scan["score"], scan["verdict"], scan["summary"], scan["analyzer_version"], scan["created_at"],
                    ),
                )
                connection.executemany(
                    "INSERT INTO scan_checks (scan_id, check_id, ordinal, title, description, status, detail, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        (scan["id"], item["id"], ordinal, item["title"], item["description"], item["status"], item["detail"], scan["created_at"])
                        for ordinal, item in enumerate(scan["checks"])
                    ],
                )
                connection.commit()
                self._secure_file_permissions()
            except Exception:
                connection.rollback()
                raise

    def find_by_id(self, scan_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT id, access_token_hash, host, scheme, score, verdict, summary, analyzer_version, created_at "
                "FROM scans WHERE id = ?", (scan_id,),
            ).fetchone()
            if row is None:
                return None
            checks = connection.execute(
                "SELECT check_id, title, description, status, detail FROM scan_checks "
                "WHERE scan_id = ? ORDER BY ordinal", (scan_id,),
            ).fetchall()
        result = dict(row)
        result["checks"] = [
            {"id": item["check_id"], "title": item["title"], "description": item["description"],
             "status": item["status"], "detail": item["detail"]}
            for item in checks
        ]
        return result

    def delete_expired(self, retention_days: int) -> int:
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "DELETE FROM scans WHERE julianday(created_at) < julianday('now', ?)",
                (f"-{retention_days} days",),
            )
            self._secure_file_permissions()
            return cursor.rowcount

    def close(self) -> None:
        if self._memory_anchor is not None:
            self._memory_anchor.close()
            self._memory_anchor = None


def make_report_credentials() -> tuple[str, str]:
    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    return token, token_hash


def verify_report_token(expected_hash: str, token: str | None) -> bool:
    if not isinstance(token, str) or len(token) != 64 or not re.fullmatch(r"[a-fA-F0-9]{64}", token):
        return False
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
        return False
    actual_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    return hmac.compare_digest(expected_hash, actual_hash)


def new_scan_id() -> str:
    return str(uuid.uuid4())

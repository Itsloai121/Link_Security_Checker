# ADR 0002: SQLite as the system of record

**Date:** 2026-11-22 · **Status:** accepted

**Context.** Short-lived, small, single-writer data; the app should run with `pip install` and no database server.
**Decision.** SQLite in WAL mode, `STRICT` tables with `CHECK` constraints, one short-lived connection per unit of work in a worker thread, bound parameters everywhere, versioned checksummed migrations run by an explicit command.
**Alternatives.** PostgreSQL (operational weight not justified yet); JSON files (no constraints, no atomicity).
**Consequences.** Single node only. Requires SQLite ≥ 3.37 (`STRICT`), which ships with Python 3.11+ on current platforms. Repositories isolate the choice: moving to PostgreSQL changes two classes and the migrations.

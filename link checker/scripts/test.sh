#!/usr/bin/env bash
# Lint + full test suite (needs: pip install -r requirements-dev.lock)
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/bin/python -m ruff check src tests scripts
.venv/bin/python scripts/export_schemas.py --check
.venv/bin/python -m pytest "$@"

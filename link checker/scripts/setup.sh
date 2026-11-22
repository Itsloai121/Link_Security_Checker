#!/usr/bin/env bash
# One-time setup: virtualenv, pinned dependencies, local .env, database schema.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
[ -d .venv ] || "$PY" -m venv .venv
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.lock
[ -f .env ] || cp .env.example .env
PYTHONPATH=src .venv/bin/python -m interfaces.cli migrate
echo "Ready. Start the app with: ./scripts/run.sh   (demo without internet: .venv/bin/python scripts/demo_server.py)"

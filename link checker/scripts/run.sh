#!/usr/bin/env bash
# Start the web app and API (default http://127.0.0.1:8000). Extra arguments are passed through, e.g. --port 9000
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=src exec .venv/bin/python -m interfaces.cli serve "$@"

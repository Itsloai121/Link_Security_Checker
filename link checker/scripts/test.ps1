# Lint + full test suite (needs: pip install -r requirements-dev.lock)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
& .\.venv\Scripts\python.exe -m ruff check src tests scripts
& .\.venv\Scripts\python.exe scripts\export_schemas.py --check
& .\.venv\Scripts\python.exe -m pytest @args

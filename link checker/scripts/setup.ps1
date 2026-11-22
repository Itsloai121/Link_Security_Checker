# One-time setup (Windows PowerShell): virtualenv, pinned dependencies, local .env, database schema.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path .venv)) { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --quiet --upgrade pip
& .\.venv\Scripts\python.exe -m pip install --quiet -r requirements.lock
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
$env:PYTHONPATH = "src"
& .\.venv\Scripts\python.exe -m interfaces.cli migrate
Write-Host "Ready. Start the app with: .\scripts\run.ps1   (demo without internet: .\.venv\Scripts\python.exe scripts\demo_server.py)"

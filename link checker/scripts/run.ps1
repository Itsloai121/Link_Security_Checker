# Start the web app and API (default http://127.0.0.1:8000). Extra arguments are passed through, e.g. --port 9000
Set-Location (Split-Path $PSScriptRoot -Parent)
$env:PYTHONPATH = "src"
& .\.venv\Scripts\python.exe -m interfaces.cli serve @args

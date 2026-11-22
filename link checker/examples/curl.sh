#!/usr/bin/env bash
# Minimal API walk-through with curl. Needs: curl, jq.
set -euo pipefail
SERVER="${SERVER:-http://127.0.0.1:8000}"
ID=$(curl -s -X POST "$SERVER/api/v1/scans" -H 'Content-Type: application/json' -d '{"url":"https://paypa1-login.example/signin"}' | jq -r .id)
echo "scan id: $ID"
until [ "$(curl -s "$SERVER/api/v1/scans/$ID" | jq -r .status)" = "completed" ]; do sleep 1; done
curl -s "$SERVER/api/v1/scans/$ID" | jq '{headline, risk_score, reasons, checks: [.checks[] | {position, id, status, summary}]}'
curl -s -X DELETE "$SERVER/api/v1/scans/$ID" -o /dev/null -w "deleted: HTTP %{http_code}\n"

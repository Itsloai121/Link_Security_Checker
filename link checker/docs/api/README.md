# API reference

Base path `/api/v1`. JSON in, JSON out. The complete machine-readable contract is [`openapi.json`](openapi.json) (generated from the code and checked in CI); interactive docs are at `/api/docs` when `UNMASK_ENVIRONMENT` is not `production`.

## Typical flow

```bash
# 1. submit (returns immediately)
curl -s -X POST http://127.0.0.1:8000/api/v1/scans -H 'Content-Type: application/json' \
     -d '{"url": "https://secure.paypal.com@login-paypa1.example/signin", "display_text": "paypal.com/signin"}'
# 202 Accepted, Location: /api/v1/scans/<id>

# 2. poll about once a second until status is "completed" (partial results appear as tests finish)
curl -s http://127.0.0.1:8000/api/v1/scans/<id>

# 3. optional: delete the report now (otherwise it is deleted after 24 h)
curl -s -X DELETE http://127.0.0.1:8000/api/v1/scans/<id>     # 204
```

A runnable version: [`examples/api_usage.py`](../../examples/api_usage.py).

## Endpoints

| Method and path | Purpose | Success | Notes |
|---|---|---|---|
| `POST /scans` | Submit a link | `202` + `Location` | Body: `url` (required, ≤ 4096 chars; any text, even `javascript:`; analysed, never executed) and `display_text` (optional, ≤ 1000). Unknown fields are rejected. |
| `GET /scans/{id}` | Read a report | `200` | `status`: `queued` → `running` → `completed` or `failed`. `checks` fills progressively. |
| `DELETE /scans/{id}` | Delete a report | `204` | Whoever holds the id may delete. |
| `GET /checks` | The 20 tests and what each does | `200` | Cacheable for an hour. |
| `GET /health/live` | Process is up | `200` | |
| `GET /health/ready` | Database and schema are usable | `200` / `503` | |

There is no endpoint to list scans (by design). `GET /internal/metrics` exists only when `UNMASK_METRICS_TOKEN` is set (`Authorization: Bearer …`).

## Report shape (abridged)

```json
{
  "id": "q1ZtG5mJp0mU3x7YkL2cAw",
  "status": "completed",
  "submitted_input": "https://secure.paypal.com@login-paypa1.example/signin",
  "final_url": null,
  "verdict": "dangerous",
  "headline": "Don't open this link",
  "reasons": ["Everything before the @ (“secure.paypal.com”) is decoy text. The link really goes to login-paypa1.example."],
  "risk_score": 97,
  "coverage_percent": 55,
  "progress": {"done": 20, "total": 20},
  "counts": {"flagged": 5, "clear": 4, "unverified": 11},
  "expires_at": "2026-11-23T12:00:00Z",
  "checks": [
    {
      "id": "userinfo_masking", "position": 6, "title": "User-Info (@) Masking Check", "category": "address",
      "category_label": "The address itself", "explanation": "Catches links containing @ …",
      "status": "danger", "risk_points": 75, "summary": "Everything before the @ …",
      "findings": [{"severity": "critical", "code": "decoy_userinfo", "message": "…", "evidence": [{"key": "Real host", "value": "login-paypa1.example"}]}],
      "facts": [{"key": "Real host", "value": "login-paypa1.example"}],
      "limitation": null, "duration_ms": 1
    }
  ]
}
```

Values: `verdict` ∈ `safe | caution | suspicious | dangerous | inconclusive`; check `status` ∈ `clear | notice | warning | danger | unavailable` (*unavailable* = **not verified**); finding `severity` ∈ `info | low | medium | high | critical`. `coverage_percent` is the share of tests that could verify. **Treat strings in `findings`, `facts` and `summary` as untrusted text**: they quote the analysed page. Render them as text, never as HTML.

## Errors

Every failure uses one shape (see `docs/architecture/backend.md`): `{"error": {"code", "message", "request_id", "details": []}}`. Quote `request_id` (also in the `X-Request-ID` response header) when reporting a problem. `429` and `503` include `Retry-After`.

## Limits (defaults)

10 submissions per minute per client, 240 reads per minute per client, 6 scans per minute per target site, 100 queued scans, 8 KB request body, 45 s per analysis. All configurable (`.env.example`).

## Compatibility policy

Within `v1`, changes are additive only (new optional response fields, new check ids at the end of the list). Clients must ignore unknown fields. Removing or changing a field means `/api/v2`. The check catalogue (`/checks`) is the source of truth for titles and explanations.

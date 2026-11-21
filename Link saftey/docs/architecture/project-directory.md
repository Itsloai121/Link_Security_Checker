# Project directory schema

```text
Link saftey/
├── backend/
│   └── link_safety/
│       ├── __init__.py          # Python backend package
│       ├── api.py               # FastAPI routes and HTTP security boundary
│       ├── config.py            # Environment parsing and settings validation
│       ├── database.py          # SQLite repository, migrations, retention, tokens
│       ├── errors.py            # Typed application and inspection errors
│       ├── ip_policy.py         # Public IP and embedded-address policy
│       ├── live_checks.py       # RDAP, ASN, PhishTank, TLS, HTML and redirect checks
│       ├── network.py           # Safe DNS, pinned HTTP(S), redirects and response limits
│       └── url_analysis.py      # URL normalization, static rules and scoring
├── server.py                    # Python/Uvicorn process entry point
├── public/                      # Existing browser UI (HTML, CSS, JavaScript)
├── migrations/                  # Ordered SQLite schema migrations
├── tests/                       # Python unittest regression and API-contract suite
├── docs/
│   ├── architecture/            # Architecture, security, data and migration decisions
│   ├── api/                     # API contract
│   ├── development/             # Local setup
│   └── operations/              # Runbook and deployment notes
├── archive/
│   └── node-backend-before-python/ # Historical Node backend; not used at runtime
├── project engineering ideas/   # Supplied project and architecture reference files
├── var/                         # Existing local SQLite database and runtime sidecars
├── .env.example                 # Safe configuration template; real .env is not distributed
├── pyproject.toml               # Pinned Python dependencies and project metadata
├── uv.lock                      # Locked Python dependency graph
└── README.md
```

The active backend is Python. The original browser GUI remains JavaScript because it runs in the browser; it continues to call the same `/api/analyze` route. The former Node server, package manifest, configuration loader, and source tree are retained under `archive/` only and are not imported by the Python runtime.

# Backend verification

Run the regression suite from the project root:

```powershell
uv run python -m unittest discover -s tests -p "test_*.py" -v
```

The suite covers URL normalization and public IP policy, DNS failure behavior, IP-pinned HTTP connections, private redirect rejection, HTTPS downgrade tracking, custom-header validation, HTML form/cloaking signals, bounded PhishTank caching, configuration parsing, SQLite permissions/migrations/token hashing, in-memory repository lifecycle, request limits, report authorization, Trusted Host enforcement, rate limiting, and the GUI/API response contract. All external network behavior is mocked; tests do not send scan requests to public websites.

Passing tests are regression evidence, not proof of zero defects or a substitute for independent security testing.

# Adding or changing a check

The project is built around exactly **20 tests** (the brief). Improving an existing test is the common case; adding a 21st needs the extra steps at the end.

## Improving an existing test
1. Open its class in `src/modules/link_analysis/domain/checks/` (`address.py`, `journey.py`, `reputation.py`, `behavior.py`).
2. Change the logic. Keep it pure: it may only read `ctx.url`, `ctx.display_text`, `ctx.ref` (reference data), `ctx.now` and the evidence keys listed in its `spec.requires`.
3. Add a test in `tests/unit/test_checks.py`: one case that **must** be flagged and one that **must not** (false positives destroy trust). Use the builders in `tests/unit/helpers.py`.
4. If the rule needs data (a brand, a list, a phrase), put it in `config/defaults/reference/*.json`, not in code; run `python scripts/export_schemas.py` if you changed a model.

## Anatomy of a check
```python
class MyCheck:
    spec = CheckSpec("my_check", 7, "My Check Title", Category.ADDRESS,
                     "One or two sentences: what this test does (shown next to the result).",
                     frozenset({"journey"}))                    # evidence it needs; empty = URL only

    def evaluate(self, ctx: CheckContext) -> Outcome:
        ev = ctx.evidence("journey")
        if not ev.available:
            return Outcome.missing(ev.reason or "…")             # NOT VERIFIED: never return "clear" when you could not look
        findings = []
        if something_suspicious:
            findings.append(fnd(Severity.HIGH, "short_code", "Plain-language message the reader sees.", Key="evidence value"))
        if not findings:
            return Outcome.clear("What was verified, in one sentence.", limitation="what this test cannot see")
        return Outcome.flagged(findings, Fact="value shown in the details")
```
Rules of thumb: write each finding so it makes sense **alone** (it may be shown as a headline reason); never put attacker-controlled text anywhere but evidence values and messages (they are clipped and rendered as text); prefer `Severity.MEDIUM` for "unusual", `HIGH` for "almost always malicious", `CRITICAL` only for confirmed or unambiguous cases (it alone makes the verdict "dangerous").

## Severity and scoring
`INFO` 0 · `LOW` 5 · `MEDIUM` 15 · `HIGH` 35 · `CRITICAL` 75 points; combined as `100 × (1 − Π(1 − p/100))` (see `domain/scoring.py`). To make a finding lead the headline reasons among equals, add its code to `PRIORITY` in `scoring.py`.

## Adding evidence
New network facts go through a **port** (`ports/evidence_sources.py`), an **adapter** (module `infrastructure/`), a key in `EVIDENCE_KEYS` (`domain/evidence.py`) and a `_collect_<key>` method in `application/evidence_collector.py`. Any outbound HTTP must use `GuardedHttpClient`. Add a fake in `tests/fixtures/fakes.py`.

## Adding a 21st test
Everything above, plus: set the position (21), update `EXPECTED_CHECKS` in `checks/catalog.py` and `EXPECTED_CHECK_COUNT` in `domain/scan.py`, add a migration relaxing `CHECK (position BETWEEN 1 AND 20)` on `scan_checks` (a new numbered file, never edit 0001), update the "20" in the web copy (`index.html`) and the tests that assert 20, and regenerate `docs/api/openapi.json`.

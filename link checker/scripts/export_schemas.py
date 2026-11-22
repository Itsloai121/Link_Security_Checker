"""Regenerate config/schemas/*.json from the validating models (the models are the source of truth).

    python scripts/export_schemas.py          # rewrite the files
    python scripts/export_schemas.py --check  # exit 1 if they are out of date (used by tests and CI)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from modules.link_analysis.infrastructure.reference_loader import BrandsFile, LexiconFile, ListsFile  # noqa: E402
from modules.threat_intel.infrastructure.feed_adapters import FeedsFile  # noqa: E402

TARGETS = {"brands.schema.json": BrandsFile, "lists.schema.json": ListsFile, "lexicons.schema.json": LexiconFile, "feeds.schema.json": FeedsFile}


def render() -> dict[str, str]:
    return {name: json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n" for name, model in TARGETS.items()}


def main() -> int:
    out = ROOT / "config" / "schemas"
    rendered = render()
    if "--check" in sys.argv:
        stale = [n for n, text in rendered.items() if not (out / n).exists() or (out / n).read_text() != text]
        print("schemas up to date" if not stale else f"out of date: {', '.join(stale)} (run scripts/export_schemas.py)")
        return 1 if stale else 0
    out.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        (out / name).write_text(text)
        print("wrote", out / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

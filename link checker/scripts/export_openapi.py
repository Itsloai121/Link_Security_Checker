"""Write docs/api/openapi.json from the running application definition (the code is the source of truth)."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bootstrap.main import create_app  # noqa: E402
from bootstrap.settings import Settings  # noqa: E402


def main() -> int:
    app = create_app(Settings(database_path=Path(tempfile.mkdtemp()) / "x.db", environment="development", _env_file=None))
    target = ROOT / "docs" / "api" / "openapi.json"
    text = json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        same = target.exists() and target.read_text() == text
        print("openapi.json up to date" if same else "openapi.json is out of date (run scripts/export_openapi.py)")
        return 0 if same else 1
    target.write_text(text)
    print("wrote", target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

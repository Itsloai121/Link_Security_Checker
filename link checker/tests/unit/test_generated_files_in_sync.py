"""Generated artefacts must match their source of truth, so documentation and schemas never drift."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _check(script):
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / script), "--check"], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr


def test_config_schemas_are_current():
    _check("export_schemas.py")


def test_openapi_document_is_current():
    _check("export_openapi.py")

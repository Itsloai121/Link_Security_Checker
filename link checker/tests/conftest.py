"""Shared fixtures for every test package."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bootstrap.main import create_app
from modules.link_analysis.infrastructure.reference_loader import load_reference
from tests.fixtures.fakes import build_test_container
from tests.fixtures.fixture_site import FixtureSite


@pytest.fixture(scope="session")
def ref():
    return load_reference(Path(__file__).resolve().parents[1] / "config" / "defaults" / "reference")


@pytest.fixture(scope="session")
def site():
    """The local fixture 'internet' (virtual hosts such as login-paypa1.test). Nothing here touches the real network."""
    s = FixtureSite().start()
    yield s
    s.stop()


@pytest.fixture
def make_client(tmp_path, site):
    """make_client(**settings_overrides) -> context manager yielding a TestClient for a fully wired app."""
    def _make(**overrides):
        c = build_test_container(tmp_path, site, **overrides)
        return TestClient(create_app(c.settings, c))
    return _make


@pytest.fixture
def client(make_client):
    with make_client(rate_limit_submit_per_minute=500, per_host_scans_per_minute=500) as c:
        yield c

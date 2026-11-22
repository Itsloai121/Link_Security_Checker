import pytest

from infrastructure.external_services.guarded_http import GuardedHttpClient
from infrastructure.external_services.network_policy import NetworkPolicy
from tests.fixtures.fakes import MappingResolver


@pytest.fixture
async def client(site):
    """Real guarded client; loopback allowed ONLY because this is a test (fake host names map to 127.0.0.1)."""
    policy = NetworkPolicy(allowed_ports=frozenset({80, 443, site.port}), allow_private_networks=True)
    c = GuardedHttpClient(policy, MappingResolver(policy, site.host_map))
    yield c
    await c.aclose()

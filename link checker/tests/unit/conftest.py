from datetime import datetime, timezone

import pytest

from modules.link_analysis.domain.checks.base import CheckContext
from modules.link_analysis.domain.evidence import Evidence
from modules.link_analysis.domain.url_model import parse_url

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def run(ref):
    """run(check, url, label=None, **evidence) -> CheckResult, with every declared evidence key defaulting to 'missing'."""
    from modules.link_analysis.domain.checks.base import build_result

    def _run(check, url, label=None, **ev):
        evidence = {k: (v if isinstance(v, Evidence) else Evidence.of(v)) for k, v in ev.items()}
        for key in check.spec.requires:
            evidence.setdefault(key, Evidence.missing("not provided in this test"))
        ctx = CheckContext(parse_url(url), label, ref, NOW, evidence, check.spec.requires)
        return build_result(check.spec, check.evaluate(ctx), 1)
    return _run

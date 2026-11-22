"""The ordered catalogue of the 20 checks (order = the order in the project brief)."""
from __future__ import annotations

from modules.link_analysis.domain.checks.address import (DangerousSchemeCheck, HomographCheck, LookalikeCheck, ObfuscationCheck,
                                                         PortPathAnomalyCheck, SubdomainSpoofingCheck, UserInfoMaskingCheck)
from modules.link_analysis.domain.checks.base import Check, CheckSpec
from modules.link_analysis.domain.checks.behavior import (AutoDownloadCheck, BrandUrgencyCheck, CloakingCheck, FormActionMismatchCheck,
                                                          HiddenElementsCheck, LoginFormCheck)
from modules.link_analysis.domain.checks.journey import DisplayMismatchCheck, OpenRedirectCheck, RedirectChainCheck
from modules.link_analysis.domain.checks.reputation import BlocklistCheck, DomainAgeCheck, HostingRiskCheck, TlsCertificateCheck

ALL_CHECKS: tuple[Check, ...] = (
    BlocklistCheck(), LookalikeCheck(), HomographCheck(), RedirectChainCheck(), OpenRedirectCheck(), UserInfoMaskingCheck(),
    SubdomainSpoofingCheck(), ObfuscationCheck(), DangerousSchemeCheck(), DomainAgeCheck(), TlsCertificateCheck(), HostingRiskCheck(),
    PortPathAnomalyCheck(), LoginFormCheck(), FormActionMismatchCheck(), BrandUrgencyCheck(), HiddenElementsCheck(), AutoDownloadCheck(),
    CloakingCheck(), DisplayMismatchCheck(),
)
EXPECTED_CHECKS = 20
assert [c.spec.position for c in ALL_CHECKS] == list(range(1, EXPECTED_CHECKS + 1)), "check positions must be 1..20 in order"
assert len({c.spec.id for c in ALL_CHECKS}) == EXPECTED_CHECKS, "check ids must be unique"

CATEGORY_LABELS = {
    "address": "The address itself",
    "journey": "Where it really goes",
    "reputation": "Who is behind it",
    "behavior": "What the page does",
}


def specs() -> tuple[CheckSpec, ...]:
    return tuple(c.spec for c in ALL_CHECKS)

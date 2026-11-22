"""Public Suffix List access, offline (bundled snapshot; no network at runtime).

Private-section suffixes (github.io, pages.dev, workers.dev...) are treated as public suffixes, so
`evil.github.io` is its own registrable domain - essential for spotting abuse of free hosting.
"""
from __future__ import annotations

from functools import lru_cache
from typing import NamedTuple

import tldextract


class HostParts(NamedTuple):
    subdomain: str      # "login.paypal.com" for login.paypal.com.evil.co.uk
    label: str          # "evil"
    suffix: str         # "co.uk"

    @property
    def registrable(self) -> str:
        return f"{self.label}.{self.suffix}" if self.suffix and self.label else (self.label or "")

    @property
    def subdomain_labels(self) -> tuple[str, ...]:
        return tuple(p for p in self.subdomain.split(".") if p)


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


@lru_cache(maxsize=4096)
def split_host(host: str) -> HostParts:
    r = _extractor()(host)
    if not r.suffix and "." in host:
        # TLD unknown to the bundled list (new gTLD, reserved .example/.test): treat the last label as the TLD so
        # "paypa1-login.example" is still split into label + suffix rather than hiding the label from every check.
        labels = host.split(".")
        return HostParts(".".join(labels[:-2]), labels[-2], labels[-1])
    return HostParts(r.subdomain, r.domain, r.suffix)


def registrable_domain(host: str) -> str:
    return split_host(host).registrable or host

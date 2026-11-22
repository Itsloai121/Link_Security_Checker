"""Outbound network policy: the scanner must never be usable as a proxy into private networks (SSRF).

USSA pillar 9 (restrict outbound traffic) and pillar 3/4 (validate third-party data, redirects).
Rules are enforced on the *resolved IP*, at connect time, so DNS rebinding cannot swap the target.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field

DEFAULT_ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})


class BlockedDestination(Exception):
    """Raised when a destination is refused by policy. `reason` is safe to show to end users."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _embedded_v4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    out: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped:
        out.append(ip.ipv4_mapped)
    if ip.sixtofour:
        out.append(ip.sixtofour)
    n = int(ip)
    if (n >> 32) == int(ipaddress.IPv6Address("64:ff9b::")) >> 32:  # NAT64 well-known prefix 64:ff9b::/96
        out.append(ipaddress.IPv4Address(n & 0xFFFFFFFF))
    return out


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally routable unicast addresses (embedded IPv4 inside IPv6 is checked too)."""
    if ip.is_multicast or not ip.is_global:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in ipaddress.ip_network("2001::/32"):  # Teredo tunnelling: embedded address is obfuscated
            return False
        return all(is_public_ip(v4) for v4 in _embedded_v4(ip))
    return True


@dataclass(frozen=True)
class NetworkPolicy:
    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS
    allow_private_networks: bool = False  # tests only; production settings refuse to enable it

    def check_port(self, port: int) -> None:
        if port not in self.allowed_ports:
            raise BlockedDestination(f"Port {port} is not on the scanner's allowed list, so the page was not fetched.")

    def check_ip(self, ip_text: str) -> None:
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise BlockedDestination("The destination is not a valid IP address.") from exc
        if not self.allow_private_networks and not is_public_ip(ip):
            raise BlockedDestination(
                "The address points to a private, local or reserved network, so the scanner refused to connect."
            )


@dataclass
class GuardedResolver:
    """Resolves a host and returns *only* addresses that satisfy the policy (all-or-nothing)."""

    policy: NetworkPolicy
    timeout: float = 4.0
    _cache: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)

    async def resolve(self, host: str, port: int = 443) -> list[str]:
        host = host.strip("[]")
        try:
            ipaddress.ip_address(host)
            self.policy.check_ip(host)
            return [host]
        except ValueError:
            pass  # not an IP literal: do a DNS lookup
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=self.timeout
            )
        except TimeoutError as exc:
            raise DnsFailure("timeout", "DNS lookup timed out.") from exc
        except socket.gaierror as exc:
            kind = "nxdomain" if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)) else "servfail"
            raise DnsFailure(kind, "The domain name does not resolve." if kind == "nxdomain" else "DNS lookup failed.") from exc
        ips: list[str] = []
        for info in infos:
            ip = info[4][0].split("%")[0]
            if ip not in ips:
                ips.append(ip)
        if not ips:
            raise DnsFailure("nxdomain", "The domain name does not resolve.")
        for ip in ips:  # any non-public answer poisons the whole result (mixed-answer rebinding defence)
            self.policy.check_ip(ip)
        return ips


class DnsFailure(Exception):
    def __init__(self, kind: str, reason: str):
        super().__init__(reason)
        self.kind = kind  # 'nxdomain' | 'timeout' | 'servfail'
        self.reason = reason

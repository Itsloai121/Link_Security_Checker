from __future__ import annotations

import ipaddress


# RFC 6052 well-known NAT64 prefix. A globally-routed address in this prefix
# can still encode a non-public IPv4 destination, so classify the embedded IPv4.
_WELL_KNOWN_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")


def is_public_ip(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True only when an IP and any embedded IPv4 destination are global."""
    try:
        address = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(value.split("%", 1)[0])
    except (ValueError, AttributeError):
        return False

    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped.is_global
        if address in _WELL_KNOWN_NAT64:
            embedded_ipv4 = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
            return embedded_ipv4.is_global
        # Do not permit transition mechanisms to obscure their IPv4 endpoint.
        if address.sixtofour is not None or address.teredo is not None:
            return False

    return address.is_global

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin

import dns.exception
import dns.resolver

from .errors import InspectionError, PolicyBlocked
from .ip_policy import is_public_ip
from .url_analysis import normalize_url


MAX_RESPONSE_BYTES = 384 * 1024
_TLS_CONTEXT = ssl.create_default_context()


@dataclass(frozen=True, slots=True)
class SafeResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool
    url: str


def resolve_public(host: str, *, timeout: float = 1.35) -> list[tuple[str, int]]:
    """Resolve A and AAAA with deadlines and reject the whole set if any answer is non-public."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not is_public_ip(str(literal)):
            raise PolicyBlocked("The destination is not a public internet address.")
        return [(str(literal), literal.version)]

    if timeout <= 0:
        raise InspectionError("DNS lookup time limit was reached.")
    deadline = time.monotonic() + timeout
    addresses: set[tuple[str, int]] = set()
    resolver = dns.resolver.Resolver(configure=True)
    for record_type, family in (("A", 4), ("AAAA", 6)):
        remaining = deadline - time.monotonic()
        if remaining <= 0.02:
            raise InspectionError("DNS lookup failed or timed out.")
        resolver.timeout = min(0.65, remaining)
        resolver.lifetime = remaining
        try:
            answers = resolver.resolve(host, record_type, lifetime=remaining, search=False, raise_on_no_answer=False)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (dns.exception.DNSException, OSError) as exc:
            # A timeout on either family could hide an unsafe alternate address.
            raise InspectionError("DNS lookup failed or timed out.") from exc
        for answer in answers:
            value = answer.address
            if not is_public_ip(value):
                raise PolicyBlocked("The host did not resolve exclusively to public internet addresses.")
            addresses.add((str(ipaddress.ip_address(value)), family))
    if not addresses:
        raise InspectionError("The host did not resolve to a public internet address.")
    return sorted(addresses)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._validated_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._validated_address, self.port), self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float):
        super().__init__(host, port=port, timeout=timeout, context=_TLS_CONTEXT)
        self._validated_address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._validated_address, self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def request_public(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
    timeout: float = 3.0,
) -> SafeResponse:
    if method not in {"GET", "HEAD", "POST"}:
        raise ValueError("Outbound request method is not allowed.")
    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= 1024 * 1024:
        raise ValueError("Outbound response byte limit is invalid.")
    if not 0.1 <= timeout <= 30:
        raise ValueError("Outbound request timeout is invalid.")
    deadline = time.monotonic() + timeout
    parsed, host, normalized = normalize_url(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if (parsed.scheme == "https" and port != 443) or (parsed.scheme == "http" and port != 80):
        raise PolicyBlocked("Non-standard destination ports are blocked for live inspection.")
    addresses = resolve_public(host, timeout=min(1.35, max(0.1, timeout * 0.5)))
    remaining = deadline - time.monotonic()
    if remaining <= 0.05:
        raise InspectionError("The destination inspection time limit was reached.")
    address, _family = addresses[0]
    cls = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
    connection = cls(host, address, port, remaining)
    # A hard wall-clock cutoff also stops a peer that drips headers or body bytes slowly.
    cutoff = threading.Timer(remaining, connection.close)
    cutoff.daemon = True
    request_headers = {
        "User-Agent": "LinkSafety/0.3 security-screening",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.1",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if headers:
        # Callers may add provider-specific headers, but cannot change routing or TLS policy.
        blocked = {"host", "connection", "content-length", "proxy-authorization", "proxy-connection", "transfer-encoding"}
        for key, value in headers.items():
            normalized_key = key.lower().strip()
            if normalized_key in blocked:
                continue
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", normalized_key):
                raise ValueError("Outbound request header name is invalid.")
            header_value = str(value)
            if any((ord(character) < 0x20 and character != "\t") or ord(character) == 0x7f for character in header_value):
                raise ValueError("Outbound request header value is invalid.")
            request_headers[normalized_key] = header_value
    request_target = parsed.path or "/"
    if parsed.query:
        request_target += "?" + parsed.query
    try:
        cutoff.start()
        connection.request(method, request_target, body=body, headers=request_headers)
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        payload = response.read(max_bytes + 1)
        truncated = len(payload) > max_bytes
        if truncated:
            payload = payload[:max_bytes]
        return SafeResponse(response.status, response_headers, payload, truncated, normalized)
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
        raise InspectionError(_safe_network_error(exc)) from exc
    finally:
        cutoff.cancel()
        connection.close()


def follow_redirects(url: str, *, max_hops: int = 5, max_bytes: int = MAX_RESPONSE_BYTES,
                     timeout: float = 7.5, request_timeout: float = 2.5,
                     user_agent: str | None = None) -> tuple[SafeResponse, list[tuple[str, str, str, str]], str]:
    _parsed, _host, current = normalize_url(url)
    redirects: list[tuple[str, str, str, str]] = []
    deadline = time.monotonic() + timeout
    for hop in range(max_hops + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0.1:
            raise InspectionError("The destination inspection time limit was reached.")
        response = request_public(current, max_bytes=max_bytes, timeout=min(request_timeout, remaining),
                                  headers={"User-Agent": user_agent} if user_agent else None)
        location = response.headers.get("location", "")
        if 300 <= response.status < 400 and location:
            if hop >= max_hops:
                raise InspectionError("The redirect limit was reached.")
            try:
                next_url = urljoin(current, location)
                next_parsed, next_host, normalized_next = normalize_url(next_url)
            except ValueError as exc:
                raise PolicyBlocked("A redirect target did not meet the public HTTP/HTTPS policy.") from exc
            current_parsed, current_host, _ = normalize_url(current)
            redirects.append((current_host, next_host, current_parsed.scheme, next_parsed.scheme))
            current = normalized_next
            continue
        return response, redirects, current
    raise InspectionError("The redirect limit was reached.")


def _safe_network_error(error: BaseException) -> str:
    code = getattr(error, "reason", None) or getattr(error, "errno", None)
    if isinstance(code, str) and code.isascii() and len(code) < 80:
        return f"Network request failed ({code})."
    name = type(error).__name__
    return f"Network request failed ({name})."

"""Bounded, SSRF-safe HTTP client built directly on httpcore.

* Redirects are NEVER followed here - the caller walks the chain and records every hop.
* The TCP connection goes to the IP validated by GuardedResolver; the original hostname is still used
  for SNI, certificate verification and the Host header.
* Hard limits: connect/read timeouts, total deadline, maximum bytes read. Content is never executed,
  never written to disk.
"""
from __future__ import annotations

import asyncio
import ssl
import time
import zlib
from dataclasses import dataclass
from collections.abc import Callable
from urllib.parse import urlsplit

import httpcore

from infrastructure.external_services.network_policy import BlockedDestination, GuardedResolver, NetworkPolicy

USER_AGENTS = {
    "scanner": "UnmaskLinkScanner/1.0 (+security link analysis; does not execute page code)",
    "browser": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36",
}


class FetchError(Exception):
    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind = kind  # blocked | dns | connect | tls | timeout | protocol
        self.detail = detail


@dataclass(frozen=True)
class RawResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool
    elapsed_ms: int
    insecure_tls: bool = False  # True when certificate verification failed and we re-fetched without it


class _GuardedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, resolver: GuardedResolver):
        self._resolver = resolver
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        ips = await self._resolver.resolve(host, port)
        last: Exception | None = None
        for ip in ips:
            try:
                return await self._inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address,
                                                     socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last or httpcore.ConnectError("no address could be reached")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
        raise BlockedDestination("Unix sockets are not allowed.")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _bounded_decode(body: bytes, encoding: str, limit: int) -> bytes:
    wbits = {"gzip": 16 + zlib.MAX_WBITS, "x-gzip": 16 + zlib.MAX_WBITS, "deflate": zlib.MAX_WBITS}.get(encoding)
    if wbits is None:
        return body
    try:
        d = zlib.decompressobj(wbits)
        return d.decompress(body, limit)  # bounded: defeats decompression bombs
    except zlib.error:
        return body


def _cause_chain(exc: BaseException):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


class GuardedHttpClient:
    def __init__(self, policy: NetworkPolicy, resolver: GuardedResolver | None = None, *,
                 connect_timeout: float = 5.0, read_timeout: float = 8.0, max_connections: int = 32):
        self.policy = policy
        self._resolver = resolver or GuardedResolver(policy)
        self._timeouts = {"connect": connect_timeout, "read": read_timeout, "write": 5.0, "pool": 5.0}
        backend = _GuardedBackend(self._resolver)
        common = dict(max_connections=max_connections, max_keepalive_connections=0, http1=True, http2=False,
                      network_backend=backend)
        self._verifying = httpcore.AsyncConnectionPool(ssl_context=ssl.create_default_context(), **common)
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        self._insecure = httpcore.AsyncConnectionPool(ssl_context=insecure, **common)

    async def aclose(self) -> None:
        await self._verifying.aclose()
        await self._insecure.aclose()

    async def request(self, method: str, url: str, *, headers: dict[str, str] | None = None, max_bytes: int = 1_500_000,
                      total_timeout: float = 15.0, read_body: bool = True, allow_insecure_retry: bool = True,
                      body: bytes | None = None, body_limit: Callable[[dict[str, str]], int] | None = None) -> RawResponse:
        """`body_limit(headers) -> bytes` lets the caller read far less of non-HTML responses (e.g. a 2 GB download)."""
        try:
            return await asyncio.wait_for(
                self._request(method, url, headers or {}, max_bytes, read_body, allow_insecure_retry, False, body, body_limit), total_timeout)
        except TimeoutError as exc:
            raise FetchError("timeout", "The server took too long to answer.") from exc

    async def _request(self, method, url, headers, max_bytes, read_body, allow_retry, insecure, body=None, body_limit=None) -> RawResponse:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            raise BlockedDestination("Only http and https addresses can be fetched.")
        port = parts.port or (443 if scheme == "https" else 80)
        self.policy.check_port(port)
        host = parts.hostname
        default = 443 if scheme == "https" else 80
        host_header = host if port == default else f"{host}:{port}"
        if ":" in host:  # IPv6 literal
            host_header = f"[{host}]" + ("" if port == default else f":{port}")
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        hdrs = [(b"Host", host_header.encode()), (b"Accept-Encoding", b"identity"),
                (b"Accept", b"text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"), (b"Connection", b"close")]
        hdrs += [(k.encode(), v.encode("latin-1", "ignore")) for k, v in headers.items()]
        if body is not None:
            hdrs.append((b"Content-Length", str(len(body)).encode()))
        origin = httpcore.URL(scheme=scheme.encode(), host=host.encode(), port=port, target=target.encode())
        pool = self._insecure if insecure else self._verifying
        started = time.monotonic()
        buf = bytearray()
        truncated = False
        try:
            async with pool.stream(method, origin, headers=hdrs, content=body, extensions={"timeout": self._timeouts}) as resp:
                status = resp.status
                out_headers: dict[str, str] = {}
                for k, v in resp.headers:
                    key = k.decode("latin-1").lower()
                    val = v.decode("latin-1")
                    out_headers[key] = f"{out_headers[key]}, {val}" if key in out_headers else val
                if read_body and method.upper() != "HEAD":
                    limit = min(max_bytes, body_limit(out_headers)) if body_limit else max_bytes
                    async for chunk in resp.aiter_stream():
                        buf += chunk
                        if len(buf) >= limit:
                            truncated = True
                            break
                    max_bytes = limit
        except BlockedDestination:
            raise
        except (httpcore.ConnectTimeout, httpcore.ReadTimeout, httpcore.WriteTimeout, httpcore.PoolTimeout) as exc:
            raise FetchError("timeout", "The server took too long to answer.") from exc
        except (httpcore.ConnectError, httpcore.ReadError, httpcore.RemoteProtocolError, httpcore.WriteError) as exc:
            tls_err = next((c for c in _cause_chain(exc) if isinstance(c, ssl.SSLError)), None)
            if tls_err is not None:
                if allow_retry and not insecure and scheme == "https":
                    resp2 = await self._request(method, url, headers, max_bytes, read_body, False, True, body, body_limit)
                    return RawResponse(resp2.url, resp2.status, resp2.headers, resp2.body, resp2.truncated,
                                       resp2.elapsed_ms, insecure_tls=True)
                raise FetchError("tls", getattr(tls_err, "verify_message", None) or str(tls_err)) from exc
            from infrastructure.external_services.network_policy import DnsFailure
            dns_err = next((c for c in _cause_chain(exc) if isinstance(c, DnsFailure)), None)
            if dns_err is not None:
                raise FetchError("dns", dns_err.reason) from exc
            blocked = next((c for c in _cause_chain(exc) if isinstance(c, BlockedDestination)), None)
            if blocked is not None:
                raise blocked from exc
            raise FetchError("connect", "Could not connect to the server.") from exc
        except httpcore.UnsupportedProtocol as exc:
            raise BlockedDestination("Only http and https addresses can be fetched.") from exc
        except Exception as exc:
            from infrastructure.external_services.network_policy import DnsFailure
            if isinstance(exc, DnsFailure):
                raise FetchError("dns", exc.reason) from exc
            raise FetchError("protocol", f"Unexpected response: {type(exc).__name__}") from exc
        data = bytes(buf[:max_bytes])
        enc = out_headers.get("content-encoding", "").lower().strip()
        if enc in ("gzip", "x-gzip", "deflate"):
            data = _bounded_decode(data, enc, max_bytes)
        return RawResponse(url, status, out_headers, data, truncated, int((time.monotonic() - started) * 1000), insecure)

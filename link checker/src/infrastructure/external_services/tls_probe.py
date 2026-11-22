"""TLS handshake probe: fetches the certificate even when verification fails, so the report can explain *why*."""
from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass

from infrastructure.external_services.network_policy import BlockedDestination, DnsFailure, GuardedResolver


@dataclass(frozen=True)
class TlsProbeResult:
    handshake_ok: bool
    verified: bool
    verify_error: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    cert_der: bytes | None = None
    error: str | None = None


async def _handshake(ip: str, port: int, host: str, verify: bool, timeout: float):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host), timeout)
    try:
        obj = writer.get_extra_info("ssl_object")
        cipher = obj.cipher()
        return obj.version(), (cipher[0] if cipher else None), obj.getpeercert(binary_form=True)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except Exception:  # pragma: no cover - best effort close
            pass


async def probe_tls(host: str, port: int, resolver: GuardedResolver, *, timeout: float = 6.0) -> TlsProbeResult:
    try:
        ips = await resolver.resolve(host, port)
    except BlockedDestination as exc:
        return TlsProbeResult(False, False, error=exc.reason)
    except DnsFailure as exc:
        return TlsProbeResult(False, False, error=exc.reason)
    last_error = "Could not connect."
    for ip in ips[:2]:
        try:
            proto, cipher, der = await _handshake(ip, port, host, True, timeout)
            return TlsProbeResult(True, True, None, proto, cipher, der)
        except ssl.SSLCertVerificationError as exc:
            reason = exc.verify_message or str(exc)
            try:
                proto, cipher, der = await _handshake(ip, port, host, False, timeout)
                return TlsProbeResult(True, False, reason, proto, cipher, der)
            except Exception as exc2:  # handshake impossible even without verification
                return TlsProbeResult(False, False, reason, error=str(exc2)[:200])
        except ssl.SSLError as exc:
            last_error = f"TLS handshake failed: {exc.reason or exc}"
        except TimeoutError:
            last_error = "Connection timed out."
        except OSError as exc:
            last_error = f"Could not connect ({exc.__class__.__name__})."
    return TlsProbeResult(False, False, error=last_error)

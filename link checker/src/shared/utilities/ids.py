"""Identifier generation. Scan IDs double as bearer capabilities, so they come from a CSPRNG (128 bits)."""
from __future__ import annotations

import re
import secrets

SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class SecureIdGenerator:
    def new_scan_id(self) -> str:
        return secrets.token_urlsafe(16)  # 16 bytes -> 22 url-safe chars

    def new_request_id(self) -> str:
        return "req_" + secrets.token_hex(8)


def is_valid_scan_id(value: str) -> bool:
    return bool(SCAN_ID_RE.fullmatch(value))

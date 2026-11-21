from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _read_env_file(path: Path) -> dict[str, str]:
    """Read simple KEY=VALUE lines without shell expansion."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Invalid .env entry on line {line_number}.")
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not ENV_NAME.fullmatch(name):
            raise ValueError(f"Invalid .env variable name on line {line_number}.")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if any(ord(character) < 0x20 for character in value):
            raise ValueError(f"Invalid control character in .env value on line {line_number}.")
        values[name] = value
    return values


def load_env_file(path: Path) -> None:
    """Load simple KEY=VALUE lines without shell expansion or overriding the process env."""
    for name, value in _read_env_file(path).items():
        os.environ.setdefault(name, value)


def _integer(env: dict[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    raw = env.get(name, "")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}.") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}.")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    bind_address: str
    port: int
    database_path: str
    max_body_bytes: int
    max_url_length: int
    rate_limit_window_ms: int
    rate_limit_max_requests: int
    data_retention_days: int
    phishtank_app_key: str
    max_concurrent_scans: int
    allowed_hosts: tuple[str, ...]
    project_root: Path = PROJECT_ROOT


def load_settings(*, env_file: Path | None = None, environ: dict[str, str] | None = None) -> Settings:
    # Explicit process values always win over .env values. Keeping the supplied
    # environ isolated also makes tests deterministic and avoids mutating globals.
    source = dict(os.environ if environ is None else environ)
    file_values = _read_env_file(env_file or PROJECT_ROOT / ".env")
    env = {**file_values, **source}
    environment = env.get("NODE_ENV", "development")
    if environment not in {"development", "test", "production"}:
        raise ValueError("NODE_ENV must be development, test, or production.")

    bind_address = env.get("BIND_ADDRESS", "127.0.0.1").strip()
    try:
        ipaddress.ip_address(bind_address)
    except ValueError as exc:
        raise ValueError("BIND_ADDRESS must be an IPv4 or IPv6 address.") from exc

    database_setting = env.get("DATABASE_PATH", "./var/link-safety.sqlite").strip()
    if not database_setting:
        raise ValueError("DATABASE_PATH must be a non-empty file path or :memory:.")
    if database_setting == ":memory:":
        database_path = database_setting
    else:
        candidate = Path(database_setting)
        candidate = candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
        if candidate.is_symlink():
            raise ValueError("DATABASE_PATH must not be a symbolic link.")
        database_path = str(candidate.resolve())

    allowed_hosts = tuple(dict.fromkeys(
        host.strip().lower().rstrip(".")
        for host in env.get("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
        if host.strip()
    ))
    if not allowed_hosts or "*" in allowed_hosts:
        raise ValueError("ALLOWED_HOSTS must contain explicit host names; wildcards are not allowed.")
    for host in allowed_hosts:
        candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass
        labels = candidate.split(".")
        if len(candidate) > 253 or not labels or any(
            not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("ALLOWED_HOSTS contains an invalid host name.")
    phishtank_app_key = env.get("PHISHTANK_APP_KEY", "").strip()
    if len(phishtank_app_key) > 256 or any(ord(character) < 0x20 for character in phishtank_app_key):
        raise ValueError("PHISHTANK_APP_KEY is invalid.")

    return Settings(
        environment=environment,
        bind_address=bind_address,
        port=_integer(env, "PORT", 3000, 1, 65535),
        database_path=database_path,
        max_body_bytes=_integer(env, "MAX_BODY_BYTES", 8192, 1024, 65536),
        max_url_length=_integer(env, "MAX_URL_LENGTH", 4096, 128, 16384),
        rate_limit_window_ms=_integer(env, "RATE_LIMIT_WINDOW_MS", 60000, 1000, 3600000),
        rate_limit_max_requests=_integer(env, "RATE_LIMIT_MAX_REQUESTS", 20, 1, 10000),
        data_retention_days=_integer(env, "DATA_RETENTION_DAYS", 30, 1, 3650),
        phishtank_app_key=phishtank_app_key,
        max_concurrent_scans=_integer(env, "MAX_CONCURRENT_SCANS", 2, 1, 16),
        allowed_hosts=allowed_hosts,
    )

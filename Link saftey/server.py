from __future__ import annotations

import os
import sys

import uvicorn

from backend.link_safety.api import create_app
from backend.link_safety.config import load_settings


def main() -> None:
    # SQLite files, WAL sidecars, and any future local state should not be
    # readable by other POSIX users on the same machine.
    if os.name == "posix":
        os.umask(0o077)
    config = load_settings()
    app = create_app(config)
    uvicorn.run(
        app,
        host=config.bind_address,
        port=config.port,
        log_config=None,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        date_header=True,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=10,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"Startup failed ({type(exc).__name__}).", file=sys.stderr, flush=True)
        raise SystemExit(1) from exc

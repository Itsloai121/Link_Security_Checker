"""Serves the three pages and their static files. Same origin as the API, so no CORS is ever needed."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from starlette.staticfiles import StaticFiles

PAGES = {"/": "index.html", "/process": "process.html", "/analysis": "analysis.html"}
STATIC_DIRS = ("components", "state", "api_client", "styles", "pages")


class CachedStatic(StaticFiles):
    def __init__(self, *args, max_age: int = 0, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = f"public, max-age={max_age}" if max_age else "no-cache"

    def file_response(self, *args, **kwargs):
        resp = super().file_response(*args, **kwargs)
        resp.headers["Cache-Control"] = self._cache
        return resp


def mount_web(app: FastAPI, web_dir: Path, assets_dir: Path, *, max_age: int) -> None:
    def make(path: Path):
        async def page() -> FileResponse:
            return FileResponse(path, media_type="text/html; charset=utf-8", headers={"Cache-Control": "no-cache"})
        return page

    for route, name in PAGES.items():
        app.add_api_route(route, make(web_dir / "pages" / name), methods=["GET"], include_in_schema=False)
    favicon = assets_dir / "images" / "favicon.svg"

    async def favicon_route() -> FileResponse:
        return FileResponse(favicon, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})

    app.add_api_route("/favicon.ico", favicon_route, methods=["GET"], include_in_schema=False)
    for sub in STATIC_DIRS:
        app.mount(f"/static/{sub}", CachedStatic(directory=web_dir / sub, max_age=max_age), name=f"static-{sub}")
    app.mount("/assets", CachedStatic(directory=assets_dir, max_age=max_age), name="assets")

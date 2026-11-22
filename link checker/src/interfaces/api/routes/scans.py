from __future__ import annotations

from fastapi import APIRouter, Request, Response

from bootstrap.dependency_wiring import Container
from interfaces.api.handlers import scans as handlers
from interfaces.api.schemas.scans import CheckCatalogOut, ErrorResponse, ScanOut, SubmitScanRequest

router = APIRouter(prefix="/api/v1", tags=["scans"])
_ERR = {429: {"model": ErrorResponse}, 503: {"model": ErrorResponse}, 422: {"model": ErrorResponse}}


def _c(request: Request) -> Container:
    return request.app.state.container


def _key(request: Request) -> str:
    c = _c(request)
    peer = request.client.host if request.client else None
    return handlers.client_key(peer, request.headers.get("x-forwarded-for"), c.settings.trusted_proxy_hops)


@router.post("/scans", status_code=202, response_model=ScanOut, responses=_ERR, summary="Submit a link for analysis")
async def submit_scan(payload: SubmitScanRequest, request: Request, response: Response) -> ScanOut:
    out = await handlers.submit_scan(_c(request), payload, _key(request))
    response.headers["Location"] = f"/api/v1/scans/{out.id}"
    return out


@router.get("/scans/{scan_id}", response_model=ScanOut, responses={404: {"model": ErrorResponse}, 429: {"model": ErrorResponse}}, summary="Read a report (poll until status is completed)")
async def read_scan(scan_id: str, request: Request) -> ScanOut:
    return await handlers.get_scan(_c(request), scan_id[:64], _key(request))


@router.delete("/scans/{scan_id}", status_code=204, responses={404: {"model": ErrorResponse}}, summary="Delete a report now")
async def delete_scan(scan_id: str, request: Request) -> Response:
    await handlers.delete_scan(_c(request), scan_id[:64], _key(request))
    return Response(status_code=204)


@router.get("/checks", response_model=CheckCatalogOut, summary="The 20 tests and what each one does")
async def list_checks(request: Request, response: Response) -> CheckCatalogOut:
    response.headers["Cache-Control"] = "public, max-age=3600"
    return handlers.check_catalog(_c(request))

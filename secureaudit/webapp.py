"""Local web dashboard (127.0.0.1 only) — full SecureAudit UI."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from secureaudit.paths import data_root
from secureaudit.scans import build_alert_for_scan, run_bundle_scan, send_alert_from_scan

_STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="SecureAudit AI",
    description="Privacy-preserving local audit dashboard",
    version="0.1.0",
)


@app.get("/api/health")
def api_health() -> dict[str, str]:
    return {"status": "ok", "service": "secureaudit-ai"}


@app.get("/api/config")
def api_config() -> dict[str, object]:
    root = data_root()
    files = sorted(p.name for p in root.iterdir() if p.is_file()) if root.is_dir() else []
    return {"data_root": str(root), "files": files}


@app.get("/api/scan/full")
def api_scan_full() -> dict[str, object]:
    return run_bundle_scan()


class ScanRequest(BaseModel):
    selected_files: list[str] = Field(default_factory=list)


@app.post("/api/scan/full")
def api_scan_full_selected(body: ScanRequest) -> dict[str, object]:
    return run_bundle_scan(selected_files=body.selected_files)


class AlertRequest(BaseModel):
    webhook_url: str = ""
    dry_run: bool = Field(default=True, description="If true, validate only; no HTTP POST.")
    selected_files: list[str] = Field(default_factory=list)


@app.post("/api/alert")
def api_alert(body: AlertRequest) -> dict[str, object]:
    bundle = run_bundle_scan(selected_files=body.selected_files)
    dup_n = int(bundle["duplicate_group_count"])
    rbac_n = int(bundle["rbac_finding_count"])
    return send_alert_from_scan(
        dup_n,
        rbac_n,
        webhook_url=body.webhook_url.strip(),
        dry_run=body.dry_run,
    )


@app.get("/")
def index() -> FileResponse:
    index_path = _STATIC / "index.html"
    if not index_path.is_file():
        raise HTTPException(status_code=500, detail="static/index.html missing")
    return FileResponse(index_path)


if _STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="SecureAudit AI web dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("SECUREAUDIT_PORT", "8750")))
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")

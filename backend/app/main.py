from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .database import connect, initialize_database
from .services import (
    add_case_note,
    get_finding,
    intelligence_status,
    list_assets,
    list_cases,
    list_findings,
    overview,
    refresh_intelligence,
    run_detection,
    update_case,
)


class DetectionRequest(BaseModel):
    mode: str = Field(default="demo", pattern="^(demo|live)$")


class CaseUpdate(BaseModel):
    status: str | None = None
    assignee: str | None = Field(default=None, max_length=120)


class NoteRequest(BaseModel):
    text: str = Field(min_length=1, max_length=2000)
    author: str = Field(default="Analyst", max_length=80)


def create_app(db_path: str | Path | None = None) -> FastAPI:
    initialize_database(db_path)
    app = FastAPI(
        title="OQVIAN VULNORBIT API",
        version="0.1.0",
        description="Local-first vulnerability intelligence demo using fictional inventory.",
    )
    app.state.db_path = str(db_path) if db_path else None
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:4173"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type"],
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "local_demo"}

    @app.get("/api/overview")
    def overview_route() -> dict[str, Any]:
        return overview(app.state.db_path)

    @app.get("/api/assets")
    def assets_route(organization_id: str | None = None) -> list[dict[str, Any]]:
        return list_assets(app.state.db_path, organization_id)

    @app.get("/api/intelligence/status")
    def intelligence_status_route() -> list[dict[str, Any]]:
        return intelligence_status(app.state.db_path)

    @app.post("/api/intelligence/refresh")
    def refresh_route() -> dict[str, Any]:
        return refresh_intelligence(app.state.db_path)

    @app.post("/api/detection/run")
    def detection_route(request: DetectionRequest) -> dict[str, Any]:
        return run_detection(app.state.db_path, request.mode)

    @app.get("/api/findings")
    def findings_route() -> list[dict[str, Any]]:
        return list_findings(app.state.db_path)

    @app.get("/api/findings/{finding_id}")
    def finding_route(finding_id: str) -> dict[str, Any]:
        result = get_finding(finding_id, app.state.db_path)
        if result is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return result

    @app.get("/api/cases")
    def cases_route() -> list[dict[str, Any]]:
        return list_cases(app.state.db_path)

    @app.patch("/api/cases/{case_id}")
    def case_update_route(case_id: str, request: CaseUpdate) -> dict[str, Any]:
        try:
            result = update_case(case_id, request.status, request.assignee, app.state.db_path)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return result

    @app.post("/api/cases/{case_id}/notes")
    def case_note_route(case_id: str, request: NoteRequest) -> dict[str, Any]:
        try:
            result = add_case_note(case_id, request.text, request.author, app.state.db_path)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return result

    @app.post("/api/demo/reset")
    def reset_demo() -> dict[str, str]:
        with connect(app.state.db_path) as connection:
            connection.execute("DELETE FROM scan_runs")
            connection.execute("DELETE FROM cases")
            connection.execute("DELETE FROM findings")
            connection.execute("DELETE FROM components")
            connection.execute("DELETE FROM assets")
            connection.execute("DELETE FROM organizations")
            connection.execute("DELETE FROM source_cache")
            connection.execute("DELETE FROM feed_state")
            connection.execute("DELETE FROM advisories")
            connection.execute("DELETE FROM audit_events")
        initialize_database(app.state.db_path)
        return {"status": "reset", "message": "Fictional demo inventory restored; run detection to recreate findings."}

    frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
    if frontend_dir.is_dir():
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="dashboard")

    return app


app = create_app()

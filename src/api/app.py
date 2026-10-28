"""
FastAPI application — main entry point.

POST /analyze  — accepts file uploads or text/URL submissions
GET  /report/{submission_id}  — retrieve a stored report
GET  /health   — liveness check
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from src.core.intake import MediaType, detect_media_type, is_url_submission
from src.core.schemas import AnalysisReport
from src.core.verdict_engine import compute_verdict
from src.engines.image_engine import run_image_engine
from src.engines.audio_engine import run_audio_engine
from src.engines.pdf_engine import run_pdf_engine
from src.engines.text_engine import run_text_engine
from src.engines.osint_engine import run_osint_engine
from src.report.generator import render_markdown, render_json, build_risk_text

app = FastAPI(
    title="Digital Authenticity & AI Detection Analyst",
    description="Multi-modal forensic authenticity checker for images, audio, PDFs, text, and social profiles.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the HTML frontend
_FRONTEND = Path(__file__).parent.parent.parent / "frontend"
if _FRONTEND.exists():
    app.mount("/ui", StaticFiles(directory=str(_FRONTEND), html=True), name="frontend")

@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(str(_FRONTEND / "index.html"))

# In-memory store (replace with DB in production)
_report_store: dict[str, AnalysisReport] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


# ─────────────────────────────────────────────────────────────────────────────
# Analyze Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze(
    file: Annotated[UploadFile | None, File(description="Upload a file (image, PDF, audio, document)")] = None,
    text: Annotated[str | None, Form(description="Raw text / email / article to analyze")] = None,
    url: Annotated[str | None, Form(description="URL or social profile link to investigate")] = None,
    context: Annotated[str, Form(description="Where did this come from? What does it claim to be?")] = "",
    output_format: Annotated[str, Form(description="Response format: json | markdown")] = "markdown",
):
    submission_id = str(uuid.uuid4())[:8]
    engine_results = []
    filename = None
    media_type = MediaType.UNKNOWN

    # ── Route to engines ─────────────────────────────────────────────────────

    if file and file.filename:
        filename = file.filename
        file_bytes = await file.read()
        media_type = detect_media_type(
            filename=file.filename,
            raw_bytes=file_bytes,
            mime_hint=file.content_type,
        )
        if media_type == MediaType.IMAGE:
            engine_results.append(run_image_engine(file_bytes, filename))
        elif media_type == MediaType.AUDIO:
            engine_results.append(run_audio_engine(file_bytes, filename))
        elif media_type == MediaType.PDF:
            engine_results.append(run_pdf_engine(file_bytes, filename))
        elif media_type == MediaType.VIDEO:
            # Video handled as image-engine for static-frame checks; full video TBD
            engine_results.append(run_image_engine(file_bytes, filename))
        else:
            # Unknown binary — attempt PDF then image
            engine_results.append(run_pdf_engine(file_bytes, filename))

    if text:
        media_type = MediaType.EMAIL if "@" in text[:500] and "Received:" in text else MediaType.TEXT
        engine_results.append(run_text_engine(text))

    if url:
        media_type = MediaType.URL
        engine_results.append(run_osint_engine(url=url, context=context))

    if not engine_results:
        raise HTTPException(status_code=422, detail="Provide at least one of: file, text, or url.")

    # ── Verdict & Report ─────────────────────────────────────────────────────
    verdict = compute_verdict(engine_results)
    all_evidence = [e for r in engine_results for e in r.evidence]
    all_checks_done = [c for r in engine_results for c in r.checks_performed]
    all_checks_skipped = [c for r in engine_results for c in r.checks_skipped]

    report = AnalysisReport(
        submission_id=submission_id,
        media_type=media_type,
        filename=filename,
        verdict=verdict,
        evidence=all_evidence,
        checks_performed=all_checks_done,
        checks_skipped=all_checks_skipped,
        source_verification="See evidence table for web-sourced signals.",
        potential_risks="",
        how_to_verify="",
        engine_results=engine_results,
    )

    risks, verify = build_risk_text(report)
    report.potential_risks = risks
    report.how_to_verify = verify

    _report_store[submission_id] = report

    if output_format == "json":
        return JSONResponse(content=report.model_dump(mode="json"))
    return PlainTextResponse(content=render_markdown(report), media_type="text/markdown")


# ─────────────────────────────────────────────────────────────────────────────
# Retrieve Report
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/report/{submission_id}")
async def get_report(submission_id: str, output_format: str = "markdown"):
    report = _report_store.get(submission_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{submission_id}' not found.")
    if output_format == "json":
        return JSONResponse(content=report.model_dump(mode="json"))
    return PlainTextResponse(content=render_markdown(report), media_type="text/markdown")

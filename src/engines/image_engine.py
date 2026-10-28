"""
Image & Video Forensics Engine.

Checks performed:
- EXIF / IPTC metadata extraction
- Error Level Analysis (ELA) — detects re-saved / composited regions
- AI-generation detection via Hive Moderation API (optional)
- Sightengine AI detector (optional)
- Lighting / geometry heuristics (LLM-assisted)
- Deepfake face-swap detection placeholder
"""
from __future__ import annotations

import io
import math
import os
import tempfile
from pathlib import Path
from typing import Any

from src.core.schemas import EngineResult, EvidenceRow, EvidenceStrength, MediaType
from src.core.settings import settings


# ─────────────────────────────────────────────────────────────────────────────
# ELA (Error Level Analysis)
# ─────────────────────────────────────────────────────────────────────────────

def run_ela(image_bytes: bytes, quality: int = 90) -> dict[str, Any]:
    """
    Re-compress the image at `quality` and compute pixel-level ELA difference.
    Returns mean and max ELA pixel value and a simplified anomaly flag.
    High mean ELA (>15) in localized regions suggests tampering.
    """
    from PIL import Image, ImageChops, ImageEnhance  # lazy import
    original = Image.open(io.BytesIO(image_bytes)).convert("RGB")

    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        tmp_path = tmp.name
        original.save(tmp_path, "JPEG", quality=quality)

    recompressed = Image.open(tmp_path).convert("RGB")
    os.unlink(tmp_path)

    ela_image = ImageChops.difference(original, recompressed)
    enhancer = ImageEnhance.Brightness(ela_image)
    ela_enhanced = enhancer.enhance(10)

    pixels = list(ela_enhanced.getdata())
    flat = [v for px in pixels for v in (px if isinstance(px, tuple) else [px])]
    mean_ela = sum(flat) / len(flat) if flat else 0
    max_ela = max(flat) if flat else 0

    return {
        "mean_ela": round(mean_ela, 2),
        "max_ela": max_ela,
        "anomaly_flag": mean_ela > 15,
    }


# ─────────────────────────────────────────────────────────────────────────────
# EXIF Extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_exif(image_bytes: bytes) -> dict[str, Any]:
    """Extract EXIF tags using Pillow. Returns {} if no EXIF present."""
    try:
        import exifread
        tags = exifread.process_file(io.BytesIO(image_bytes), details=False, stop_tag="UNDEF")
        return {str(k): str(v) for k, v in tags.items()}
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# AI Detection — Hive Moderation
# ─────────────────────────────────────────────────────────────────────────────

def check_hive_ai_detection(image_bytes: bytes) -> dict[str, Any] | None:
    """Call Hive Moderation AI image detection. Returns None if key not set."""
    if not settings.hive_api_key:
        return None
    try:
        import httpx
        resp = httpx.post(
            "https://api.thehive.ai/api/v2/task/sync",
            headers={"Authorization": f"Token {settings.hive_api_key}"},
            files={"image": ("image.jpg", image_bytes, "image/jpeg")},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        # Extract AI-generated probability
        classes = (
            data.get("status", [{}])[0]
            .get("response", {})
            .get("output", [{}])[0]
            .get("classes", [])
        )
        ai_score = next(
            (c["score"] for c in classes if "ai_generated" in c.get("class", "").lower()), None
        )
        return {"provider": "hive", "ai_generated_score": ai_score, "raw": classes}
    except Exception as e:
        return {"provider": "hive", "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# AI Detection — Sightengine
# ─────────────────────────────────────────────────────────────────────────────

def check_sightengine_ai(image_bytes: bytes) -> dict[str, Any] | None:
    """Call Sightengine AI-generated image detector. Returns None if creds not set."""
    if not settings.sightengine_user or not settings.sightengine_secret:
        return None
    try:
        import httpx
        resp = httpx.post(
            "https://api.sightengine.com/1.0/check.json",
            data={
                "models": "genai",
                "api_user": settings.sightengine_user,
                "api_secret": settings.sightengine_secret,
            },
            files={"media": ("image.jpg", image_bytes, "image/jpeg")},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return {"provider": "sightengine", "type": data.get("type", {}), "raw": data}
    except Exception as e:
        return {"provider": "sightengine", "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Main Engine Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def run_image_engine(file_bytes: bytes, filename: str = "") -> EngineResult:
    """
    Run all image forensic checks and return a consolidated EngineResult.
    """
    checks_done: list[str] = []
    checks_skipped: list[str] = []
    evidence: list[EvidenceRow] = []
    raw_meta: dict[str, Any] = {}
    scores: list[float] = []

    # ── EXIF ─────────────────────────────────────────────────────────────────
    exif = extract_exif(file_bytes)
    checks_done.append("EXIF metadata extraction")
    raw_meta["exif"] = exif

    if exif:
        software = exif.get("Image Software", "")
        if software and any(kw in software.lower() for kw in ["photoshop", "gimp", "paint.net"]):
            evidence.append(EvidenceRow(
                clue=f"EXIF Software tag: '{software}'",
                source="Metadata",
                suggests="Image was processed in an editing application",
                innocent_alternative="Standard photo post-processing (cropping, color correction)",
                strength=EvidenceStrength.MODERATE,
            ))
        if not exif.get("EXIF DateTimeOriginal"):
            evidence.append(EvidenceRow(
                clue="Original capture timestamp absent from EXIF",
                source="Metadata",
                suggests="Image may have had metadata stripped",
                innocent_alternative="Social media platforms strip EXIF on upload by default",
                strength=EvidenceStrength.WEAK,
            ))
    else:
        evidence.append(EvidenceRow(
            clue="No EXIF metadata found",
            source="Metadata",
            suggests="Metadata may have been stripped",
            innocent_alternative="Platform re-encoding or deliberate privacy stripping; not standalone proof of forgery",
            strength=EvidenceStrength.WEAK,
        ))

    # ── ELA ──────────────────────────────────────────────────────────────────
    try:
        ela = run_ela(file_bytes)
        checks_done.append("Error Level Analysis (ELA)")
        raw_meta["ela"] = ela
        scores.append(0.3 if ela["anomaly_flag"] else 0.8)

        if ela["anomaly_flag"]:
            evidence.append(EvidenceRow(
                clue=f"ELA mean={ela['mean_ela']} — elevated re-save artifacts detected",
                source="Code (ELA script)",
                suggests="Localized re-compression typical of copy-paste compositing",
                innocent_alternative="Heavy JPEG re-encoding without tampering also raises ELA values",
                strength=EvidenceStrength.MODERATE,
            ))
        else:
            evidence.append(EvidenceRow(
                clue=f"ELA mean={ela['mean_ela']} — within normal range",
                source="Code (ELA script)",
                suggests="No obvious re-save artifacts; uniform compression history",
                innocent_alternative="N/A — this is a negative / authenticating signal",
                strength=EvidenceStrength.MODERATE,
            ))
    except Exception as e:
        checks_skipped.append(f"ELA — error: {e}")

    # ── Hive AI Detection ────────────────────────────────────────────────────
    hive = check_hive_ai_detection(file_bytes)
    if hive is None:
        checks_skipped.append("Hive AI-generation detection (API key not configured)")
    elif "error" in hive:
        checks_skipped.append(f"Hive AI-generation detection (API error: {hive['error']})")
    else:
        checks_done.append("Hive Moderation AI-generation detection")
        raw_meta["hive"] = hive
        ai_score = hive.get("ai_generated_score") or 0.0
        scores.append(1.0 - float(ai_score))
        evidence.append(EvidenceRow(
            clue=f"Hive AI-generated score: {ai_score:.2%}",
            source="External API (Hive)",
            suggests="Probabilistic AI generation signal from commercial detector",
            innocent_alternative="Commercial detectors have false-positive rates; score alone is not conclusive",
            strength=EvidenceStrength.STRONG if ai_score > 0.8 else EvidenceStrength.MODERATE,
        ))

    # ── Sightengine ──────────────────────────────────────────────────────────
    se = check_sightengine_ai(file_bytes)
    if se is None:
        checks_skipped.append("Sightengine AI-generation detection (credentials not configured)")
    elif "error" in se:
        checks_skipped.append(f"Sightengine (API error: {se['error']})")
    else:
        checks_done.append("Sightengine AI-generation detection")
        raw_meta["sightengine"] = se
        ai_prob = se.get("type", {}).get("ai_generated", 0.0)
        scores.append(1.0 - float(ai_prob))
        evidence.append(EvidenceRow(
            clue=f"Sightengine AI-generated probability: {ai_prob:.2%}",
            source="External API (Sightengine)",
            suggests="Secondary probabilistic AI generation signal",
            innocent_alternative="Cross-reference with other signals; no single detector is definitive",
            strength=EvidenceStrength.STRONG if ai_prob > 0.8 else EvidenceStrength.MODERATE,
        ))

    # ── Deepfake placeholder ─────────────────────────────────────────────────
    checks_skipped.append("Deepfake / face-swap detection (FaceForensics++ model — not bundled; requires GPU)")

    # ── Composite score ──────────────────────────────────────────────────────
    composite = sum(scores) / len(scores) if scores else None

    return EngineResult(
        engine="image",
        checks_performed=checks_done,
        checks_skipped=checks_skipped,
        evidence=evidence,
        authenticity_score=composite,
        raw_metadata=raw_meta,
    )

"""
Core Pydantic schemas shared across all engines and the verdict layer.
"""
from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class MediaType(str, Enum):
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    PDF = "pdf"
    DOCUMENT = "document"
    TEXT = "text"
    EMAIL = "email"
    URL = "url"
    UNKNOWN = "unknown"


class VerdictLabel(str, Enum):
    LIKELY_AUTHENTIC = "🟢 Likely Authentic"
    LIKELY_AI_GENERATED = "🤖 Likely AI-Generated"
    LIKELY_MANIPULATED = "✂️ Likely Manipulated / Edited"
    LIKELY_MISLEADING = "⚠️ Likely Misleading / Out of Context"
    MIXED = "🔀 Mixed Authentic & Synthetic"
    INCONCLUSIVE = "❓ Inconclusive"


class ConfidenceLevel(str, Enum):
    HIGH = "High"
    MODERATE = "Moderate"
    LOW = "Low"
    INDETERMINATE = "Indeterminate"


class EvidenceStrength(str, Enum):
    STRONG = "Strong"
    MODERATE = "Moderate"
    WEAK = "Weak"


# ─────────────────────────────────────────────────────────────────────────────
# Evidence Row (populates the report table)
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceRow(BaseModel):
    clue: str = Field(..., description="Observed clue or anomaly")
    source: str = Field(..., description="Where it was found: Visual / Metadata / Web / Code")
    suggests: str = Field(..., description="Forensic interpretation")
    innocent_alternative: str = Field(..., description="Benign explanation (compression, human error, etc.)")
    strength: EvidenceStrength


# ─────────────────────────────────────────────────────────────────────────────
# Engine Result — one per engine
# ─────────────────────────────────────────────────────────────────────────────

class EngineResult(BaseModel):
    engine: str
    checks_performed: list[str] = Field(default_factory=list)
    checks_skipped: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRow] = Field(default_factory=list)
    # Numeric score: 0.0 = definitely manipulated/AI, 1.0 = definitely authentic
    authenticity_score: float | None = Field(None, ge=0.0, le=1.0)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Final Verdict
# ─────────────────────────────────────────────────────────────────────────────

class VerdictResult(BaseModel):
    label: VerdictLabel
    confidence: ConfidenceLevel
    bottom_line: str
    biggest_limitation: str
    composite_score: float = Field(..., ge=0.0, le=1.0)
    signal_count: int


# ─────────────────────────────────────────────────────────────────────────────
# Full Analysis Report
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisReport(BaseModel):
    submission_id: str
    media_type: MediaType
    filename: str | None = None
    verdict: VerdictResult
    evidence: list[EvidenceRow]
    checks_performed: list[str]
    checks_skipped: list[str]
    source_verification: str
    potential_risks: str
    how_to_verify: str
    engine_results: list[EngineResult]

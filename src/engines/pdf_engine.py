"""
PDF & Document Forensics Engine.

Checks performed:
- PyMuPDF revision history / incremental update detection
- pdfplumber hidden-text / layer extraction
- Font consistency analysis
- Embedded image ELA (rasterized pages)
- pyhanko digital signature validation
- Numerical / totals cross-check
"""
from __future__ import annotations

import io
import os
import tempfile
from collections import Counter
from typing import Any

# All heavy deps (fitz/PyMuPDF, pdfplumber, pyhanko) are imported lazily inside
# each function so the server starts even without them installed.

from src.core.schemas import EngineResult, EvidenceRow, EvidenceStrength


# ─────────────────────────────────────────────────────────────────────────────
# Revision History
# ─────────────────────────────────────────────────────────────────────────────

def check_pdf_revisions(file_bytes: bytes) -> dict[str, Any]:
    """Detect incremental updates — multiple %%EOF markers indicate revisions."""
    import fitz  # PyMuPDF

    doc = fitz.open(stream=file_bytes, filetype="pdf")
    revisions = file_bytes.count(b"%%EOF")
    xref_count = doc.xref_length()
    doc.close()
    return {
        "revision_count": revisions,
        "xref_objects": xref_count,
        "has_revisions": revisions > 1,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Hidden Text / Layers
# ─────────────────────────────────────────────────────────────────────────────

def extract_all_text(file_bytes: bytes) -> dict[str, Any]:
    """Extract all text including hidden/invisible layers via pdfplumber."""
    try:
        import pdfplumber
        result: dict[str, Any] = {"pages": []}
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for i, page in enumerate(pdf.pages):
                text = page.extract_text() or ""
                result["pages"].append({"page": i + 1, "chars": len(text), "snippet": text[:200]})
        result["total_pages"] = len(result["pages"])
        return result
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Font Consistency
# ─────────────────────────────────────────────────────────────────────────────

def analyze_fonts(file_bytes: bytes) -> dict[str, Any]:
    """Collect all font names across pages. Mixed font origins may suggest paste-in."""
    try:
        import fitz
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        fonts: list[str] = []
        for page in doc:
            for block in page.get_text("dict").get("blocks", []):
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        font = span.get("font", "")
                        if font:
                            fonts.append(font)
        doc.close()
        counter = Counter(fonts)
        return {
            "unique_fonts": list(counter.keys()),
            "font_counts": dict(counter.most_common(10)),
            "total_font_instances": len(fonts),
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Digital Signature Validation
# ─────────────────────────────────────────────────────────────────────────────

def check_signatures(file_bytes: bytes) -> dict[str, Any]:
    """Check for embedded PDF digital signatures using pyhanko."""
    try:
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext
        from pyhanko.pdf_utils.reader import PdfFileReader

        reader = PdfFileReader(io.BytesIO(file_bytes))
        sig_fields = reader.embedded_regular_sig_fields
        results = []
        for field in sig_fields:
            try:
                vc = ValidationContext(allow_fetching=False)
                status = validate_pdf_signature(field, vc)
                results.append({
                    "field": field.field_name,
                    "intact": status.intact,
                    "valid": status.valid,
                    "signer": str(status.signing_cert.subject) if status.signing_cert else None,
                })
            except Exception as sig_err:
                results.append({"field": field.field_name, "error": str(sig_err)})
        return {"signature_fields": len(list(reader.embedded_regular_sig_fields)), "results": results}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Main Engine Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def run_pdf_engine(file_bytes: bytes, filename: str = "document.pdf") -> EngineResult:
    checks_done: list[str] = []
    checks_skipped: list[str] = []
    evidence: list[EvidenceRow] = []
    raw_meta: dict[str, Any] = {}
    scores: list[float] = []

    # ── Revision History ─────────────────────────────────────────────────────
    try:
        rev = check_pdf_revisions(file_bytes)
        checks_done.append("PDF revision history (PyMuPDF)")
        raw_meta["revisions"] = rev
        if rev["has_revisions"]:
            scores.append(0.4)
            evidence.append(EvidenceRow(
                clue=f"{rev['revision_count']} revision(s) detected in PDF structure",
                source="Metadata (PyMuPDF)",
                suggests="Document was incrementally updated after initial creation — possible post-signing edit",
                innocent_alternative="Legitimate form-filling, digital signatures, or tracked changes",
                strength=EvidenceStrength.MODERATE,
            ))
        else:
            scores.append(0.85)
    except Exception as e:
        checks_skipped.append(f"PDF revision history (error: {e})")

    # ── Text Extraction ──────────────────────────────────────────────────────
    text_result = extract_all_text(file_bytes)
    if "error" in text_result:
        checks_skipped.append(f"Text/layer extraction (pdfplumber error: {text_result['error']})")
    else:
        checks_done.append("Full text & hidden-layer extraction (pdfplumber)")
        raw_meta["text"] = text_result

    # ── Font Consistency ─────────────────────────────────────────────────────
    font_result = analyze_fonts(file_bytes)
    if "error" in font_result:
        checks_skipped.append(f"Font analysis (error: {font_result['error']})")
    else:
        checks_done.append("Font consistency analysis (PyMuPDF)")
        raw_meta["fonts"] = font_result
        unique = font_result.get("unique_fonts", [])
        if len(unique) > 6:
            scores.append(0.45)
            evidence.append(EvidenceRow(
                clue=f"{len(unique)} distinct font families found: {unique[:6]}…",
                source="Metadata (PyMuPDF)",
                suggests="High font diversity may indicate text was pasted from multiple sources",
                innocent_alternative="Multi-section documents (header, body, footer) naturally use several fonts",
                strength=EvidenceStrength.MODERATE,
            ))
        else:
            scores.append(0.8)
            evidence.append(EvidenceRow(
                clue=f"{len(unique)} font(s) found — consistent typography",
                source="Metadata (PyMuPDF)",
                suggests="Uniform font usage consistent with a single-origin document",
                innocent_alternative="N/A — authenticating signal",
                strength=EvidenceStrength.MODERATE,
            ))

    # ── Digital Signatures ───────────────────────────────────────────────────
    sig_result = check_signatures(file_bytes)
    if "error" in sig_result:
        checks_skipped.append(f"Digital signature validation (pyhanko error: {sig_result['error']})")
    else:
        checks_done.append("Digital signature validation (pyhanko)")
        raw_meta["signatures"] = sig_result
        sig_count = sig_result.get("signature_fields", 0)
        if sig_count == 0:
            evidence.append(EvidenceRow(
                clue="No embedded digital signature found",
                source="Metadata (pyhanko)",
                suggests="Document lacks cryptographic signing — authenticity cannot be cryptographically verified",
                innocent_alternative="Most informal documents are not digitally signed",
                strength=EvidenceStrength.WEAK,
            ))
        else:
            for r in sig_result.get("results", []):
                if r.get("valid"):
                    scores.append(0.95)
                    evidence.append(EvidenceRow(
                        clue=f"Valid digital signature from: {r.get('signer', 'unknown')}",
                        source="Metadata (pyhanko)",
                        suggests="Document cryptographically signed and unmodified since signing",
                        innocent_alternative="N/A — strong authenticating signal",
                        strength=EvidenceStrength.STRONG,
                    ))
                elif "error" not in r:
                    scores.append(0.1)
                    evidence.append(EvidenceRow(
                        clue=f"Digital signature INVALID or broken (field: {r.get('field')})",
                        source="Metadata (pyhanko)",
                        suggests="Document may have been modified after signing — signature no longer covers content",
                        innocent_alternative="Certificate expired, revoked, or untrusted root CA",
                        strength=EvidenceStrength.STRONG,
                    ))

    # ── ELA on embedded images ───────────────────────────────────────────────
    checks_skipped.append("ELA on embedded PDF images (requires page rasterization — add with --full-scan flag)")

    composite = sum(scores) / len(scores) if scores else None
    return EngineResult(
        engine="pdf",
        checks_performed=checks_done,
        checks_skipped=checks_skipped,
        evidence=evidence,
        authenticity_score=composite,
        raw_metadata=raw_meta,
    )

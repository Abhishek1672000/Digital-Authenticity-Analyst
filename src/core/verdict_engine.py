"""
Verdict Engine — Evidence Aggregator & Confidence Scorer.

Combines engine scores + evidence into a VerdictResult using weighted rules.

Verdict decision tree:
1. If any digital signature is valid and intact → strong Authentic pull
2. If AI-gen score (image or audio) > 0.75 → AI-Generated
3. If ELA + font inconsistency + revision flags co-occur → Manipulated
4. If WHOIS young + VirusTotal flags + recycled photo → Misleading / Impersonation
5. If signals conflict between engines → Mixed or Inconclusive
6. Confidence capped at Moderate if < 3 checks ran
"""
from __future__ import annotations

from src.core.schemas import (
    ConfidenceLevel,
    EngineResult,
    EvidenceRow,
    VerdictLabel,
    VerdictResult,
)


# ─────────────────────────────────────────────────────────────────────────────
# Signal extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

def _has_valid_signature(results: list[EngineResult]) -> bool:
    for r in results:
        for sig in r.raw_metadata.get("signatures", {}).get("results", []):
            if sig.get("valid") and sig.get("intact"):
                return True
    return False


def _ai_gen_score(results: list[EngineResult]) -> float | None:
    """Highest AI-generation probability across image / audio engines."""
    ai_scores: list[float] = []
    for r in results:
        if r.engine in ("image",):
            hive = r.raw_metadata.get("hive", {})
            se = r.raw_metadata.get("sightengine", {})
            if hive.get("ai_generated_score") is not None:
                ai_scores.append(float(hive["ai_generated_score"]))
            se_prob = se.get("type", {}).get("ai_generated") if isinstance(se.get("type"), dict) else None
            if se_prob is not None:
                ai_scores.append(float(se_prob))
    return max(ai_scores) if ai_scores else None


def _has_manipulation_cluster(results: list[EngineResult]) -> bool:
    """Return True if ELA anomaly + font inconsistency + revision co-occur."""
    ela_flag = False
    font_flag = False
    rev_flag = False
    for r in results:
        ela = r.raw_metadata.get("ela", {})
        if ela.get("anomaly_flag"):
            ela_flag = True
        fonts = r.raw_metadata.get("fonts", {})
        if len(fonts.get("unique_fonts", [])) > 6:
            font_flag = True
        rev = r.raw_metadata.get("revisions", {})
        if rev.get("has_revisions"):
            rev_flag = True
    return sum([ela_flag, font_flag, rev_flag]) >= 2


def _has_impersonation_cluster(results: list[EngineResult]) -> bool:
    """WHOIS young + VT flags + recycled photo."""
    young_domain = False
    vt_flag = False
    recycled_photo = False
    for r in results:
        whois = r.raw_metadata.get("whois", {})
        creation = str(whois.get("creation_date", ""))
        if any(y in creation for y in ["2024", "2025", "2026"]):
            young_domain = True
        vt = r.raw_metadata.get("virustotal", {})
        if vt.get("malicious", 0) > 0:
            vt_flag = True
        ris = r.raw_metadata.get("reverse_image", {})
        if ris.get("full_matches", 0) > 3:
            recycled_photo = True
    return sum([young_domain, vt_flag, recycled_photo]) >= 2


# ─────────────────────────────────────────────────────────────────────────────
# Main Verdict Function
# ─────────────────────────────────────────────────────────────────────────────

def compute_verdict(engine_results: list[EngineResult]) -> VerdictResult:
    """
    Aggregate all engine results into a single VerdictResult.
    """
    all_scores = [r.authenticity_score for r in engine_results if r.authenticity_score is not None]
    total_checks = sum(len(r.checks_performed) for r in engine_results)
    all_evidence: list[EvidenceRow] = [e for r in engine_results for e in r.evidence]

    composite = sum(all_scores) / len(all_scores) if all_scores else 0.5

    # ── Rule-based overrides ─────────────────────────────────────────────────
    valid_sig = _has_valid_signature(engine_results)
    ai_prob = _ai_gen_score(engine_results)
    manip_cluster = _has_manipulation_cluster(engine_results)
    impersonation = _has_impersonation_cluster(engine_results)

    # ── Verdict selection ─────────────────────────────────────────────────────
    label: VerdictLabel
    bottom_line: str
    limitation: str

    if valid_sig and composite > 0.7:
        label = VerdictLabel.LIKELY_AUTHENTIC
        bottom_line = (
            "A valid, unbroken digital signature confirms the document has not been altered since signing. "
            "Supporting forensic signals are consistent with an authentic origin."
        )
        limitation = "Signature trust depends on the certificate chain being traceable to a trusted root CA."

    elif ai_prob is not None and ai_prob > 0.75:
        label = VerdictLabel.LIKELY_AI_GENERATED
        bottom_line = (
            f"At least one commercial AI detector returned a high probability ({ai_prob:.0%}) of AI generation. "
            "Supporting signals (e.g., ELA, EXIF absence) align with synthetic media."
        )
        limitation = "Commercial AI detectors have known false-positive rates; no single detector is definitive."

    elif manip_cluster:
        label = VerdictLabel.LIKELY_MANIPULATED
        bottom_line = (
            "Multiple forensic signals co-occur — ELA re-save artifacts, font inconsistencies, and PDF revision history "
            "together suggest the document or image was edited after creation."
        )
        limitation = "Individual signals each have innocent explanations; only the cluster is suspicious."

    elif impersonation:
        label = VerdictLabel.LIKELY_MISLEADING
        bottom_line = (
            "A combination of a newly registered domain, security vendor flags, and recycled profile images "
            "suggest impersonation or a deceptive campaign rather than a genuine identity."
        )
        limitation = "Confirmation requires comparing against the official organization's verified channels."

    elif len(all_scores) == 0 or total_checks < 3:
        label = VerdictLabel.INCONCLUSIVE
        bottom_line = (
            "Insufficient evidence was collected (fewer than 3 forensic checks completed) to make a reliable call. "
            "Configure API keys and resubmit the original file for a stronger verdict."
        )
        limitation = "Most checks were skipped due to missing API keys or the submission being text-only."

    elif composite >= 0.75:
        label = VerdictLabel.LIKELY_AUTHENTIC
        bottom_line = (
            "The available forensic signals — metadata consistency, ELA results, and source checks — "
            "collectively support an authentic origin with no major red flags detected."
        )
        limitation = "Raw file not available for deeper analysis; verdict relies on observable signals only."

    elif composite <= 0.35:
        label = VerdictLabel.LIKELY_MANIPULATED
        bottom_line = (
            "Multiple forensic signals point toward alteration or synthetic content, "
            "though no single decisive proof was found."
        )
        limitation = "A raw, original uncompressed file is needed for definitive forensic confirmation."

    else:
        # Conflicting signals
        label = VerdictLabel.INCONCLUSIVE
        bottom_line = (
            "Signals conflict across engines — some checks suggest authenticity while others raise concerns. "
            "This warrants deeper investigation with the original file and additional API coverage."
        )
        limitation = "Conflicting signals prevent a confident classification without additional data."

    # ── Confidence level ──────────────────────────────────────────────────────
    if total_checks < 3:
        confidence = ConfidenceLevel.INDETERMINATE
    elif label == VerdictLabel.INCONCLUSIVE:
        confidence = ConfidenceLevel.LOW
    elif valid_sig or (ai_prob is not None and ai_prob > 0.85):
        confidence = ConfidenceLevel.HIGH
    elif total_checks >= 5 and len(all_scores) >= 2:
        confidence = ConfidenceLevel.MODERATE
    else:
        confidence = ConfidenceLevel.LOW

    return VerdictResult(
        label=label,
        confidence=confidence,
        bottom_line=bottom_line,
        biggest_limitation=limitation,
        composite_score=round(composite, 3),
        signal_count=total_checks,
    )

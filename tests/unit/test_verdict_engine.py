"""
Unit tests for the Verdict Engine.
"""
import pytest
from src.core.schemas import EngineResult, EvidenceRow, EvidenceStrength, VerdictLabel, ConfidenceLevel
from src.core.verdict_engine import compute_verdict


def _make_result(engine: str, score: float, checks: int = 3) -> EngineResult:
    return EngineResult(
        engine=engine,
        checks_performed=[f"check_{i}" for i in range(checks)],
        authenticity_score=score,
    )


def test_high_score_returns_authentic():
    results = [_make_result("image", 0.9), _make_result("text", 0.85)]
    verdict = compute_verdict(results)
    assert verdict.label == VerdictLabel.LIKELY_AUTHENTIC


def test_low_score_returns_manipulated():
    results = [_make_result("image", 0.2), _make_result("pdf", 0.25)]
    verdict = compute_verdict(results)
    assert verdict.label == VerdictLabel.LIKELY_MANIPULATED


def test_no_scores_returns_inconclusive():
    results = [EngineResult(engine="text", checks_performed=["a"], authenticity_score=None)]
    verdict = compute_verdict(results)
    assert verdict.label == VerdictLabel.INCONCLUSIVE


def test_few_checks_caps_confidence():
    results = [EngineResult(engine="text", checks_performed=["a", "b"], authenticity_score=0.9)]
    verdict = compute_verdict(results)
    assert verdict.confidence == ConfidenceLevel.INDETERMINATE


def test_valid_signature_overrides_to_authentic():
    result = EngineResult(
        engine="pdf",
        checks_performed=["sig_check", "rev_check", "font_check"],
        authenticity_score=0.75,
        raw_metadata={"signatures": {"results": [{"valid": True, "intact": True, "signer": "Test CA"}]}},
    )
    verdict = compute_verdict([result])
    assert verdict.label == VerdictLabel.LIKELY_AUTHENTIC


def test_ai_gen_score_overrides_to_ai():
    result = EngineResult(
        engine="image",
        checks_performed=["ela", "exif", "hive"],
        authenticity_score=0.2,
        raw_metadata={"hive": {"ai_generated_score": 0.92}},
    )
    verdict = compute_verdict([result])
    assert verdict.label == VerdictLabel.LIKELY_AI_GENERATED

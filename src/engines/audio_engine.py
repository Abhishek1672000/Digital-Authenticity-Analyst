"""
Audio Forensics Engine.

Checks performed:
- Mutagen metadata extraction (encoder, bitrate, creation date)
- Librosa splice / discontinuity detection (spectral boundary analysis)
- Resemblyzer speaker embedding consistency
- TTS / voice-clone detection (placeholder — Pindrop / ElevenLabs detector)
"""
from __future__ import annotations

import io
import os
import tempfile
from typing import Any

# All heavy dependencies (librosa, mutagen, resemblyzer, soundfile) are imported
# lazily inside each function so the app starts even if they are not installed.

from src.core.schemas import EngineResult, EvidenceRow, EvidenceStrength


# ─────────────────────────────────────────────────────────────────────────────
# Metadata
# ─────────────────────────────────────────────────────────────────────────────

def extract_audio_metadata(file_bytes: bytes, filename: str = "audio.mp3") -> dict[str, Any]:
    """Extract audio tags using Mutagen."""
    try:
        import mutagen
        with tempfile.NamedTemporaryFile(suffix=os.path.splitext(filename)[1] or ".mp3", delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name
        meta = mutagen.File(tmp_path)
        os.unlink(tmp_path)
        if meta is None:
            return {}
        return {
            "format": type(meta).__name__,
            "length_seconds": round(meta.info.length, 2) if hasattr(meta.info, "length") else None,
            "bitrate": getattr(meta.info, "bitrate", None),
            "sample_rate": getattr(meta.info, "sample_rate", None),
            "tags": {k: str(v) for k, v in (meta.tags or {}).items()},
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Splice Detection via Librosa
# ─────────────────────────────────────────────────────────────────────────────

def detect_splices(file_bytes: bytes) -> dict[str, Any]:
    """
    Detect abrupt spectral discontinuities that may indicate audio splicing.
    Returns a list of suspected splice timestamps (in seconds).
    """
    try:
        import librosa
        import numpy as np
        import soundfile as sf

        audio_data, sr = sf.read(io.BytesIO(file_bytes))
        if audio_data.ndim > 1:
            audio_data = audio_data.mean(axis=1)  # stereo → mono

        # Spectral flux: frame-by-frame change in spectral magnitude
        spec = librosa.feature.melspectrogram(y=audio_data.astype(float), sr=sr, n_mels=128)
        spec_db = librosa.power_to_db(spec, ref=np.max)
        flux = np.sum(np.diff(spec_db, axis=1) ** 2, axis=0)

        threshold = flux.mean() + 3 * flux.std()
        splice_frames = np.where(flux > threshold)[0]
        hop_length = 512
        splice_times = librosa.frames_to_time(splice_frames, sr=sr, hop_length=hop_length)

        return {
            "suspected_splices": [round(float(t), 2) for t in splice_times],
            "mean_flux": round(float(flux.mean()), 4),
            "threshold": round(float(threshold), 4),
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Speaker Consistency (Resemblyzer)
# ─────────────────────────────────────────────────────────────────────────────

def check_speaker_consistency(file_bytes: bytes) -> dict[str, Any] | None:
    """
    Use Resemblyzer to compute speaker embeddings across segments.
    Large embedding distance between segments suggests voice splicing.
    """
    try:
        import numpy as np
        import soundfile as sf
        from resemblyzer import VoiceEncoder, preprocess_wav

        audio_data, sr = sf.read(io.BytesIO(file_bytes))
        if audio_data.ndim > 1:
            audio_data = audio_data.mean(axis=1)

        wav = preprocess_wav(audio_data, source_sr=sr)
        encoder = VoiceEncoder()

        # Split into 5-second segments
        seg_len = sr * 5
        segments = [wav[i : i + seg_len] for i in range(0, len(wav) - seg_len, seg_len)]
        if len(segments) < 2:
            return {"note": "Audio too short for multi-segment speaker analysis"}

        embeds = np.array([encoder.embed_utterance(seg) for seg in segments])
        # Cosine similarity between consecutive segments
        sims = [
            float(np.dot(embeds[i], embeds[i + 1]))
            for i in range(len(embeds) - 1)
        ]
        min_sim = min(sims)
        return {
            "segment_count": len(segments),
            "min_cosine_similarity": round(min_sim, 4),
            "speaker_inconsistency_flag": min_sim < 0.75,
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Main Engine Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def run_audio_engine(file_bytes: bytes, filename: str = "audio.mp3") -> EngineResult:
    checks_done: list[str] = []
    checks_skipped: list[str] = []
    evidence: list[EvidenceRow] = []
    raw_meta: dict[str, Any] = {}
    scores: list[float] = []

    # ── Metadata ─────────────────────────────────────────────────────────────
    meta = extract_audio_metadata(file_bytes, filename)
    checks_done.append("Audio metadata extraction (Mutagen)")
    raw_meta["metadata"] = meta

    if "error" not in meta and meta.get("tags"):
        evidence.append(EvidenceRow(
            clue=f"Audio encoder/tags present: {list(meta.get('tags', {}).keys())[:5]}",
            source="Metadata",
            suggests="File has embedded origin information",
            innocent_alternative="Standard tags from recording app or DAW",
            strength=EvidenceStrength.WEAK,
        ))

    # ── Splice Detection ─────────────────────────────────────────────────────
    splice_result = detect_splices(file_bytes)
    if "error" in splice_result:
        checks_skipped.append(f"Splice detection (librosa error: {splice_result['error']})")
    else:
        checks_done.append("Spectral splice / discontinuity detection (Librosa)")
        raw_meta["splice"] = splice_result
        splices = splice_result.get("suspected_splices", [])
        score = max(0.2, 1.0 - (len(splices) * 0.15))
        scores.append(score)
        if splices:
            evidence.append(EvidenceRow(
                clue=f"{len(splices)} spectral discontinuity point(s) at: {splices[:5]} seconds",
                source="Code (Librosa spectral flux)",
                suggests="Potential audio splice or cut-and-paste editing",
                innocent_alternative="Natural speech pauses, background noise changes, or heavy compression",
                strength=EvidenceStrength.MODERATE if len(splices) > 2 else EvidenceStrength.WEAK,
            ))
        else:
            evidence.append(EvidenceRow(
                clue="No significant spectral discontinuities detected",
                source="Code (Librosa spectral flux)",
                suggests="Continuous, uncut audio — no splice markers",
                innocent_alternative="N/A — authenticating signal",
                strength=EvidenceStrength.MODERATE,
            ))

    # ── Speaker Consistency ──────────────────────────────────────────────────
    speaker = check_speaker_consistency(file_bytes)
    if speaker is None or "error" in (speaker or {}):
        checks_skipped.append(f"Speaker consistency check (resemblyzer error: {(speaker or {}).get('error', 'unavailable')})")
    elif "note" in speaker:
        checks_skipped.append(f"Speaker consistency: {speaker['note']}")
    else:
        checks_done.append("Speaker embedding consistency (Resemblyzer)")
        raw_meta["speaker"] = speaker
        min_sim = speaker.get("min_cosine_similarity", 1.0)
        scores.append(min_sim)
        if speaker.get("speaker_inconsistency_flag"):
            evidence.append(EvidenceRow(
                clue=f"Speaker embedding min cosine similarity: {min_sim:.3f} (below 0.75 threshold)",
                source="Code (Resemblyzer)",
                suggests="Voice characteristics differ between segments — possible voice swap or multi-speaker splice",
                innocent_alternative="Natural speaker variation, different recording conditions, or phone/mic change",
                strength=EvidenceStrength.MODERATE,
            ))
        else:
            evidence.append(EvidenceRow(
                clue=f"Speaker embedding consistency: {min_sim:.3f} (above threshold)",
                source="Code (Resemblyzer)",
                suggests="Same speaker detected across all segments",
                innocent_alternative="N/A — authenticating signal",
                strength=EvidenceStrength.MODERATE,
            ))

    # ── TTS/Clone Detection Placeholder ─────────────────────────────────────
    checks_skipped.append(
        "TTS / voice-clone classification (Pindrop / ElevenLabs detector — requires external API key)"
    )

    composite = sum(scores) / len(scores) if scores else None
    return EngineResult(
        engine="audio",
        checks_performed=checks_done,
        checks_skipped=checks_skipped,
        evidence=evidence,
        authenticity_score=composite,
        raw_metadata=raw_meta,
    )

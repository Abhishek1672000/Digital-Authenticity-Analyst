"""
Submission intake router: detects media type from uploaded bytes / filename / MIME.
"""
from __future__ import annotations

import io
import mimetypes
from pathlib import Path

from src.core.schemas import MediaType

# Map MIME prefixes → MediaType
_MIME_MAP: dict[str, MediaType] = {
    "image/": MediaType.IMAGE,
    "video/": MediaType.VIDEO,
    "audio/": MediaType.AUDIO,
    "application/pdf": MediaType.PDF,
    "text/": MediaType.TEXT,
    "message/": MediaType.EMAIL,
    "application/msword": MediaType.DOCUMENT,
    "application/vnd.openxmlformats": MediaType.DOCUMENT,
}

# Magic byte signatures for format sniffing (fallback when python-magic unavailable)
_MAGIC_BYTES: list[tuple[bytes, MediaType]] = [
    (b"\xff\xd8\xff", MediaType.IMAGE),         # JPEG
    (b"\x89PNG\r\n", MediaType.IMAGE),           # PNG
    (b"GIF8", MediaType.IMAGE),                  # GIF
    (b"RIFF", MediaType.VIDEO),                  # AVI / WAV (differentiated below)
    (b"\x1aE\xdf\xa3", MediaType.VIDEO),         # WebM / MKV
    (b"ftyp", MediaType.VIDEO),                  # MP4 (at offset 4)
    (b"%PDF", MediaType.PDF),                    # PDF
    (b"ID3", MediaType.AUDIO),                   # MP3 with ID3
    (b"fLaC", MediaType.AUDIO),                  # FLAC
    (b"OggS", MediaType.AUDIO),                  # OGG
    (b"From:", MediaType.EMAIL),                 # Raw email
    (b"Return-Path:", MediaType.EMAIL),
    (b"Received:", MediaType.EMAIL),
]


def detect_media_type(
    filename: str | None = None,
    raw_bytes: bytes | None = None,
    mime_hint: str | None = None,
) -> MediaType:
    """
    Detect the MediaType of a submission using three strategies in priority order:
    1. Magic-byte inspection of raw_bytes
    2. Declared MIME type from the client
    3. File extension from filename
    Returns MediaType.UNKNOWN if none match.
    """
    # 1. Magic bytes
    if raw_bytes:
        head = raw_bytes[:12]
        for magic, mtype in _MAGIC_BYTES:
            if head.startswith(magic):
                # Disambiguate RIFF: WAV vs AVI
                if magic == b"RIFF":
                    return MediaType.AUDIO if raw_bytes[8:12] == b"WAVE" else MediaType.VIDEO
                # MP4 check at offset 4
                if magic == b"ftyp":
                    return MediaType.VIDEO
                return mtype
        # MP4 offset-4 check
        if raw_bytes[4:8] == b"ftyp":
            return MediaType.VIDEO

    # 2. MIME hint
    if mime_hint:
        for prefix, mtype in _MIME_MAP.items():
            if mime_hint.startswith(prefix):
                return mtype

    # 3. Extension
    if filename:
        ext = Path(filename).suffix.lower()
        guessed, _ = mimetypes.guess_type(f"f{ext}")
        if guessed:
            for prefix, mtype in _MIME_MAP.items():
                if guessed.startswith(prefix):
                    return mtype

    return MediaType.UNKNOWN


def is_url_submission(text: str) -> bool:
    """Return True if the submission is a bare URL rather than body text."""
    stripped = text.strip()
    return stripped.startswith(("http://", "https://", "ftp://"))

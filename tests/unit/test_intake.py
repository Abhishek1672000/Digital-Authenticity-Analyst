"""
Unit tests for the intake router (media type detection).
"""
import pytest
from src.core.intake import detect_media_type, is_url_submission, MediaType

JPEG_MAGIC = b"\xff\xd8\xff\xe0" + b"\x00" * 100
PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
PDF_MAGIC = b"%PDF-1.4\n" + b"\x00" * 100
MP3_MAGIC = b"ID3" + b"\x00" * 100


def test_detect_jpeg_from_bytes():
    assert detect_media_type(raw_bytes=JPEG_MAGIC) == MediaType.IMAGE


def test_detect_png_from_bytes():
    assert detect_media_type(raw_bytes=PNG_MAGIC) == MediaType.IMAGE


def test_detect_pdf_from_bytes():
    assert detect_media_type(raw_bytes=PDF_MAGIC) == MediaType.PDF


def test_detect_mp3_from_bytes():
    assert detect_media_type(raw_bytes=MP3_MAGIC) == MediaType.AUDIO


def test_detect_from_extension():
    assert detect_media_type(filename="invoice.pdf") == MediaType.PDF
    assert detect_media_type(filename="photo.jpg") == MediaType.IMAGE


def test_detect_from_mime():
    assert detect_media_type(mime_hint="image/png") == MediaType.IMAGE
    assert detect_media_type(mime_hint="application/pdf") == MediaType.PDF
    assert detect_media_type(mime_hint="audio/mpeg") == MediaType.AUDIO


def test_unknown_fallback():
    assert detect_media_type() == MediaType.UNKNOWN


def test_is_url():
    assert is_url_submission("https://example.com/profile")
    assert is_url_submission("http://x.com/user123")
    assert not is_url_submission("This is a plain text message.")

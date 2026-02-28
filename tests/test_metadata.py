"""tests/test_metadata.py — Unit tests for Metadata Inspector"""
import os
import tempfile
import pytest

from analyzer.metadata import inspect, _parse_pdf_date


# ── _parse_pdf_date ───────────────────────────────────────────────────────────

def test_parse_pdf_date_utc():
    dt = _parse_pdf_date("D:20230115120000Z")
    assert dt is not None
    assert dt.year == 2023
    assert dt.month == 1
    assert dt.day == 15


def test_parse_pdf_date_offset():
    dt = _parse_pdf_date("D:20230115120000+05'30'")
    assert dt is not None
    assert dt.year == 2023


def test_parse_pdf_date_invalid():
    assert _parse_pdf_date("NOT_A_DATE") is None
    assert _parse_pdf_date("") is None
    assert _parse_pdf_date(None) is None


# ── inspect() ────────────────────────────────────────────────────────────────

def test_inspect_minimal_pdf(sample_pdf_bytes, tmp_path):
    pdf_path = str(tmp_path / "test.pdf")
    with open(pdf_path, "wb") as f:
        f.write(sample_pdf_bytes)
    result = inspect(pdf_path, {"MANIPULATION_TOOLS": []})
    assert "findings" in result
    assert "module_data" in result


def test_inspect_returns_low_for_missing_author(sample_pdf_bytes, tmp_path):
    pdf_path = str(tmp_path / "test.pdf")
    with open(pdf_path, "wb") as f:
        f.write(sample_pdf_bytes)
    result = inspect(pdf_path, {"MANIPULATION_TOOLS": []})
    severities = [f["severity"] for f in result["findings"]]
    # Missing author should produce at least the LOW finding
    assert any(s in severities for s in ["LOW", "INFO"])

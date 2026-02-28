"""tests/test_structure.py — Unit tests for Structure Analyzer"""
from analyzer.structure import inspect


def test_inspect_minimal_pdf(sample_pdf_bytes, tmp_path):
    pdf_path = str(tmp_path / "test.pdf")
    with open(pdf_path, "wb") as f:
        f.write(sample_pdf_bytes)
    result = inspect(pdf_path, {})
    assert "findings" in result
    assert "module_data" in result
    assert "pdf_version" in result["module_data"]


def test_js_embedded_detected(js_embedded_pdf_bytes, tmp_path):
    pdf_path = str(tmp_path / "js.pdf")
    with open(pdf_path, "wb") as f:
        f.write(js_embedded_pdf_bytes)
    result = inspect(pdf_path, {})
    crits = [f for f in result["findings"] if f["severity"] == "CRITICAL"]
    titles = [f["title"] for f in crits]
    assert any("JavaScript" in t for t in titles), \
        f"Expected JS CRITICAL finding, got: {titles}"


def test_multi_eof_detected(multi_eof_pdf_bytes, tmp_path):
    pdf_path = str(tmp_path / "multieof.pdf")
    with open(pdf_path, "wb") as f:
        f.write(multi_eof_pdf_bytes)
    result = inspect(pdf_path, {})
    # Should have incremental update finding (MEDIUM or HIGH)
    sev = [f["severity"] for f in result["findings"]]
    assert any(s in ("HIGH", "MEDIUM") for s in sev)

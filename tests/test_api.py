"""tests/test_api.py — API integration tests"""
import io
import json
import pytest


def _make_minimal_pdf():
    return b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj
xref
0 4
0000000000 65535 f\r
0000000009 00000 n\r
0000000058 00000 n\r
0000000115 00000 n\r
trailer<</Size 4/Root 1 0 R>>
startxref
200
%%EOF
"""


# ── Health ────────────────────────────────────────────────────────────────────

def test_health_endpoint(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "version" in data


# ── Analyze ───────────────────────────────────────────────────────────────────

def test_analyze_valid_pdf(client):
    pdf_bytes = _make_minimal_pdf()
    data = {"file": (io.BytesIO(pdf_bytes), "test.pdf", "application/pdf")}
    resp = client.post("/api/v1/analyze",
                       data=data,
                       content_type="multipart/form-data")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "analysis_id" in body
    assert "trust_score" in body
    assert "classification" in body
    assert "findings" in body
    assert isinstance(body["trust_score"], int)
    assert 0 <= body["trust_score"] <= 100


def test_analyze_no_file(client):
    resp = client.post("/api/v1/analyze", data={}, content_type="multipart/form-data")
    assert resp.status_code == 400


def test_analyze_non_pdf(client):
    data = {"file": (io.BytesIO(b"This is not a PDF"), "evil.pdf", "application/pdf")}
    resp = client.post("/api/v1/analyze",
                       data=data,
                       content_type="multipart/form-data")
    assert resp.status_code == 415


def test_analyze_deduplication(client):
    """Second upload of same file must return same analysis_id from cache."""
    pdf_bytes = _make_minimal_pdf() + b"# dedup-test-unique\n"
    data1 = {"file": (io.BytesIO(pdf_bytes), "dedup.pdf", "application/pdf")}
    data2 = {"file": (io.BytesIO(pdf_bytes), "dedup.pdf", "application/pdf")}

    resp1 = client.post("/api/v1/analyze", data=data1, content_type="multipart/form-data")
    resp2 = client.post("/api/v1/analyze", data=data2, content_type="multipart/form-data")

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.get_json()["analysis_id"] == resp2.get_json()["analysis_id"]


# ── Report ────────────────────────────────────────────────────────────────────

def test_report_not_found(client):
    resp = client.get("/api/v1/report/DEADBEEF")
    assert resp.status_code == 404


def test_report_round_trip(client):
    """Upload → get report by ID."""
    pdf_bytes = _make_minimal_pdf() + b"# report-round-trip\n"
    data = {"file": (io.BytesIO(pdf_bytes), "report_test.pdf", "application/pdf")}
    resp = client.post("/api/v1/analyze", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    analysis_id = resp.get_json()["analysis_id"]

    rep = client.get(f"/api/v1/report/{analysis_id}")
    assert rep.status_code == 200
    body = rep.get_json()
    assert body["analysis_id"] == analysis_id


# ── History ───────────────────────────────────────────────────────────────────

def test_history_endpoint(client):
    resp = client.get("/api/v1/history")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "items" in body
    assert "total" in body
    assert "page" in body


# ── Batch ─────────────────────────────────────────────────────────────────────

def test_batch_endpoint(client):
    from werkzeug.datastructures import MultiDict, FileStorage
    pdf_bytes = _make_minimal_pdf()

    # Werkzeug 3.x requires MultiDict for multiple values with the same key
    data = MultiDict([
        ("files[]", FileStorage(io.BytesIO(pdf_bytes + b"# batch1"), filename="b1.pdf", content_type="application/pdf")),
        ("files[]", FileStorage(io.BytesIO(pdf_bytes + b"# batch2"), filename="b2.pdf", content_type="application/pdf")),
    ])
    resp = client.post("/api/v1/analyze/batch",
                       data=data,
                       content_type="multipart/form-data")
    assert resp.status_code == 200
    body = resp.get_json()
    assert isinstance(body, list)
    assert len(body) == 2
    # Sorted by trust_score ascending
    scores = [x.get("trust_score", 999) for x in body if "trust_score" in x]
    assert scores == sorted(scores)

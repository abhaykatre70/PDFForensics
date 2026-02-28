"""
tests/conftest.py — pytest fixtures for PDF Forensics Tool
"""
import os
import io
import pytest
from app import create_app
from extensions import db


@pytest.fixture(scope="session")
def app():
    """Create a test Flask application."""
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        yield application
        db.drop_all()


@pytest.fixture()
def client(app):
    """Test client for API integration tests."""
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


# ── Minimal synthetic PDF fixtures ───────────────────────────────────────────

def _make_pdf(extra_bytes: bytes = b"") -> bytes:
    """Generate a minimal but valid PDF 1.4 document."""
    content = b"""%PDF-1.4
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
    return content + extra_bytes


@pytest.fixture(scope="session")
def sample_pdf_bytes():
    return _make_pdf()


@pytest.fixture(scope="session")
def js_embedded_pdf_bytes():
    """PDF with /JavaScript in raw bytes (triggers CRITICAL finding)."""
    return _make_pdf(b"\n/JavaScript << /JS (app.alert('XSS')) >>\n")


@pytest.fixture(scope="session")
def multi_eof_pdf_bytes():
    """PDF with extra %%EOF markers."""
    return _make_pdf(b"\n%%EOF\n")

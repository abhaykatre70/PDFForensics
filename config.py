"""
config.py — Flask configuration classes for PDF Forensics Tool.
"""
import os
import secrets


class BaseConfig:
    """Base configuration shared by all environments."""
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 100))
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024  # bytes

    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join("/tmp", "pdf_uploads"))
    
    if os.environ.get("VERCEL") == "1":
        REPORT_FOLDER = os.environ.get("REPORT_FOLDER", os.path.join("/tmp", "reports"))
        DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join('/tmp', 'app.db')}")
    else:
        REPORT_FOLDER = os.environ.get("REPORT_FOLDER", os.path.join(os.path.dirname(__file__), "data", "reports"))
        DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(os.path.dirname(__file__), 'data', 'app.db')}")

    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    REPORT_RETENTION_DAYS = int(os.environ.get("REPORT_RETENTION_DAYS", 30))
    ENCRYPT_REPORTS = os.environ.get("ENCRYPT_REPORTS", "false").lower() == "true"
    POPPLER_PATH = os.environ.get("POPPLER_PATH", None)

    RATE_LIMIT = os.environ.get("RATE_LIMIT", "60 per minute")

    # Manipulation tool signatures
    MANIPULATION_TOOLS = [
        "ilovepdf", "smallpdf", "pdfescape", "foxit phantom", "libreoffice draw",
        "pdftk", "pdf-xchange", "nitro", "sejda", "pdf24", "camscanner",
        "scanbot", "adobe acrobat", "preview", "inkscape", "ghostscript",
        "pdfsharp", "itextsharp", "itext", "pdfbox", "reportlab",
    ]

    VERSION = "1.0.0"


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(os.path.dirname(__file__), 'data', 'dev.db')}"
    )


class ProductionConfig(BaseConfig):
    DEBUG = False
    TESTING = False


class TestingConfig(BaseConfig):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    UPLOAD_FOLDER = "/tmp/pdf_test_uploads"
    WTF_CSRF_ENABLED = False


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}

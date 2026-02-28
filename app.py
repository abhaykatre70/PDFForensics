"""
app.py — Flask Application Factory for PDF Forensics Tool.
"""
import os
import logging
from flask import Flask
from flask_cors import CORS

from config import config_map
from extensions import db, limiter

# ── Logging ────────────────────────────────────────────────────────────────────
try:
    from pythonjsonlogger import jsonlogger
    handler = logging.StreamHandler()
    handler.setFormatter(jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    ))
    logging.basicConfig(level=logging.INFO, handlers=[handler])
except ImportError:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

logger = logging.getLogger(__name__)


def sort_findings_by_severity(findings):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(findings, key=lambda x: order.get(x.get("severity"), 5))


def create_app(env: str = None) -> Flask:
    """Application factory."""
    env = env or os.environ.get("FLASK_ENV", "development")
    cfg = config_map.get(env, config_map["default"])

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(cfg)

    # Add custom Jinja filter
    app.jinja_env.filters['sort_by_severity'] = sort_findings_by_severity

    # ── Ensure directories exist ───────────────────────────────────────────────
    try:
        for folder in [app.config["UPLOAD_FOLDER"], app.config["REPORT_FOLDER"]]:
            os.makedirs(folder, exist_ok=True)
        data_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(data_dir, exist_ok=True)
    except OSError:
        pass

    # ── Extensions ────────────────────────────────────────────────────────────
    db.init_app(app)
    CORS(app, origins="same-origin")
    limiter.init_app(app)

    # ── Blueprints ────────────────────────────────────────────────────────────
    from blueprints.api import api_bp
    from blueprints.ui import ui_bp
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(ui_bp)

    # ── DB init ───────────────────────────────────────────────────────────────
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created / verified.")
        except Exception as e:
            logger.error("Failed to initialize database: %s", e)

    logger.info("PDF Forensics app created [env=%s]", env)
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

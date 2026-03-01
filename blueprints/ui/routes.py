"""
blueprints/ui/routes.py — Web UI routes for PDF Forensics Tool.

Routes:
    GET  /           → index (drag-and-drop upload)
    POST /upload     → process upload, redirect to /result/<id>
    GET  /result/<id>→ analysis result dashboard
    GET  /history    → paginated history table
    GET  /report/<id>→ printable HTML report
"""
import os
import json
import logging
import tempfile
import shutil

from flask import (
    current_app, request, render_template,
    redirect, url_for, flash, abort
)
from werkzeug.utils import secure_filename

from blueprints.ui import ui_bp
from extensions import db
from models.analysis import Analysis
from models.finding import Finding
from analyzer import PDFAnalyzer, compute_sha256, compute_md5
from analyzer.scoring import get_classification_color

logger = logging.getLogger(__name__)


def _run_analysis(tmp_path: str, safe_name: str, password: str = None) -> dict:
    """Shared analysis runner with dedup key on SHA-256."""
    sha256 = compute_sha256(tmp_path)
    md5 = compute_md5(tmp_path)
    size = os.path.getsize(tmp_path)

    existing = Analysis.query.filter_by(sha256=sha256).first()
    if existing:
        return {"analysis_id": existing.id, "cached": True}

    analyzer = PDFAnalyzer(current_app.config)
    report = analyzer.run(tmp_path, safe_name, sha256, md5, size, password=password)

    analysis = Analysis(
        id=report["analysis_id"],
        sha256=sha256,
        md5=md5,
        filename=safe_name,
        filesize=size,
        trust_score=report["trust_score"],
        classification=report["classification"],
        report_path=report.get("report_path"),
        module_metadata=json.dumps(report["modules"].get("metadata", {}), default=str),
        module_signatures=json.dumps(report["modules"].get("signatures", {}), default=str),
        module_structure=json.dumps(report["modules"].get("structure", {}), default=str),
        module_content=json.dumps(report["modules"].get("content", {}), default=str),
        module_visual=json.dumps(report["modules"].get("visual", {}), default=str),
    )
    for f_dict in report["findings"]:
        finding = Finding(
            analysis_id=report["analysis_id"],
            module=f_dict.get("module", ""),
            severity=f_dict.get("severity", "INFO"),
            title=f_dict.get("title", ""),
            detail=f_dict.get("detail", ""),
            evidence=str(f_dict.get("evidence", "")),
        )
        db.session.add(finding)

    db.session.add(analysis)
    db.session.commit()
    return {"analysis_id": report["analysis_id"], "cached": False}


@ui_bp.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@ui_bp.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("ui.index"))

    file = request.files["file"]
    if not file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("ui.index"))

    password = request.form.get("password") or None
    safe_name = secure_filename(file.filename)

    if not safe_name.lower().endswith(".pdf"):
        flash("Only PDF files are supported.", "error")
        return redirect(url_for("ui.index"))

    upload_dir = tempfile.mkdtemp(prefix="pdf_ui_")
    try:
        tmp_path = os.path.join(upload_dir, safe_name)
        file.save(tmp_path)

        with open(tmp_path, "rb") as f:
            header = f.read(5)
        if header != b"%PDF-":
            flash("Uploaded file does not appear to be a valid PDF.", "error")
            return redirect(url_for("ui.index"))

        result = _run_analysis(tmp_path, safe_name, password)
        return redirect(url_for("ui.result", analysis_id=result["analysis_id"]))

    except Exception as e:
        logger.error("Upload processing error: %s", e, exc_info=True)
        flash(f"Analysis failed: {e}", "error")
        return redirect(url_for("ui.index"))
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)


@ui_bp.route("/result/<analysis_id>", methods=["GET"])
def result(analysis_id: str):
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        abort(404)

    def _load(field):
        try:
            return json.loads(field) if field else {}
        except Exception:
            return {}

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in analysis.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    report = {
        "analysis_id": analysis.id,
        "filename": analysis.filename,
        "sha256": analysis.sha256,
        "md5": analysis.md5,
        "filesize": analysis.filesize,
        "trust_score": analysis.trust_score,
        "classification": analysis.classification,
        "analyzed_at": analysis.analyzed_at.isoformat() + "Z" if analysis.analyzed_at else None,
        "severity_counts": sev_counts,
        "findings": [f.to_dict() for f in analysis.findings],
        "modules": {
            "metadata":   _load(analysis.module_metadata),
            "signatures": _load(analysis.module_signatures),
            "structure":  _load(analysis.module_structure),
            "content":    _load(analysis.module_content),
            "visual":     _load(analysis.module_visual),
        },
    }

    color_class = get_classification_color(analysis.classification)
    return render_template("result.html", report=report, analysis=analysis,
                           color_class=color_class)


@ui_bp.route("/history", methods=["GET"])
def history():
    page = int(request.args.get("page", 1))
    search_query = request.args.get("search", "").strip()
    per_page = 20

    query = Analysis.query
    if search_query:
        # Search by filename or ID
        query = query.filter(
            (Analysis.filename.ilike(f"%{search_query}%")) |
            (Analysis.id.ilike(f"%{search_query}%"))
        )

    pagination = query.order_by(
        Analysis.analyzed_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    return render_template("history.html", pagination=pagination,
                           search_query=search_query,
                           get_classification_color=get_classification_color)


@ui_bp.route("/report/<analysis_id>", methods=["GET"])
def report_page(analysis_id: str):
    return redirect(url_for("api.get_report_html", analysis_id=analysis_id))

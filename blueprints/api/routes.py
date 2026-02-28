"""
blueprints/api/routes.py — REST API endpoints for PDF Forensics Tool.

Routes:
    POST  /api/v1/analyze
    POST  /api/v1/analyze/batch
    POST  /api/v1/analyze/url
    GET   /api/v1/report/<id>
    GET   /api/v1/report/<id>/html
    GET   /api/v1/history
    DELETE /api/v1/report/<id>
    GET   /api/v1/health
    GET   /api/v1/docs
"""
import os
import json
import logging
import tempfile
import shutil
from datetime import datetime, timezone

import requests
from flask import (
    current_app, request, jsonify, send_file,
    render_template, abort
)
from werkzeug.utils import secure_filename

from blueprints.api import api_bp
from extensions import db
from models.analysis import Analysis
from models.finding import Finding
from analyzer import PDFAnalyzer, compute_sha256, compute_md5
from app import limiter

logger = logging.getLogger(__name__)

ALLOWED_MIME = {"application/pdf"}


# ── Helper: validate + save upload ─────────────────────────────────────────────

def _validate_and_save(file_storage, upload_dir: str) -> tuple[str, str]:
    """
    Validate MIME type and save a FileStorage to upload_dir.
    Returns (safe_filename, temp_path).
    Raises ValueError on invalid input.
    """
    safe_name = secure_filename(file_storage.filename or "upload.pdf")
    if not safe_name.lower().endswith(".pdf"):
        raise ValueError("Only .pdf files are accepted")

    tmp_path = os.path.join(upload_dir, safe_name)
    file_storage.save(tmp_path)

    # Magic bytes check (%PDF-)
    with open(tmp_path, "rb") as f:
        header = f.read(5)
    if header != b"%PDF-":
        os.remove(tmp_path)
        raise ValueError("File does not begin with PDF magic bytes (%PDF-)")

    return safe_name, tmp_path


def _run_analysis(tmp_path: str, safe_name: str, password: str = None) -> dict:
    """Compute hashes, check dedup cache, run analysis, persist to DB."""
    sha256 = compute_sha256(tmp_path)
    md5 = compute_md5(tmp_path)
    size = os.path.getsize(tmp_path)

    # Deduplication
    existing = Analysis.query.filter_by(sha256=sha256).first()
    if existing:
        logger.info("Cache hit for sha256=%s → analysis_id=%s", sha256, existing.id)
        return _analysis_to_full_dict(existing)

    analyzer = PDFAnalyzer(current_app.config)
    report = analyzer.run(tmp_path, safe_name, sha256, md5, size, password=password)

    # Persist
    analysis = Analysis(
        id=report["analysis_id"],
        sha256=sha256,
        md5=md5,
        filename=safe_name,
        filesize=size,
        trust_score=report["trust_score"],
        classification=report["classification"],
        analyzed_at=datetime.now(timezone.utc),
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

    return report


def _analysis_to_full_dict(analysis: Analysis) -> dict:
    """Reconstruct a full report dict from persisted Analysis model."""
    def _load(field):
        try:
            return json.loads(field) if field else {}
        except Exception:
            return {}

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in analysis.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    return {
        "analysis_id": analysis.id,
        "filename": analysis.filename,
        "analyzed_at": analysis.analyzed_at.isoformat() + "Z" if analysis.analyzed_at else None,
        "file_info": {"sha256": analysis.sha256, "md5": analysis.md5, "size_bytes": analysis.filesize},
        "trust_score": analysis.trust_score,
        "classification": analysis.classification,
        "severity_counts": sev_counts,
        "findings": [f.to_dict() for f in analysis.findings],
        "modules": {
            "metadata":   _load(analysis.module_metadata),
            "signatures": _load(analysis.module_signatures),
            "structure":  _load(analysis.module_structure),
            "content":    _load(analysis.module_content),
            "visual":     _load(analysis.module_visual),
        },
        "report_path": analysis.report_path,
    }


# ── Routes ──────────────────────────────────────────────────────────────────────

@api_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": current_app.config.get("VERSION", "1.0.0")}), 200


@api_bp.route("/analyze", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT", "60 per minute"))
def analyze():
    """POST /api/v1/analyze — analyze a single uploaded PDF."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided. Include 'file' in multipart form."}), 400

    file = request.files["file"]
    password = request.form.get("password") or None

    upload_dir = tempfile.mkdtemp(prefix="pdf_up_")
    try:
        safe_name, tmp_path = _validate_and_save(file, upload_dir)
        report = _run_analysis(tmp_path, safe_name, password)
        return jsonify(report), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 415
    except Exception as e:
        logger.error("Analysis error: %s", e, exc_info=True)
        return jsonify({"error": "Internal analysis error", "detail": str(e)}), 500
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)


@api_bp.route("/analyze/batch", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT", "60 per minute"))
def analyze_batch():
    """POST /api/v1/analyze/batch — analyze up to 100 PDFs."""
    files = request.files.getlist("files[]")
    if not files:
        return jsonify({"error": "No files provided"}), 400
    if len(files) > 100:
        return jsonify({"error": "Maximum 100 files per batch"}), 400

    results = []
    for file in files:
        upload_dir = tempfile.mkdtemp(prefix="pdf_batch_")
        try:
            safe_name, tmp_path = _validate_and_save(file, upload_dir)
            report = _run_analysis(tmp_path, safe_name)
            results.append({
                "filename": safe_name,
                "analysis_id": report.get("analysis_id"),
                "trust_score": report.get("trust_score"),
                "classification": report.get("classification"),
                "report_url": f"/api/v1/report/{report.get('analysis_id')}",
                "severity_counts": report.get("severity_counts", {}),
            })
        except ValueError as e:
            results.append({"filename": file.filename, "error": str(e)})
        except Exception as e:
            results.append({"filename": file.filename, "error": str(e)})
        finally:
            shutil.rmtree(upload_dir, ignore_errors=True)

    # Sort by trust_score ascending (highest risk first)
    results.sort(key=lambda x: x.get("trust_score", 999))
    return jsonify(results), 200


@api_bp.route("/analyze/url", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT", "60 per minute"))
def analyze_url():
    """POST /api/v1/analyze/url — download and analyze a PDF from a URL."""
    body = request.get_json(silent=True) or {}
    pdf_url = body.get("pdf_url")
    password = body.get("password")

    if not pdf_url:
        return jsonify({"error": "pdf_url field required"}), 400

    upload_dir = tempfile.mkdtemp(prefix="pdf_url_")
    try:
        resp = requests.get(pdf_url, timeout=30, stream=True)
        resp.raise_for_status()

        filename = secure_filename(pdf_url.split("/")[-1] or "download.pdf")
        if not filename.endswith(".pdf"):
            filename += ".pdf"

        tmp_path = os.path.join(upload_dir, filename)
        with open(tmp_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)

        with open(tmp_path, "rb") as f:
            if f.read(5) != b"%PDF-":
                return jsonify({"error": "Downloaded file is not a valid PDF"}), 415

        report = _run_analysis(tmp_path, filename, password)
        return jsonify(report), 200
    except requests.RequestException as e:
        return jsonify({"error": f"Failed to download PDF: {e}"}), 400
    except Exception as e:
        logger.error("URL analysis error: %s", e, exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)


@api_bp.route("/report/<analysis_id>", methods=["GET"])
def get_report(analysis_id: str):
    """GET /api/v1/report/<id> — retrieve cached JSON report."""
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found"}), 404
    return jsonify(_analysis_to_full_dict(analysis)), 200


@api_bp.route("/report/<analysis_id>/html", methods=["GET"])
def get_report_html(analysis_id: str):
    """GET /api/v1/report/<id>/html — rendered HTML report."""
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        abort(404)
    report = _analysis_to_full_dict(analysis)
    from analyzer.scoring import get_classification_color
    color_class = get_classification_color(analysis.classification)
    return render_template("report.html", report=report, analysis=analysis,
                           color_class=color_class)


@api_bp.route("/report/<analysis_id>", methods=["DELETE"])
def delete_report(analysis_id: str):
    """DELETE /api/v1/report/<id> — delete analysis and report file."""
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found"}), 404

    if analysis.report_path and os.path.exists(analysis.report_path):
        try:
            os.remove(analysis.report_path)
        except Exception:
            pass

    db.session.delete(analysis)
    db.session.commit()
    return "", 204


@api_bp.route("/history", methods=["GET"])
def history():
    """GET /api/v1/history — paginated analysis list."""
    page = int(request.args.get("page", 1))
    limit = min(int(request.args.get("limit", 50)), 200)

    pagination = Analysis.query.order_by(
        Analysis.analyzed_at.desc()
    ).paginate(page=page, per_page=limit, error_out=False)

    items = [
        {
            "analysis_id": a.id,
            "filename": a.filename,
            "trust_score": a.trust_score,
            "classification": a.classification,
            "analyzed_at": a.analyzed_at.isoformat() + "Z" if a.analyzed_at else None,
            "sha256": a.sha256,
        }
        for a in pagination.items
    ]
    return jsonify({
        "items": items,
        "total": pagination.total,
        "page": page,
        "pages": pagination.pages,
        "limit": limit,
    }), 200

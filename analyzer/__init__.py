"""
analyzer/__init__.py — PDFAnalyzer orchestrator.

Coordinates all five forensic modules, aggregates findings,
computes the Trust Score, and persists the report.
"""
import os
import json
import hashlib
import logging
import tempfile
import shutil
import secrets
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from analyzer import metadata, signatures, structure, content, visual, scoring

logger = logging.getLogger(__name__)


class PDFAnalyzer:
    """Orchestrates all five forensic modules for a single PDF file."""

    def __init__(self, app_config: dict):
        self.config = app_config

    def run(
        self,
        pdf_path: str,
        filename: str,
        sha256: str,
        md5: str,
        filesize: int,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute all five modules and return a complete analysis result dict.
        """
        analysis_id = _generate_id()
        analyzed_at = datetime.now(timezone.utc).isoformat()

        all_findings: List[Dict] = []
        module_results: Dict[str, Any] = {}

        modules = [
            ("metadata",   metadata.inspect),
            ("signatures", signatures.inspect),
            ("structure",  structure.inspect),
            ("content",    content.inspect),
            ("visual",     visual.inspect),
        ]

        for module_name, module_fn in modules:
            try:
                logger.info("Running module: %s for %s", module_name, analysis_id)
                result = module_fn(pdf_path, self.config)
                module_findings = result.get("findings", [])
                module_data = result.get("module_data", {})
                all_findings.extend(module_findings)
                module_results[module_name] = module_data
            except Exception as exc:
                logger.error("Module %s failed: %s", module_name, exc, exc_info=True)
                all_findings.append({
                    "module": module_name.title(),
                    "severity": "INFO",
                    "title": f"{module_name.title()} Module Error",
                    "detail": str(exc),
                    "evidence": "",
                })
                module_results[module_name] = {"error": str(exc)}

        # ── Score ─────────────────────────────────────────────────────────────
        score_result = scoring.compute(all_findings)

        # ── Build report dict ─────────────────────────────────────────────────
        report = {
            "analysis_id": analysis_id,
            "filename": filename,
            "analyzed_at": analyzed_at,
            "file_info": {
                "sha256": sha256,
                "md5": md5,
                "size_bytes": filesize,
            },
            "trust_score": score_result["trust_score"],
            "classification": score_result["classification"],
            "severity_counts": score_result["severity_counts"],
            "deduction_detail": score_result["deduction_detail"],
            "findings": all_findings,
            "modules": module_results,
        }

        # ── Persist JSON report ───────────────────────────────────────────────
        report_path = self._save_report(analysis_id, report)
        report["report_path"] = report_path

        return report

    def _save_report(self, analysis_id: str, report: Dict) -> Optional[str]:
        """Serialize and save the JSON report to disk."""
        try:
            report_folder = self.config.get("REPORT_FOLDER", "/tmp/reports")
            os.makedirs(report_folder, exist_ok=True)
            report_path = os.path.join(report_folder, f"{analysis_id}.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str, ensure_ascii=False)
            return report_path
        except Exception as e:
            logger.error("Failed to save report: %s", e)
            return None


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _generate_id() -> str:
    return secrets.token_hex(4).upper()

"""
analyzer/structure.py — Module 3: Structure Analyzer

Analyzes the low-level PDF structure for suspicious elements including
embedded JavaScript, incremental updates, hidden layers, and malicious actions.
"""
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Patterns to detect in raw PDF bytes
_JS_PATTERNS = [b"/JavaScript", b"/JS "]
_LAUNCH_PATTERN = b"/Launch"
_OPEN_ACTION = b"/OpenAction"
_OCG_PATTERNS = [b"/OCG", b"/OCMD"]
_EMBEDDED_FILE = b"/EmbeddedFile"
_URI_ACTION = b"/URI"


def inspect(pdf_path: str, config: dict, password: str = None) -> Dict[str, Any]:
    """
    Run the Structure Analyzer on the given PDF file.

    Returns:
        {
            "findings": [Finding-like dicts],
            "module_data": {...}
        }
    """
    findings: List[Dict] = []
    module_data: Dict[str, Any] = {}

    try:
        with open(pdf_path, "rb") as f:
            raw = f.read()

        # ── PDF Header Version ────────────────────────────────────────────────
        version_match = re.search(rb"%PDF-(\d+\.\d+)", raw)
        module_data["pdf_version"] = version_match.group(1).decode() if version_match else "unknown"

        # ── Object count ──────────────────────────────────────────────────────
        obj_count = len(re.findall(rb"\d+ \d+ obj", raw))
        module_data["object_count"] = obj_count

        # ── Incremental updates (%%EOF count) ─────────────────────────────────
        eof_count = raw.count(b"%%EOF")
        module_data["incremental_updates"] = max(0, eof_count - 1)
        module_data["eof_count"] = eof_count

        if eof_count > 2:
            findings.append(_finding(
                "HIGH", "Multiple Incremental Updates Detected",
                f"Found {eof_count} %%EOF markers, indicating {eof_count - 1} incremental update(s). "
                "Multiple incremental saves can be used to layer unauthorized modifications.",
                f"%%EOF count={eof_count}"
            ))
        elif eof_count == 2:
            findings.append(_finding(
                "MEDIUM", "Incremental Update Present",
                "One incremental update detected (2 %%EOF markers). Document was modified after initial creation.",
                f"%%EOF count=2"
            ))

        # ── Embedded JavaScript ───────────────────────────────────────────────
        for pat in _JS_PATTERNS:
            if pat in raw:
                findings.append(_finding(
                    "CRITICAL", "Embedded JavaScript Detected",
                    f"PDF contains embedded JavaScript ({pat.decode()}). This is a critical security risk "
                    "and a common vector for malicious payload delivery.",
                    f"Pattern found: {pat.decode()!r}"
                ))
                break
        module_data["has_javascript"] = any(p in raw for p in _JS_PATTERNS)

        # ── Launch actions ────────────────────────────────────────────────────
        has_launch = _LAUNCH_PATTERN in raw
        module_data["has_launch_action"] = has_launch
        if has_launch:
            findings.append(_finding(
                "CRITICAL", "Launch Action Detected",
                "PDF contains a /Launch action that can execute external processes on open.",
                "/Launch found in raw PDF bytes"
            ))

        # ── OpenAction ────────────────────────────────────────────────────────
        has_open_action = _OPEN_ACTION in raw
        module_data["has_open_action"] = has_open_action
        if has_open_action:
            findings.append(_finding(
                "HIGH", "OpenAction Present",
                "PDF contains an /OpenAction that executes automatically when the document is opened.",
                "/OpenAction found in raw PDF bytes"
            ))

        # ── Optional Content Groups (hidden layers) ───────────────────────────
        has_ocg = any(p in raw for p in _OCG_PATTERNS)
        module_data["has_optional_content"] = has_ocg
        if has_ocg:
            findings.append(_finding(
                "MEDIUM", "Optional Content Group (Hidden Layer) Detected",
                "PDF contains Optional Content Groups (/OCG or /OCMD) which can be used to hide content layers.",
                "OCG/OCMD found in raw PDF bytes"
            ))

        # ── Embedded files ────────────────────────────────────────────────────
        has_embedded = _EMBEDDED_FILE in raw
        module_data["has_embedded_files"] = has_embedded
        if has_embedded:
            findings.append(_finding(
                "MEDIUM", "Embedded File Detected",
                "PDF contains embedded file streams (/EmbeddedFile). Verify embedded content is expected.",
                "/EmbeddedFile found in raw PDF bytes"
            ))

        # ── URI actions ───────────────────────────────────────────────────────
        uri_count = raw.count(_URI_ACTION)
        module_data["uri_action_count"] = uri_count
        if uri_count > 0:
            findings.append(_finding(
                "LOW", f"URI Action(s) Present ({uri_count})",
                f"Document contains {uri_count} /URI action(s). Verify all linked URLs are legitimate.",
                f"/URI count={uri_count}"
            ))

        # ── Hybrid cross-reference ────────────────────────────────────────────
        has_xref_table = b"xref" in raw
        has_xref_stream = re.search(rb"/XRef\s+\d+\s+\d+\s+obj", raw) is not None
        module_data["hybrid_xref"] = has_xref_table and has_xref_stream
        if has_xref_table and has_xref_stream:
            findings.append(_finding(
                "MEDIUM", "Hybrid Cross-Reference Table Detected",
                "The PDF uses both traditional xref tables and cross-reference streams. "
                "This hybrid structure can be exploited to conceal objects from standard viewers.",
                "Both 'xref' keyword and /XRef stream found"
            ))

        # ── Encryption ────────────────────────────────────────────────────────
        module_data["encrypted"] = b"/Encrypt" in raw

        # ── Deep structure with pikepdf ───────────────────────────────────────
        _analyze_with_pikepdf(pdf_path, raw, findings, module_data, password)

    except Exception as exc:
        logger.warning("Structure analysis error: %s", exc, exc_info=True)
        findings.append(_finding(
            "INFO", "Structure Analysis Partial",
            f"Structure module encountered an error: {exc}", ""
        ))

    return {"findings": findings, "module_data": module_data}


def _analyze_with_pikepdf(pdf_path: str, raw: bytes, findings: List, module_data: Dict, password: str = None):
    """Use pikepdf for deeper structural analysis."""
    try:
        import pikepdf
        pdf = pikepdf.open(pdf_path, suppress_warnings=True, password=password or "")

        # Check for /AA (Additional Actions) in catalog
        root = pdf.Root
        if "/AA" in root:
            findings.append(_finding(
                "HIGH", "Additional Actions (AA) in Document Catalog",
                "The document catalog contains /AA (Additional Actions), which can trigger scripts on events.",
                "/AA found in document Root"
            ))

        # Count pages with XObjects
        try:
            xobject_pages = 0
            for page in pdf.pages:
                resources = page.get("/Resources", {})
                if "/XObject" in resources:
                    xobject_pages += 1
            module_data["pages_with_xobjects"] = xobject_pages
        except Exception:
            pass

    except Exception as e:
        logger.debug("pikepdf structure error: %s", e)


def _finding(severity: str, title: str, detail: str, evidence: str) -> Dict:
    return {
        "module": "Structure",
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
    }

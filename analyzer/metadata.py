"""
analyzer/metadata.py — Module 1: Metadata Inspector

Extracts and audits PDF metadata fields including DocInfo and XMP,
checking for manipulation tool signatures, timestamp anomalies, and
field inconsistencies.
"""
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# PDF date string format: D:YYYYMMDDHHmmSSOHH'mm'
_PDF_DATE_PATTERN = re.compile(
    r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})"
    r"([+\-Z])?"
    r"(\d{2})?'?(\d{2})?"
)


def _parse_pdf_date(date_str: str) -> datetime | None:
    """Parse a PDF date string into a timezone-aware datetime object."""
    if not date_str:
        return None
    try:
        s = str(date_str).strip()
        m = _PDF_DATE_PATTERN.search(s)
        if not m:
            return None
        year, month, day, hour, minute, second = (int(x) for x in m.groups()[:6])
        tz_sign = m.group(7) or "Z"
        tz_hh = int(m.group(8) or 0)
        tz_mm = int(m.group(9) or 0)

        if tz_sign == "Z" or tz_sign is None:
            tz = timezone.utc
        elif tz_sign == "+":
            tz = timezone(timedelta(hours=tz_hh, minutes=tz_mm))
        else:
            tz = timezone(-timedelta(hours=tz_hh, minutes=tz_mm))

        return datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except Exception:
        return None


def inspect(pdf_path: str, config: dict) -> Dict[str, Any]:
    """
    Run the Metadata Inspector on the given PDF file.

    Returns:
        {
            "findings": [Finding-like dicts],
            "module_data": {raw metadata fields}
        }
    """
    findings = []
    module_data: Dict[str, Any] = {}

    try:
        import pypdf

        reader = pypdf.PdfReader(pdf_path, strict=False)
        meta = reader.metadata or {}

        # ── Extract standard DocInfo ──────────────────────────────────────────
        fields = {
            "title": meta.get("/Title", ""),
            "author": meta.get("/Author", ""),
            "subject": meta.get("/Subject", ""),
            "creator": meta.get("/Creator", ""),
            "producer": meta.get("/Producer", ""),
            "keywords": meta.get("/Keywords", ""),
            "creation_date_raw": meta.get("/CreationDate", ""),
            "mod_date_raw": meta.get("/ModDate", ""),
        }
        module_data.update(fields)

        creation_dt = _parse_pdf_date(str(fields["creation_date_raw"]))
        mod_dt = _parse_pdf_date(str(fields["mod_date_raw"]))
        module_data["creation_date"] = creation_dt.isoformat() if creation_dt else None
        module_data["mod_date"] = mod_dt.isoformat() if mod_dt else None

        now_utc = datetime.now(timezone.utc)

        # ── Future timestamp check ────────────────────────────────────────────
        if creation_dt and creation_dt > now_utc:
            findings.append(_finding(
                "CRITICAL", "Future Creation Date",
                f"CreationDate ({creation_dt.isoformat()}) is in the future.",
                str(fields["creation_date_raw"])
            ))
        if mod_dt and mod_dt > now_utc:
            findings.append(_finding(
                "CRITICAL", "Future Modification Date",
                f"ModDate ({mod_dt.isoformat()}) is in the future.",
                str(fields["mod_date_raw"])
            ))

        # ── Post-creation modification ────────────────────────────────────────
        if creation_dt and mod_dt:
            delta = (mod_dt - creation_dt).total_seconds()
            if delta > 60:
                findings.append(_finding(
                    "MEDIUM", "Post-Creation Modification Detected",
                    f"ModDate is {int(delta)} seconds after CreationDate, indicating document was edited after initial creation.",
                    f"CreationDate={creation_dt.isoformat()}, ModDate={mod_dt.isoformat()}, Δ={int(delta)}s"
                ))

        # ── Manipulation tool detection ───────────────────────────────────────
        manipulation_tools = config.get("MANIPULATION_TOOLS", [])
        for field_name in ("creator", "producer"):
            field_val = str(fields.get(field_name, "") or "").lower()
            for tool in manipulation_tools:
                if tool.lower() in field_val:
                    findings.append(_finding(
                        "HIGH", f"Manipulation Tool Detected in {field_name.title()}",
                        f"The {field_name} field contains '{tool}', a known PDF manipulation tool.",
                        f"{field_name}={fields[field_name]!r}"
                    ))
                    break

        # ── Missing author ────────────────────────────────────────────────────
        if not fields.get("author"):
            findings.append(_finding(
                "LOW", "Missing Author Field",
                "The Author metadata field is empty or absent.",
                "Author field not present in DocInfo"
            ))

        # ── XMP metadata extraction & DocInfo comparison ──────────────────────
        xmp_data = _extract_xmp(reader)
        module_data["xmp"] = xmp_data
        if xmp_data:
            _compare_xmp_docinfo(fields, xmp_data, findings)

        # ── Page count ───────────────────────────────────────────────────────
        module_data["page_count"] = len(reader.pages)

    except Exception as exc:
        logger.warning("Metadata inspection error: %s", exc, exc_info=True)
        findings.append(_finding(
            "INFO", "Metadata Extraction Partial",
            f"Could not fully extract metadata: {exc}", ""
        ))

    return {"findings": findings, "module_data": module_data}


def _extract_xmp(reader) -> Dict[str, str]:
    """Extract key/value pairs from embedded XMP stream."""
    results = {}
    try:
        xmp_meta = reader.xmp_metadata
        if xmp_meta is None:
            return results
        # Try common XMP namespaces
        for ns, prefix in [
            ("http://purl.org/dc/elements/1.1/", "dc"),
            ("http://ns.adobe.com/xap/1.0/", "xmp"),
            ("http://ns.adobe.com/pdf/1.3/", "pdf"),
        ]:
            try:
                for tag in ["title", "creator", "description", "date", "format", "producer", "createDate", "modifyDate"]:
                    val = xmp_meta.dc_format if hasattr(xmp_meta, "dc_format") else None
                    # Generic attribute fetch
                    attr = f"{prefix}_{tag}"
                    v = getattr(xmp_meta, attr, None)
                    if v:
                        results[attr] = str(v)
            except Exception:
                pass
    except Exception:
        pass
    return results


def _compare_xmp_docinfo(docinfo: Dict, xmp: Dict, findings: List):
    """Flag discrepancies between DocInfo and XMP fields."""
    xmp_creator = xmp.get("xmp_creator") or xmp.get("dc_creator")
    if xmp_creator and docinfo.get("creator"):
        if str(xmp_creator).strip().lower() != str(docinfo["creator"]).strip().lower():
            findings.append(_finding(
                "MEDIUM", "XMP / DocInfo Creator Mismatch",
                f"XMP creator '{xmp_creator}' does not match DocInfo creator '{docinfo['creator']}'.",
                f"XMP={xmp_creator!r}, DocInfo={docinfo['creator']!r}"
            ))


def _finding(severity: str, title: str, detail: str, evidence: str) -> Dict:
    return {
        "module": "Metadata",
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
    }

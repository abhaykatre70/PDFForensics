"""
analyzer/signatures.py — Module 2: Signature Verifier

Analyzes PDF digital signatures: ByteRange coverage, certificate
validity, incremental-save attacks, and unsigned signature fields.
"""
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def inspect(pdf_path: str, config: dict) -> Dict[str, Any]:
    """
    Run the Signature Verifier on the given PDF file.

    Returns:
        {
            "findings": [Finding-like dicts],
            "module_data": {...}
        }
    """
    findings: List[Dict] = []
    module_data: Dict[str, Any] = {
        "count": 0,
        "signatures": [],
        "incremental_save_attack": False,
    }

    try:
        _analyze_signatures(pdf_path, findings, module_data)
        _detect_incremental_save_attack(pdf_path, findings, module_data)
    except Exception as exc:
        logger.warning("Signature inspection error: %s", exc, exc_info=True)
        findings.append(_finding(
            "INFO", "Signature Analysis Partial",
            f"Signature module encountered an error: {exc}", ""
        ))

    return {"findings": findings, "module_data": module_data}


# ── Internal helpers ────────────────────────────────────────────────────────────

def _analyze_signatures(pdf_path: str, findings: List, module_data: Dict):
    """Traverse AcroForm signature fields and validate each."""
    try:
        import pikepdf
        from datetime import datetime, timezone

        pdf = pikepdf.open(pdf_path, suppress_warnings=True)
        root = pdf.Root

        if "/AcroForm" not in root:
            module_data["count"] = 0
            return

        acroform = root["/AcroForm"]
        if "/Fields" not in acroform:
            return

        file_size = _get_file_size(pdf_path)
        sig_infos = []

        def walk_fields(fields):
            for field_ref in fields:
                try:
                    field = field_ref
                    ft = str(field.get("/FT", "")).strip()
                    if ft != "/Sig":
                        # Recurse into kids
                        if "/Kids" in field:
                            walk_fields(field["/Kids"])
                        continue

                    sig_info = _process_sig_field(field, pdf_path, file_size, findings)
                    if sig_info:
                        sig_infos.append(sig_info)
                    elif "/V" not in field:
                        # Unsigned signature field
                        field_name = str(field.get("/T", "Unknown"))
                        findings.append(_finding(
                            "MEDIUM", "Unsigned Signature Field Present",
                            f"Field '{field_name}' is a signature field but has no signature (/V absent).",
                            f"Field: {field_name}"
                        ))
                except Exception as e:
                    logger.debug("Error processing field: %s", e)

        walk_fields(acroform["/Fields"])

        module_data["count"] = len(sig_infos)
        module_data["signatures"] = sig_infos

    except Exception as exc:
        logger.warning("AcroForm traversal error: %s", exc)
        raise


def _process_sig_field(field, pdf_path: str, file_size: int, findings: List) -> Dict | None:
    """Extract and validate a single /Sig field."""
    try:
        import pikepdf
        if "/V" not in field:
            return None

        v = field["/V"]
        sig_info: Dict = {}

        # Basic fields
        sig_info["subfilter"] = str(v.get("/SubFilter", ""))
        sig_info["name"] = str(v.get("/Name", ""))
        sig_info["reason"] = str(v.get("/Reason", ""))
        sig_info["location"] = str(v.get("/Location", ""))
        signing_time_raw = str(v.get("/M", ""))
        sig_info["signing_time_raw"] = signing_time_raw

        # ByteRange
        byte_range = None
        if "/ByteRange" in v:
            try:
                byte_range = [int(x) for x in v["/ByteRange"]]
                sig_info["byte_range"] = byte_range
                coverage = _compute_byte_range_coverage(byte_range, file_size)
                sig_info["byte_range_coverage_pct"] = round(coverage * 100, 2)
            except Exception:
                sig_info["byte_range"] = []
                sig_info["byte_range_coverage_pct"] = 0.0

        # ByteRange validation
        br_valid, br_detail = _validate_byte_range(pdf_path, byte_range)
        sig_info["byte_range_valid"] = br_valid
        if not br_valid:
            findings.append(_finding(
                "CRITICAL", "Signature ByteRange Mismatch",
                f"The signed byte ranges do not match the file content. {br_detail}",
                br_detail
            ))
        else:
            # Check for unsigned bytes at end of file
            if byte_range and len(byte_range) >= 4:
                signed_end = byte_range[2] + byte_range[3]
                if signed_end < file_size:
                    unsigned_bytes = file_size - signed_end
                    findings.append(_finding(
                        "CRITICAL", "Content Outside Signed ByteRange",
                        f"{unsigned_bytes} bytes exist beyond the signed region (offset {signed_end}–{file_size}). "
                        "This is a strong indicator of an incremental-save attack.",
                        f"signed_end={signed_end}, file_size={file_size}, unsigned_bytes={unsigned_bytes}"
                    ))

        # Certificate parsing
        cert_info = _parse_cert(v)
        sig_info["certificate"] = cert_info
        if cert_info.get("expired"):
            findings.append(_finding(
                "HIGH", "Expired Signer Certificate",
                f"The signer certificate for '{cert_info.get('subject_cn', 'Unknown')}' "
                f"expired on {cert_info.get('not_after', 'unknown')}.",
                f"Subject={cert_info.get('subject_cn')}, NotAfter={cert_info.get('not_after')}"
            ))

        return sig_info
    except Exception as e:
        logger.debug("Error processing sig field: %s", e)
        return None


def _validate_byte_range(pdf_path: str, byte_range) -> tuple[bool, str]:
    """Verify that declared ByteRange positions are readable in the file."""
    if not byte_range or len(byte_range) < 4:
        return True, "No ByteRange to validate"
    try:
        b0, l0, b1, l1 = byte_range[0], byte_range[1], byte_range[2], byte_range[3]
        with open(pdf_path, "rb") as f:
            f.seek(0, 2)
            total = f.tell()
            if b0 < 0 or b1 < 0 or l0 < 0 or l1 < 0:
                return False, "Negative ByteRange values"
            if b0 + l0 > total or b1 + l1 > total:
                return False, f"ByteRange extends beyond file (file={total})"
        return True, "OK"
    except Exception as e:
        return False, str(e)


def _compute_byte_range_coverage(byte_range, file_size: int) -> float:
    """Return fraction of file covered by ByteRange."""
    if not byte_range or len(byte_range) < 4 or file_size == 0:
        return 0.0
    covered = byte_range[1] + byte_range[3]
    return min(covered / file_size, 1.0)


def _parse_cert(v) -> Dict:
    """Parse the /Contents DER blob to extract certificate info."""
    info: Dict = {
        "subject_cn": None,
        "issuer_cn": None,
        "not_before": None,
        "not_after": None,
        "expired": False,
    }
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from datetime import datetime, timezone
        import pikepdf

        contents = bytes(v["/Contents"])
        # PKCS#7/CMS — try to extract cert from SignedData
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            certs = pkcs7.load_der_pkcs7_certificates(contents)
            if certs:
                cert = certs[0]
                info["subject_cn"] = cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else str(cert.subject)
                info["issuer_cn"] = cert.issuer.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value if cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else str(cert.issuer)
                info["not_before"] = cert.not_valid_before_utc.isoformat()
                info["not_after"] = cert.not_valid_after_utc.isoformat()
                info["expired"] = cert.not_valid_after_utc < datetime.now(timezone.utc)
        except Exception:
            # Fallback: try DER certificate directly
            try:
                cert = x509.load_der_x509_certificate(contents, default_backend())
                info["subject_cn"] = str(cert.subject)
                info["expired"] = cert.not_valid_after_utc < datetime.now(timezone.utc)
            except Exception:
                pass
    except Exception as e:
        logger.debug("Cert parse error: %s", e)
    return info


def _detect_incremental_save_attack(pdf_path: str, findings: List, module_data: Dict):
    """Detect incremental-save attacks by counting %%EOF markers."""
    try:
        with open(pdf_path, "rb") as f:
            raw = f.read()
        eof_count = raw.count(b"%%EOF")
        module_data["eof_count"] = eof_count

        if module_data.get("count", 0) > 0 and eof_count > 1:
            module_data["incremental_save_attack"] = True
            # Already flagged per-sig above; add structural note
            findings.append(_finding(
                "HIGH", "Multiple %%EOF Markers With Signatures",
                f"Found {eof_count} %%EOF markers in a signed document. "
                "This pattern is consistent with an incremental-save attack where content was appended after signing.",
                f"%%EOF count={eof_count}"
            ))
    except Exception as e:
        logger.debug("EOF detection error: %s", e)


def _get_file_size(pdf_path: str) -> int:
    import os
    return os.path.getsize(pdf_path)


def _finding(severity: str, title: str, detail: str, evidence: str) -> Dict:
    return {
        "module": "Signatures",
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
    }

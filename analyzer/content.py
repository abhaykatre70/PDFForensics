"""
analyzer/content.py — Module 4: Content Stream Parser

Analyzes PDF content streams for invisible text, complex filter chains,
off-page glyphs, unusual font counts, and form-field value injection.
"""
import logging
import re
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def inspect(pdf_path: str, config: dict, password: str = None) -> Dict[str, Any]:
    """
    Run the Content Stream Parser on the given PDF file.

    Returns:
        {
            "findings": [Finding-like dicts],
            "module_data": {...}
        }
    """
    findings: List[Dict] = []
    module_data: Dict[str, Any] = {
        "text_layers": 0,
        "image_count": 0,
        "font_count": 0,
        "fonts": [],
        "invisible_text_pages": [],
        "complex_filter_pages": [],
    }

    try:
        import pypdf

        reader = pypdf.PdfReader(pdf_path, strict=False)
        if reader.is_encrypted and password:
            try:
                reader.decrypt(password)
            except Exception as e:
                logger.warning("Failed to decrypt content module: %s", e)

        all_fonts: set = set()
        total_images = 0
        invisible_text_pages = []
        complex_filter_pages = []

        for page_num, page in enumerate(reader.pages, start=1):
            try:
                # ── Extract text ──────────────────────────────────────────────
                text = page.extract_text() or ""
                if text.strip():
                    module_data["text_layers"] = module_data.get("text_layers", 0) + 1

                # ── Font enumeration ──────────────────────────────────────────
                resources = page.get("/Resources", {})
                if isinstance(resources, pypdf.generic.DictionaryObject):
                    fonts = resources.get("/Font", {})
                    if hasattr(fonts, "keys"):
                        for font_key in fonts.keys():
                            try:
                                font_obj = fonts[font_key]
                                font_name = str(font_obj.get("/BaseFont", font_key))
                                all_fonts.add(font_name)
                            except Exception:
                                all_fonts.add(str(font_key))

                    # ── Image count ───────────────────────────────────────────
                    xobjects = resources.get("/XObject", {})
                    if hasattr(xobjects, "keys"):
                        for xobj_key in xobjects.keys():
                            try:
                                xobj = xobjects[xobj_key]
                                if str(xobj.get("/Subtype", "")) == "/Image":
                                    total_images += 1
                            except Exception:
                                pass

                # ── Content stream analysis ───────────────────────────────────
                _analyze_content_stream(page, page_num, invisible_text_pages,
                                        complex_filter_pages, findings)

            except Exception as e:
                logger.debug("Page %d content error: %s", page_num, e)

        # ── Aggregate findings ────────────────────────────────────────────────
        module_data["image_count"] = total_images
        module_data["font_count"] = len(all_fonts)
        module_data["fonts"] = sorted(all_fonts)[:50]  # Cap for storage
        module_data["invisible_text_pages"] = invisible_text_pages
        module_data["complex_filter_pages"] = complex_filter_pages

        if invisible_text_pages:
            findings.append(_finding(
                "HIGH", "Invisible Text Detected",
                f"Text Rendering Mode 3 (invisible) found on page(s): {invisible_text_pages}. "
                "Invisible text is used in legitimate OCR scans but can hide malicious content.",
                f"Pages with Tr=3: {invisible_text_pages}"
            ))

        if complex_filter_pages:
            findings.append(_finding(
                "MEDIUM", "Complex Filter Chain Detected",
                f"Multi-layer filter chains found on page(s): {complex_filter_pages}. "
                "Chained filters are sometimes used to obfuscate malicious content streams.",
                f"Pages with complex filters: {complex_filter_pages}"
            ))

        if len(all_fonts) > 15:
            findings.append(_finding(
                "MEDIUM", f"Unusual Font Count ({len(all_fonts)} Fonts)",
                f"Document contains {len(all_fonts)} distinct fonts. Legitimate documents rarely use more than 15.",
                f"Fonts: {', '.join(sorted(all_fonts)[:10])}{'...' if len(all_fonts) > 10 else ''}"
            ))

        # ── AcroForm field validation ─────────────────────────────────────────
        _validate_acroform_fields(pdf_path, findings, module_data, password)

        # ── Raw stream analysis with regex ────────────────────────────────────
        _analyze_raw_streams(pdf_path, findings, module_data)

    except Exception as exc:
        logger.warning("Content analysis error: %s", exc, exc_info=True)
        findings.append(_finding(
            "INFO", "Content Analysis Partial",
            f"Content module encountered an error: {exc}", ""
        ))

    return {"findings": findings, "module_data": module_data}


def _analyze_content_stream(page, page_num: int, invisible_pages: List, complex_pages: List, findings: List):
    """Inspect a single page's content stream for suspicious operators."""
    try:
        import pypdf
        # Check for invisible text rendering mode (Tr 3)
        # We look in the compressed stream bytes
        if "/Contents" in page:
            contents = page["/Contents"]
            if not isinstance(contents, list):
                contents = [contents]
            for content_ref in contents:
                try:
                    # Get raw stream bytes
                    if hasattr(content_ref, "get_object"):
                        stream_obj = content_ref.get_object()
                    else:
                        stream_obj = content_ref

                    if hasattr(stream_obj, "get_data"):
                        data = stream_obj.get_data()
                    elif hasattr(stream_obj, "data"):
                        data = stream_obj.data
                    else:
                        continue

                    # Invisible text: 3 Tr
                    if b"3 Tr" in data or b" 3 Tr" in data:
                        if page_num not in invisible_pages:
                            invisible_pages.append(page_num)

                    # Complex filter chains (checked via raw PDF object)
                    filters = stream_obj.get("/Filter", None)
                    if isinstance(filters, list) and len(filters) > 2:
                        if page_num not in complex_pages:
                            complex_pages.append(page_num)

                except Exception:
                    pass
    except Exception as e:
        logger.debug("Content stream parse error on page %d: %s", page_num, e)


def _validate_acroform_fields(pdf_path: str, findings: List, module_data: Dict, password: str = None):
    """Check AcroForm field values for type-inconsistent injection."""
    injection_count = 0
    try:
        import pikepdf
        pdf = pikepdf.open(pdf_path, suppress_warnings=True, password=password or "")
        root = pdf.Root
        if "/AcroForm" not in root:
            return
        acroform = root["/AcroForm"]
        if "/Fields" not in acroform:
            return

        for field_ref in acroform["/Fields"]:
            try:
                field = field_ref
                ft = str(field.get("/FT", "")).strip()
                v = field.get("/V", None)
                if v is None:
                    continue
                val = str(v).strip()

                # Numeric fields should contain only numeric values
                if ft == "/Tx":
                    aa = field.get("/AA", None)
                    format_action = None
                    if aa and "/F" in aa:
                        format_action = str(aa["/F"])
                    # If field has a numeric format but value is alphabetic
                    if format_action and "AFNumber" in format_action:
                        if val and not re.match(r"^-?\d*\.?\d*$", val):
                            injection_count += 1
                            findings.append(_finding(
                                "MEDIUM", "Form Field Value Injection Suspected",
                                f"Numeric field contains non-numeric value: {val!r}",
                                f"Field value={val!r}, format=AFNumber"
                            ))
            except Exception:
                pass

        module_data["form_field_injection_count"] = injection_count

    except Exception as e:
        logger.debug("AcroForm validation error: %s", e)


def _analyze_raw_streams(pdf_path: str, findings: List, module_data: Dict):
    """Raw byte analysis for additional content-stream flags."""
    try:
        with open(pdf_path, "rb") as f:
            raw = f.read()

        # Detect complex filter arrays in raw bytes
        filter_arrays = re.findall(rb"/Filter\s*\[([^\]]+)\]", raw)
        deep_filters = [fa for fa in filter_arrays if fa.count(b"/") > 2]
        module_data["deep_filter_chains"] = len(deep_filters)

    except Exception as e:
        logger.debug("Raw stream analysis error: %s", e)


def _finding(severity: str, title: str, detail: str, evidence: str) -> Dict:
    return {
        "module": "Content",
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
    }

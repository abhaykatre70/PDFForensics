"""
analyzer/visual.py — Module 5: Visual Forensics Engine

Rasterizes PDF pages and applies image forensics including ELA
(Error Level Analysis), uniform region detection, and format analysis.
"""
import logging
import os
import tempfile
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

MAX_PAGES_VISUAL = 10
DPI = 150
ELA_QUALITY = 75
ELA_DIFF_THRESHOLD = 50
UNIFORM_STDDEV_THRESHOLD = 0.5


def inspect(pdf_path: str, config: dict) -> Dict[str, Any]:
    """
    Run the Visual Forensics Engine on the given PDF file.

    Returns:
        {
            "findings": [Finding-like dicts],
            "module_data": {...}
        }
    """
    findings: List[Dict] = []
    module_data: Dict[str, Any] = {
        "pages_analyzed": 0,
        "image_formats": [],
        "scan_indicators": [],
        "ela_anomaly_pages": [],
        "uniform_region_pages": [],
        "jpeg_count": 0,
        "dimension_anomalies": [],
    }

    tmp_dir = tempfile.mkdtemp(prefix="pdf_visual_")
    try:
        _analyze_raw_bytes(pdf_path, findings, module_data)
        _check_page_dimensions(pdf_path, findings, module_data)
        _run_visual_rasterization(pdf_path, tmp_dir, findings, module_data, config)
    except Exception as exc:
        logger.warning("Visual forensics error: %s", exc, exc_info=True)
        findings.append(_finding(
            "INFO", "Visual Analysis Partial",
            f"Visual forensics module encountered an error: {exc}", ""
        ))
    finally:
        _cleanup_dir(tmp_dir)

    return {"findings": findings, "module_data": module_data}


# ── Sub-routines ────────────────────────────────────────────────────────────────

def _analyze_raw_bytes(pdf_path: str, findings: List, module_data: Dict):
    """Check raw bytes for scan and JPEG embedding indicators."""
    with open(pdf_path, "rb") as f:
        raw = f.read()

    # Scanned document indicator
    if b"CCITTFaxDecode" in raw:
        module_data["scan_indicators"].append("CCITTFaxDecode filter")
        findings.append(_finding(
            "MEDIUM", "Scanned (Rasterized) Page Indicator",
            "CCITTFaxDecode filter detected — document likely originated as a scanned image. "
            "Verify content was not digitally composited.",
            "CCITTFaxDecode found in raw bytes"
        ))

    # Count embedded JPEG images
    jpeg_count = raw.count(b"\xff\xd8\xff")
    module_data["jpeg_count"] = jpeg_count
    if jpeg_count > 5:
        findings.append(_finding(
            "MEDIUM", f"High JPEG Image Count ({jpeg_count})",
            f"Document contains {jpeg_count} embedded JPEG images. "
            "A high number of JPEG images may indicate image-composition or splicing.",
            f"JFIF/Exif SOI markers found: {jpeg_count}"
        ))

    # Image format detection
    formats = []
    if b"\xff\xd8\xff" in raw:
        formats.append("JPEG")
    if b"\x89PNG" in raw:
        formats.append("PNG")
    if b"II*\x00" in raw or b"MM\x00*" in raw:
        formats.append("TIFF")
    module_data["image_formats"] = formats


def _check_page_dimensions(pdf_path: str, findings: List, module_data: Dict):
    """Check for abnormally small page dimensions."""
    try:
        import pypdf
        reader = pypdf.PdfReader(pdf_path, strict=False)
        anomalies = []
        for i, page in enumerate(reader.pages, start=1):
            mb = page.mediabox
            width = float(mb.width)
            height = float(mb.height)
            if width < 10 or height < 10:
                anomalies.append({"page": i, "width_pts": width, "height_pts": height})
                findings.append(_finding(
                    "HIGH", f"Abnormal Page Dimension on Page {i}",
                    f"Page {i} has dimensions {width:.1f} × {height:.1f} pts (< 10 pts threshold). "
                    "Micro-pages can be used to hide content or defeat visual inspection.",
                    f"Page={i}, width={width:.1f}pts, height={height:.1f}pts"
                ))
        module_data["dimension_anomalies"] = anomalies
    except Exception as e:
        logger.debug("Dimension check error: %s", e)


def _run_visual_rasterization(pdf_path: str, tmp_dir: str, findings: List, module_data: Dict, config: dict):
    """
    Rasterize up to MAX_PAGES_VISUAL pages and run pixel-level forensics.
    (pdf2image / Poppler required)
    """
    try:
        from pdf2image import convert_from_path
        from PIL import Image, ImageChops, ImageStat

        poppler_path = config.get("POPPLER_PATH") or None

        convert_kwargs = dict(
            pdf_path=pdf_path,
            dpi=DPI,
            output_folder=tmp_dir,
            first_page=1,
            last_page=MAX_PAGES_VISUAL,
            fmt="ppm",
        )
        if poppler_path:
            convert_kwargs["poppler_path"] = poppler_path

        pages = convert_from_path(**convert_kwargs)
        module_data["pages_analyzed"] = len(pages)

        ela_anomaly_pages = []
        uniform_region_pages = []

        for page_num, pil_img in enumerate(pages, start=1):
            try:
                # ── Uniform region detection ──────────────────────────────────
                gray = pil_img.convert("L")
                w, h = gray.size
                # Scan 100×100 regions
                step = 100
                for x in range(0, w - step, step * 2):
                    for y in range(0, h - step, step * 2):
                        region = gray.crop((x, y, x + step, y + step))
                        stat = ImageStat.Stat(region)
                        if stat.stddev[0] < UNIFORM_STDDEV_THRESHOLD:
                            if page_num not in uniform_region_pages:
                                uniform_region_pages.append(page_num)

                # ── Error Level Analysis (ELA) ─────────────────────────────────
                ela_path = os.path.join(tmp_dir, f"ela_page_{page_num}.jpg")
                pil_img.save(ela_path, "JPEG", quality=ELA_QUALITY)
                ela_img = Image.open(ela_path)

                orig_rgb = pil_img.convert("RGB")
                ela_rgb = ela_img.convert("RGB")

                if orig_rgb.size != ela_rgb.size:
                    ela_rgb = ela_rgb.resize(orig_rgb.size, Image.LANCZOS)

                diff = ImageChops.difference(orig_rgb, ela_rgb)
                max_diff = _max_diff_in_regions(diff, step=100)
                if max_diff > ELA_DIFF_THRESHOLD:
                    ela_anomaly_pages.append({"page": page_num, "max_diff": max_diff})

            except Exception as e:
                logger.debug("Per-page visual error on page %d: %s", page_num, e)

        module_data["ela_anomaly_pages"] = ela_anomaly_pages
        module_data["uniform_region_pages"] = uniform_region_pages

        if uniform_region_pages:
            findings.append(_finding(
                "LOW", "Suspiciously Uniform Image Regions Detected",
                f"Page(s) {uniform_region_pages} contain regions with near-zero pixel variance "
                "(std_dev < 0.5). May indicate copy-paste compositing.",
                f"Uniform pages: {uniform_region_pages}"
            ))

        if ela_anomaly_pages:
            findings.append(_finding(
                "MEDIUM", "ELA Anomaly Detected (Possible Image Manipulation)",
                f"Error Level Analysis identified potential manipulation on page(s): "
                f"{[x['page'] for x in ela_anomaly_pages]}. Re-saved JPEG regions show "
                f"unexpectedly high pixel differences (> {ELA_DIFF_THRESHOLD}).",
                f"ELA anomaly pages: {ela_anomaly_pages}"
            ))

    except ImportError:
        logger.info("pdf2image or Pillow not available — skipping rasterization forensics")
        module_data["pages_analyzed"] = 0
        findings.append(_finding(
            "INFO", "Visual Rasterization Skipped",
            "pdf2image or Poppler is not installed. Pixel-level forensics were not performed.",
            "Install pdf2image and poppler-utils to enable visual forensics."
        ))
    except Exception as e:
        logger.warning("Rasterization error: %s", e)


def _max_diff_in_regions(diff_img, step: int = 100) -> int:
    """Return the maximum pixel difference across all step×step regions."""
    from PIL import ImageStat
    w, h = diff_img.size
    max_val = 0
    for x in range(0, w - step, step):
        for y in range(0, h - step, step):
            region = diff_img.crop((x, y, x + step, y + step))
            stat = ImageStat.Stat(region)
            region_max = int(max(stat.extrema[c][1] for c in range(3)))
            if region_max > max_val:
                max_val = region_max
    return max_val


def _cleanup_dir(path: str):
    """Silently clean up a temporary directory."""
    try:
        import shutil
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


def _finding(severity: str, title: str, detail: str, evidence: str) -> Dict:
    return {
        "module": "Visual",
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
    }

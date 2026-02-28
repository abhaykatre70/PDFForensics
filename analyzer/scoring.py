"""
analyzer/scoring.py — Trust Score aggregation and report generation.

Computes a deduction-from-baseline Trust Score starting at 100.
"""
from typing import List, Dict, Any

SEVERITY_DEDUCTIONS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 3,
    "INFO": 0,
}

CLASSIFICATIONS = [
    (80, 100, "Likely Authentic"),
    (60, 79, "Suspicious"),
    (35, 59, "High Risk"),
    (0, 34, "Compromised"),
]


def compute(findings: List[Dict]) -> Dict[str, Any]:
    """
    Compute Trust Score and classification from a list of finding dicts.

    Returns:
        {
            "trust_score": int,
            "classification": str,
            "severity_counts": {"CRITICAL": n, ...},
            "deduction_detail": [...]
        }
    """
    score = 100
    severity_counts: Dict[str, int] = {k: 0 for k in SEVERITY_DEDUCTIONS}
    deduction_detail = []

    for finding in findings:
        sev = finding.get("severity", "INFO").upper()
        deduction = SEVERITY_DEDUCTIONS.get(sev, 0)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if deduction > 0:
            score -= deduction
            deduction_detail.append({
                "title": finding.get("title"),
                "severity": sev,
                "deduction": deduction,
            })

    score = max(0, score)  # Floor at 0

    classification = "Compromised"
    for low, high, label in CLASSIFICATIONS:
        if low <= score <= high:
            classification = label
            break

    return {
        "trust_score": score,
        "classification": classification,
        "severity_counts": severity_counts,
        "deduction_detail": deduction_detail,
    }


def get_classification_color(classification: str) -> str:
    """Return a CSS color class for a given classification."""
    return {
        "Likely Authentic": "success",
        "Suspicious": "warning",
        "High Risk": "danger-light",
        "Compromised": "danger",
    }.get(classification, "secondary")

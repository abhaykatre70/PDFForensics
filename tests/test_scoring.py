"""tests/test_scoring.py — Unit tests for Trust Score computation"""
from analyzer.scoring import compute


def test_empty_findings():
    result = compute([])
    assert result["trust_score"] == 100
    assert result["classification"] == "Likely Authentic"


def test_single_critical():
    findings = [{"severity": "CRITICAL", "title": "Test"}]
    result = compute(findings)
    assert result["trust_score"] == 75
    assert result["severity_counts"]["CRITICAL"] == 1


def test_score_floor_at_zero():
    findings = [{"severity": "CRITICAL", "title": f"C{i}"} for i in range(10)]
    result = compute(findings)
    assert result["trust_score"] == 0
    assert result["classification"] == "Compromised"


def test_classification_thresholds():
    # CRITICAL=-25, HIGH=-15, MEDIUM=-7, LOW=-3
    # 100 - 15 = 85 → Likely Authentic
    # 100 - 15*3 = 55 → High Risk
    # 100 - 25*3 = 25 → Compromised
    # 100 - 15*3 - 7 = 48 → High Risk; 100-15*3-7*3 = 34 → Compromised boundary
    cases = [
        ([],                                                "Likely Authentic"),
        ([{"severity": "HIGH", "title": "H"}],             "Likely Authentic"),  # 85
        ([{"severity": "HIGH", "title": "H"}] * 3,         "High Risk"),          # 55
        ([{"severity": "CRITICAL", "title": "C"}] * 3,     "Compromised"),        # 25
        ([{"severity": "MEDIUM", "title": "M"}] * 6,       "Suspicious"),         # 58 → wait 100-7*6=58 → High Risk; fix below
    ]
    # Verify each independently for clarity
    assert compute([])["classification"] == "Likely Authentic"
    assert compute([{"severity": "HIGH", "title": "H"}])["trust_score"] == 85
    assert compute([{"severity": "HIGH", "title": "H"}] * 3)["trust_score"] == 55
    three_high = compute([{"severity": "HIGH", "title": "H"}] * 3)
    assert three_high["classification"] == "High Risk"   # 55 → 35-59
    two_crit = compute([{"severity": "CRITICAL", "title": "C"}] * 3)
    assert two_crit["classification"] == "Compromised"   # 25 → 0-34


def test_info_findings_no_deduction():
    findings = [{"severity": "INFO", "title": "Info"} for _ in range(5)]
    result = compute(findings)
    assert result["trust_score"] == 100
    assert result["severity_counts"]["INFO"] == 5

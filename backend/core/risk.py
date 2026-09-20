"""
risk.py — Adaptive Forensic Risk Scoring (AFRS) engine for TraceShield X++
Combines ML anomaly score, rule-based detection, and behavioral factors
into a single interpretable risk score (0–100).
"""

from typing import Dict, Any


def calculate_risk(
    anomaly_score: float,
    detection_result: Dict[str, Any],
    row: Dict[str, Any],
    anomaly: bool = False,
) -> Dict[str, Any]:
    """
    Compute a composite risk score from multiple signal sources.

    Args:
        anomaly_score:    Normalized ML anomaly score in [0, 1].
        detection_result: Output of summarize_alerts() — must contain "flags" list.
        row:              Raw log dict with behavioral features.

    Returns:
        Dict with risk_score, risk_level, and per-component breakdown.
    """
    # 1. ML contribution (max 40)
    ml_score = float(anomaly_score) * 40

    # 2. Rule contribution (max ~36, 3 rules * 12)
    flags = detection_result.get("flags", [])
    rule_score = len(flags) * 12

    # 3. IP reputation contribution (max 15)
    ip_rep = row.get("ip_reputation_score", 0) or 0
    ip_score = float(ip_rep) * 15

    # 4. Brute-force behavior contribution (max 9)
    failed_logins = min(row.get("failed_logins", 0) or 0, 5)
    brute_score = float(failed_logins) * 1.8

    # Final score — clamped to [0, 100]
    total = ml_score + rule_score + ip_score + brute_score
    total_score = round(max(0.0, min(100.0, total)), 2)

    # Consistency cap: no anomaly + no flags → cap at 49
    flags = detection_result.get("flags", [])
    if not anomaly and len(flags) == 0:
        total_score = min(total_score, 49.0)

    risk_level = _map_risk_level(total_score)

    return {
        "risk_score": total_score,
        "risk_level": risk_level,
        "breakdown": {
            "ml_contribution":          round(ml_score, 2),
            "rule_contribution":        round(rule_score, 2),
            "ip_contribution":          round(ip_score, 2),
            "brute_force_contribution": round(brute_score, 2),
        },
    }


def _map_risk_level(score: float) -> str:
    """
    Map a numeric risk score to a categorical risk level.

    Args:
        score: Risk score in [0, 100].

    Returns:
        One of "CRITICAL", "HIGH", "MEDIUM", or "LOW".
    """
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def get_risk_color(level: str) -> str:
    """
    Return a hex color code for a given risk level.

    Args:
        level: Risk level string.

    Returns:
        Hex color string.
    """
    colors = {
        "CRITICAL": "#E24B4A",
        "HIGH":     "#EF9F27",
        "MEDIUM":   "#FAC775",
        "LOW":      "#97C459",
    }
    return colors.get(level, "#999999")

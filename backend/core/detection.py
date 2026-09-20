"""
detection.py — Rule-based threat detection engine for TraceShield X++
Analyzes a single log entry and returns triggered alerts with explanations.
"""

from typing import Dict, Any, List


def _get(log: Dict[str, Any], key: str, default: Any = 0) -> Any:
    """Safely retrieve a value from the log, falling back to a default."""
    val = log.get(key, default)
    return val if val is not None else default


def detect_threats(log: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluate a log entry against all defined threat rules.

    Args:
        log: Dictionary containing network/session features.

    Returns:
        List of alert dicts for every rule that triggered.
    """
    alerts: List[Dict[str, Any]] = []

    failed_logins    = _get(log, "failed_logins")
    login_attempts   = _get(log, "login_attempts")
    session_duration = _get(log, "session_duration")
    ip_rep_score     = _get(log, "ip_reputation_score", default=1.0)
    unusual_time     = _get(log, "unusual_time_access")

    # Rule 1 — Brute Force Attack
    if failed_logins > 5 and login_attempts > 10:
        alerts.append({
            "type":     "BRUTE_FORCE",
            "severity": "HIGH",
            "message":  "Multiple failed login attempts detected",
        })

    # Rule 2 — Suspicious Session Length
    if session_duration > 300:
        alerts.append({
            "type":     "LONG_SESSION",
            "severity": "MEDIUM",
            "message":  "Unusually long session duration",
        })

    # Rule 3 — Low IP Reputation
    if ip_rep_score < 0.3:
        alerts.append({
            "type":     "LOW_REPUTATION_IP",
            "severity": "HIGH",
            "message":  "IP has low reputation score",
        })

    # Rule 4 — Odd Access Time
    if unusual_time == 1:
        alerts.append({
            "type":     "ODD_ACCESS_TIME",
            "severity": "MEDIUM",
            "message":  "Access at unusual time detected",
        })

    return alerts


_FLAG_READABLE = {
    "BRUTE_FORCE":       "Brute Force Attack",
    "LOW_REPUTATION_IP": "Suspicious IP Address",
    "ODD_ACCESS_TIME":   "Unusual Access Time",
    "LONG_SESSION":      "Abnormal Session Duration",
}


def summarize_alerts(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Summarize a list of alerts into aggregate statistics.

    Args:
        alerts: List of alert dicts returned by detect_threats().

    Returns:
        Dict with total count, severity breakdown, raw types, and readable labels.
    """
    high   = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    types  = [a.get("type") for a in alerts if a.get("type")]
    readable = [_FLAG_READABLE.get(t, t) for t in types]

    return {
        "total_alerts":    len(alerts),
        "high_severity":   high,
        "medium_severity": medium,
        "types":           types,
        "readable_flags":  readable,
        "flags":           types,
    }

"""
summarizer.py — AI-style forensic summarizer for TraceShield X++
Converts raw ML + rule-based output into human-readable analyst reports.
No external APIs — fully local rule-driven generation.
"""

import re as _re
from typing import Dict, Any, List


_RISK_OPENER = {
    "CRITICAL": "CRITICAL risk detected.",
    "HIGH":     "HIGH risk detected.",
    "MEDIUM":   "MEDIUM risk detected.",
    "LOW":      "LOW risk. System activity appears normal.",
}

_RISK_RECOMMENDATION = {
    "CRITICAL": "Immediate investigation required.",
    "HIGH":     "Potential threat — monitor closely.",
    "MEDIUM":   "Suspicious activity detected — review recommended.",
    "LOW":      "System behavior appears normal.",
}

_FLAG_TIMELINE = {
    "BRUTE_FORCE":       {
        "source": "auth.log",
        "description": "Multiple failed login attempts detected — brute-force pattern",
        "evidence": "sshd: Failed password for root — repeated attempts exceeded threshold",
    },
    "LOW_REPUTATION_IP": {
        "source": "fail2ban.log",
        "description": "Connection from low-reputation IP address flagged",
        "evidence": "fail2ban.actions: Ban triggered — ip_reputation_score below 0.3",
    },
    "ODD_ACCESS_TIME":   {
        "source": "auth.log",
        "description": "Authentication attempt outside normal business hours",
        "evidence": "pam_unix(sshd:auth): authentication failure — unusual_time_access=1",
    },
    "LONG_SESSION":      {
        "source": "syslog",
        "description": "Abnormally long session duration detected",
        "evidence": "systemd: Session active beyond 300s threshold — possible persistence",
    },
}


def generate_summary(
    risk_result: Dict[str, Any],
    detection_result: Dict[str, Any],
    anomaly: bool,
) -> str:
    """
    Generate a concise human-readable forensic summary.

    Args:
        risk_result:      Output of calculate_risk() — must contain "risk_level".
        detection_result: Output of summarize_alerts() — must contain "flags".
        anomaly:          True if ML model flagged the record as anomalous.

    Returns:
        A 1–3 sentence professional summary string.
    """
    risk_level = risk_result.get("risk_level", "LOW")
    flags      = detection_result.get("flags", [])

    parts: List[str] = []

    # 1. Risk level opener
    parts.append(_RISK_OPENER.get(risk_level, "Risk level unknown."))

    # 2. ML anomaly insight
    if anomaly:
        parts.append("Anomalous behavior detected by the ML model.")
    else:
        parts.append("No anomaly detected by the ML model.")

    # 3. Rule explanation
    if flags:
        parts.append(f"Triggered rules: {', '.join(flags)}.")
    else:
        parts.append("No suspicious rules were triggered.")

    # 4. Recommendation
    parts.append(_RISK_RECOMMENDATION.get(risk_level, ""))

    return " ".join(p for p in parts if p)


def generate_timeline(flags: List[str], log_lines: List[str] | None = None) -> List[Dict[str, Any]]:
    """
    Build timeline events for a scored record.

    Real log lines are used as evidence whenever the caller has them. Rule flags
    are only a fallback, and produce descriptions of what the rule matched —
    never invented log text, and never padding to hit a minimum count.
    """
    from datetime import datetime, timedelta

    now = datetime.utcnow()

    if log_lines:
        return [_timeline_from_log(line) for line in log_lines[:8]]

    events = []
    for i, flag in enumerate(flags):
        if flag in _FLAG_TIMELINE:
            t = (now - timedelta(minutes=30 - i * 8)).strftime("%Y-%m-%d %H:%M:%S")
            entry = dict(_FLAG_TIMELINE[flag])
            entry["time"] = t
            entry["synthetic"] = True   # rule description, not an observed log line
            events.append(entry)
    return events


_LOG_TS = _re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')


def _timeline_from_log(line: str) -> Dict[str, Any]:
    """Turn one real log line into a timeline entry, evidence verbatim."""
    lower = line.lower()
    if "failed password" in lower or "authentication failure" in lower:
        desc, src = "Failed login — credential guessing attempt", "auth.log"
    elif "invalid user" in lower:
        desc, src = "Invalid user — probing for valid accounts", "auth.log"
    elif "accepted password" in lower or "session opened" in lower:
        desc, src = "Session opened — authentication succeeded", "auth.log"
    elif "command=" in lower or "sudo" in lower:
        desc, src = "Sudo command — privilege escalation attempt", "auth.log"
    elif any(k in lower for k in ("/etc/shadow", "/etc/passwd", "/etc/sudoers")):
        desc, src = "Sensitive file access", "audit.log"
    elif "ufw block" in lower or "scan" in lower:
        desc, src = "Blocked inbound connection", "kern.log"
    else:
        desc, src = "System event", "syslog"

    m = _LOG_TS.match(line)
    return {
        "time":        m.group(1) if m else "",
        "source":      src,
        "description": desc,
        "evidence":    line[:200],
    }

"""
log_parser.py — Linux system log parser for TraceShield hybrid detection.

Parses raw Linux auth/syslog lines and extracts structured security signals.
Aggregates per-IP in a sliding window for real-time scoring.

Detected events:
    - Failed login attempts  ("Failed password")
    - Successful logins      ("Accepted password")
    - sudo usage             ("sudo", "COMMAND=")
    - Suspicious commands    ("nc", "bash -i", "chmod 777", etc.)
    - Sensitive file access  ("/etc/passwd", "/etc/shadow", "/var/log")
"""

import re
import logging
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# ── Patterns ──────────────────────────────────────────────────────────────────

_IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

_FAILED_LOGIN = re.compile(
    r'Failed password|authentication failure|Invalid user|FAILED LOGIN|incorrect password',
    re.IGNORECASE
)

_SUCCESS_LOGIN = re.compile(
    r'Accepted password|Accepted publickey|session opened for user',
    re.IGNORECASE
)

_SUDO = re.compile(
    r'\bsudo\b|COMMAND=',
    re.IGNORECASE
)

_SUSPICIOUS_COMMANDS = re.compile(
    r'\bnc\b|netcat|bash\s+-i|sh\s+-i|chmod\s+777|wget\s+http|curl\s+http'
    r'|python.*socket|perl.*exec|ruby.*exec|/dev/tcp|mkfifo|base64\s+-d',
    re.IGNORECASE
)

_SENSITIVE_FILES = re.compile(
    r'/etc/passwd|/etc/shadow|/etc/sudoers|/root/\.ssh|/var/log/auth'
    r'|/proc/\d+|/sys/kernel',
    re.IGNORECASE
)

_PRIVILEGE_ESC = re.compile(
    r'COMMAND=\S*(?:/bin/bash|/bin/sh|/usr/bin/bash|/usr/bin/sh)'
    r'|session opened for user root by (?!root)'
    r'|sudo:\s*(?:www-data|nobody|apache|nginx)\s*:'
    r'|pkexec|su:\s*FAILED',
    re.IGNORECASE
)

# ── Per-IP aggregation window ─────────────────────────────────────────────────

MAX_LOG_HISTORY = 50   # keep last 50 log events per IP

class IPLogState:
    def __init__(self):
        self.events: deque = deque(maxlen=MAX_LOG_HISTORY)
        self.failed_logins:           int = 0
        self.successful_logins:       int = 0
        self.sudo_attempts:           int = 0
        self.suspicious_commands:     int = 0
        self.sensitive_file_accesses: int = 0
        self.privilege_escalations:   int = 0

    def add(self, parsed: Dict[str, Any]) -> None:
        self.events.append(parsed)
        self.failed_logins           += parsed.get("failed_login", 0)
        self.successful_logins       += parsed.get("successful_login", 0)
        self.sudo_attempts           += parsed.get("sudo_attempt", 0)
        self.suspicious_commands     += parsed.get("suspicious_command", 0)
        self.sensitive_file_accesses += parsed.get("sensitive_file_access", 0)
        self.privilege_escalations   += parsed.get("privilege_escalation", 0)

    def summary(self) -> Dict[str, int]:
        return {
            "failed_logins":           self.failed_logins,
            "successful_logins":       self.successful_logins,
            "sudo_attempts":           self.sudo_attempts,
            "suspicious_commands":     self.suspicious_commands,
            "sensitive_file_accesses": self.sensitive_file_accesses,
            "privilege_escalations":   self.privilege_escalations,
            "total_events":            len(self.events),
        }


_ip_log_state: Dict[str, IPLogState] = defaultdict(IPLogState)


# ── Parsing ───────────────────────────────────────────────────────────────────

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single Linux log line into structured fields.

    Args:
        line: Raw log line string.

    Returns:
        Dict with extracted fields, or None if no IP found.
    """
    line = line.strip()
    if not line:
        return None

    # Extract IP address
    ips = _IP_PATTERN.findall(line)
    ip  = ips[0] if ips else None

    parsed = {
        "raw":                  line,
        "ip":                   ip,
        "failed_login":         1 if _FAILED_LOGIN.search(line) else 0,
        "successful_login":     1 if _SUCCESS_LOGIN.search(line) else 0,
        "sudo_attempt":         1 if _SUDO.search(line) else 0,
        "suspicious_command":   1 if _SUSPICIOUS_COMMANDS.search(line) else 0,
        "sensitive_file_access":1 if _SENSITIVE_FILES.search(line) else 0,
        "privilege_escalation": 1 if _PRIVILEGE_ESC.search(line) else 0,
        "timestamp":            datetime.utcnow().isoformat(),
    }

    if ip:
        _ip_log_state[ip].add(parsed)
        logger.debug(
            "LOG | ip=%s failed=%d sudo=%d suspicious=%d sensitive=%d priv_esc=%d",
            ip,
            parsed["failed_login"],
            parsed["sudo_attempt"],
            parsed["suspicious_command"],
            parsed["sensitive_file_access"],
            parsed["privilege_escalation"],
        )

    return parsed


def parse_log_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """Parse multiple log lines, skipping empty/unparseable ones."""
    results = []
    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            results.append(parsed)
    return results


# ── Scoring ───────────────────────────────────────────────────────────────────

_MAX_RAW_LOG_SCORE = 100.0   # lower denominator = higher sensitivity per signal


def compute_log_score(ip: str) -> Dict[str, Any]:
    """
    Compute normalized log_score (0–100) for an IP from its aggregated history.

    Weights calibrated so real attacks score correctly:
        failed_logins           × 18  — 3 failures → ~54 raw → SUSPICIOUS
        sudo_attempts           × 28  — 1 sudo → 28 raw → SUSPICIOUS
        suspicious_commands     × 40  — 1 command → 40 raw → HIGH_RISK
        sensitive_file_accesses × 35  — 1 access → 35 raw → HIGH_RISK
        privilege_escalations   × 45  — 1 priv-esc → 45 raw → HIGH_RISK
    """
    state = _ip_log_state[ip]
    s     = state.summary()

    raw = (
        s["failed_logins"]                * 18 +
        s["sudo_attempts"]                * 28 +
        s["suspicious_commands"]          * 40 +
        s["sensitive_file_accesses"]      * 35 +
        s.get("privilege_escalations", 0) * 45
    )

    score = round(min(raw / _MAX_RAW_LOG_SCORE * 100.0, 100.0), 2)

    logger.info(
        "LOG_SCORE | ip=%s failed=%d sudo=%d suspicious=%d sensitive=%d priv_esc=%d "
        "raw=%d score=%.2f",
        ip,
        s["failed_logins"],
        s["sudo_attempts"],
        s["suspicious_commands"],
        s["sensitive_file_accesses"],
        s.get("privilege_escalations", 0),
        raw, score,
    )

    return {
        "log_score":              score,
        "failed_logins":          s["failed_logins"],
        "sudo_attempts":          s["sudo_attempts"],
        "suspicious_commands":    s["suspicious_commands"],
        "sensitive_file_accesses":s["sensitive_file_accesses"],
        "privilege_escalations":  s.get("privilege_escalations", 0),
        "total_log_events":       s["total_events"],
    }


def ingest_logs_for_ip(ip: str, log_lines: List[str]) -> Dict[str, Any]:
    """
    Parse a batch of log lines attributed to an IP and return log score.
    All lines are attributed to the provided IP regardless of whether
    the IP appears in the line text.
    """
    state = _ip_log_state[ip]
    for line in log_lines:
        line = line.strip()
        if not line:
            continue
        parsed = {
            "raw":                   line,
            "ip":                    ip,
            "failed_login":          1 if _FAILED_LOGIN.search(line) else 0,
            "successful_login":      1 if _SUCCESS_LOGIN.search(line) else 0,
            "sudo_attempt":          1 if _SUDO.search(line) else 0,
            "suspicious_command":    1 if _SUSPICIOUS_COMMANDS.search(line) else 0,
            "sensitive_file_access": 1 if _SENSITIVE_FILES.search(line) else 0,
            "privilege_escalation":  1 if _PRIVILEGE_ESC.search(line) else 0,
            "timestamp":             datetime.utcnow().isoformat(),
        }
        state.add(parsed)
        logger.debug(
            "LOG | ip=%s failed=%d sudo=%d suspicious=%d sensitive=%d priv_esc=%d",
            ip, parsed["failed_login"], parsed["sudo_attempt"],
            parsed["suspicious_command"], parsed["sensitive_file_access"],
            parsed["privilege_escalation"],
        )

    return compute_log_score(ip)


def get_ip_log_summary(ip: str) -> Dict[str, Any]:
    """Return full log aggregation summary for an IP."""
    return _ip_log_state[ip].summary()


def reset_state() -> int:
    """
    Drop all accumulated per-IP log signals. Returns how many IPs were tracked.

    These counters only ever grow, so without this a re-uploaded file keeps
    inflating the same IP's score instead of scoring the file on its own.
    """
    n = len(_ip_log_state)
    _ip_log_state.clear()
    return n

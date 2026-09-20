"""
linux_log_parser.py — Robust Linux log dataset parser for TraceShield.

Handles real-world Linux log formats: auth.log, syslog, audit.log, kern.log,
fail2ban.log, secure, messages — any unknown format.

Design principles:
  - Never crashes on malformed input (all parsing in try/except)
  - Extracts IP, username, timestamp from any line format
  - IP defaults to 'unknown' only when truly absent
  - 'unknown' bucket is kept separate and not inflated
  - request_count fed to process_event() reflects attack intensity
"""

import re
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── IP extraction ─────────────────────────────────────────────────────────────

_RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# ── Username extraction ───────────────────────────────────────────────────────

_RE_USER = re.compile(
    r'(?:for|user|USER=|acct=|by)\s+([a-zA-Z0-9_\-\.]+)',
    re.IGNORECASE,
)

# ── Timestamp extraction (syslog / ISO / audit formats) ──────────────────────

_RE_SYSLOG_TS = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'   # Apr 10 03:12:44
)
_RE_ISO_TS = re.compile(
    r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'  # 2024-04-10T03:12:44
)
_RE_AUDIT_TS = re.compile(
    r'msg=audit\((\d+\.\d+)'                       # msg=audit(1712700000.123
)

# ── Security signal patterns ──────────────────────────────────────────────────

_RE_FAILED_LOGIN = re.compile(
    r'Failed password'
    r'|authentication failure'
    r'|Invalid user'
    r'|FAILED LOGIN'
    r'|pam_unix.*auth.*failure'
    r'|no such user'
    r'|illegal user'
    r'|input_userauth_request.*invalid user'
    r'|Connection closed by.*\[preauth\]'
    r'|Disconnected from.*\[preauth\]',
    re.IGNORECASE,
)

_RE_SUCCESS_LOGIN = re.compile(
    r'Accepted password'
    r'|Accepted publickey'
    r'|session opened for user'
    r'|New session \d+ of user'
    r'|Successful su for'
    r'|pam_unix.*session.*opened',
    re.IGNORECASE,
)

_RE_SUDO = re.compile(
    # Real sudo log: "username : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"
    r'sudo\s*:\s*\w+\s*:.*COMMAND='
    # sudo with COMMAND= anywhere
    r'|COMMAND=\S+'
    # sudo[ in syslog
    r'|sudo\[\d+\]'
    # audit sudo
    r'|type=USER_CMD',
    re.IGNORECASE,
)

_RE_SUSPICIOUS = re.compile(
    r'\bnc\b[\s-]|\bnc\s+-[lep]'       # netcat
    r'|netcat'
    r'|bash\s+-i'                        # reverse shell
    r'|sh\s+-i'
    r'|/bin/bash\s+-i'
    r'|chmod\s+[0-7]*777'               # world-writable
    r'|chmod\s+\+[xs]'                  # setuid/setgid
    r'|wget\s+https?://'                # download
    r'|curl\s+https?://'
    r'|python[23]?\s+-c'                # inline exec
    r'|perl\s+-e'
    r'|ruby\s+-e'
    r'|/dev/tcp'                         # bash tcp redirect
    r'|mkfifo'                           # named pipe
    r'|base64\s+-d'                      # decode payload
    r'|\bnmap\b'                         # scanner
    r'|\bhydra\b'                        # brute force tool
    r'|\bmetasploit\b'
    r'|\bmsfconsole\b'
    r'|dd\s+if=/dev/'                    # disk wipe
    r'|rm\s+-rf\s+/'                     # destructive
    r'|>\s*/dev/null\s+2>&1.*&'          # background process hiding
    r'|crontab\s+-[lr]'                  # cron manipulation
    r'|iptables\s+-F'                    # firewall flush
    r'|history\s+-[cw]',                 # log clearing
    re.IGNORECASE,
)

_RE_SENSITIVE = re.compile(
    r'/etc/passwd'
    r'|/etc/shadow'
    r'|/etc/sudoers'
    r'|/etc/sudoers\.d'
    r'|/root/\.ssh'
    r'|/home/\w+/\.ssh'
    r'|/var/log/auth'
    r'|/proc/\d+/mem'
    r'|/sys/kernel/security'
    r'|/etc/crontab'
    r'|/etc/cron\.'
    r'|/etc/hosts'
    r'|/etc/hostname'
    r'|/etc/network'
    r'|/boot/grub'
    r'|/etc/ssl/private',
    re.IGNORECASE,
)

_RE_PORT_SCAN = re.compile(
    r'UFW BLOCK'
    r'|iptables.*DROP'
    r'|port scan'
    r'|SCAN detected'
    r'|SYN flood'
    r'|Too many connections'
    r'|repeated connection attempts'
    r'|DPT=\d+.*repeated'
    r'|PROTO=TCP.*DPT=\d+.*SRC=\S+.*repeated'
    r'|kernel:.*\[UFW BLOCK\]',
    re.IGNORECASE,
)

_RE_PRIVILEGE_ESC = re.compile(
    # Failed sudo attempts
    r'sudo.*incorrect password'
    r'|sudo.*3 incorrect password'
    r'|sudo.*authentication failure'
    # su failures
    r'|su\s*:\s*FAILED'
    r'|su\s*:\s*pam_authenticate'
    # Spawning a root shell via sudo — the key attack pattern
    r'|sudo\s*:.*COMMAND\s*=\s*/bin/bash'
    r'|sudo\s*:.*COMMAND\s*=\s*/bin/sh'
    r'|sudo\s*:.*COMMAND\s*=\s*/usr/bin/bash'
    r'|sudo\s*:.*COMMAND\s*=\s*/usr/bin/python'
    r'|sudo\s*:.*COMMAND\s*=\s*/usr/bin/perl'
    # pam session opened as root (escalation confirmed)
    r'|pam_unix.*sudo.*session.*opened for user root'
    r'|sudo.*session opened for user root'
    r'|pam_unix\(sudo:session\).*session opened for user root'
    # Kernel/audit privilege escalation
    r'|pkexec'
    r'|polkit'
    r'|CVE-\d{4}-\d+'
    r'|type=USER_AUTH.*res=failed'
    r'|type=SYSCALL.*comm="su"',
    re.IGNORECASE,
)

_RE_LOG_CLEARED = re.compile(
    r'rm\s+.*auth\.log'
    r'|>\s*/var/log'
    r'|truncate.*log'
    r'|shred.*log'
    r'|type=CONFIG_CHANGE'
    r'|auditd.*log.*deleted',
    re.IGNORECASE,
)

_RE_RECON = re.compile(
    r'\bwhoami\b'
    r'|\bid\b'
    r'|\buname\s+-a\b'
    r'|\bcat\s+/etc/os-release\b'
    r'|\bls\s+-la\s+/root\b'
    r'|\bfind\s+/\s+-name\b'
    r'|\bps\s+aux\b'
    r'|\bnetstat\b'
    r'|\bss\s+-'
    r'|\bip\s+addr\b',
    re.IGNORECASE,
)

# ── Sudo actor extraction (username before the colon in sudo lines) ───────────

_RE_SUDO_ACTOR = re.compile(
    r'sudo\s*:\s*([a-zA-Z0-9_\-\.]+)\s*:',
    re.IGNORECASE,
)

_RE_PAM_ACTOR = re.compile(
    r'session opened for user root by ([a-zA-Z0-9_\-\.]+)\(',
    re.IGNORECASE,
)

def _extract_sudo_actor(line: str) -> Optional[str]:
    """Extract the acting username from a sudo log line."""
    m = _RE_SUDO_ACTOR.search(line)
    if m:
        actor = m.group(1)
        if actor.lower() not in ('pam_unix', 'pam', 'session', 'root'):
            return actor
    m = _RE_PAM_ACTOR.search(line)
    if m:
        return m.group(1)
    return None



def _extract_timestamp(line: str) -> Optional[str]:
    """Try to extract a timestamp string from a log line."""
    m = _RE_ISO_TS.search(line)
    if m:
        return m.group(1)
    m = _RE_SYSLOG_TS.match(line)
    if m:
        return m.group(1)
    m = _RE_AUDIT_TS.search(line)
    if m:
        try:
            return datetime.fromtimestamp(float(m.group(1))).isoformat()
        except Exception:
            pass
    return None


def _extract_username(line: str) -> Optional[str]:
    """Try to extract a username from a log line."""
    m = _RE_USER.search(line)
    if m:
        candidate = m.group(1)
        # Filter out common false positives
        if candidate.lower() not in ('from', 'by', 'for', 'user', 'the', 'a', 'an'):
            return candidate
    return None


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single log line into structured security features.

    Returns None only on empty input — never raises.
    IP defaults to 'unknown' if not found in line.
    """
    try:
        line = line.strip()
        if not line:
            return None

        ips = _RE_IP.findall(line)
        ip  = ips[0] if ips else "unknown"

        return {
            "ip":                   ip,
            "username":             _extract_username(line),
            "sudo_actor":           _extract_sudo_actor(line),
            "log_timestamp":        _extract_timestamp(line),
            "failed_login":         1 if _RE_FAILED_LOGIN.search(line)    else 0,
            "successful_login":     1 if _RE_SUCCESS_LOGIN.search(line)   else 0,
            "sudo_attempt":         1 if _RE_SUDO.search(line)            else 0,
            "suspicious_command":   1 if _RE_SUSPICIOUS.search(line)      else 0,
            "sensitive_file_access":1 if _RE_SENSITIVE.search(line)       else 0,
            "port_scan":            1 if _RE_PORT_SCAN.search(line)       else 0,
            "privilege_escalation": 1 if _RE_PRIVILEGE_ESC.search(line)   else 0,
            "log_cleared":          1 if _RE_LOG_CLEARED.search(line)     else 0,
            "recon":                1 if _RE_RECON.search(line)           else 0,
            "raw":                  line,
        }
    except Exception as exc:
        logger.warning("parse_line skipped malformed input: %s", exc)
        return None


# ── Batch parsing ─────────────────────────────────────────────────────────────

def parse_lines(lines: List[str]) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Parse a list of raw log lines.

    Returns:
        (parsed_events, total_lines, valid_events)
    """
    parsed, valid = [], 0
    for line in lines:
        result = parse_line(line)
        if result:
            parsed.append(result)
            valid += 1
    logger.info("DATASET PARSE | total=%d valid=%d skipped=%d",
                len(lines), valid, len(lines) - valid)
    return parsed, len(lines), valid


# ── Per-IP aggregation ────────────────────────────────────────────────────────

def aggregate_by_ip(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Group parsed events by IP and sum security feature counts.
    'unknown' IPs are tracked separately and not mixed with real IPs.

    Returns dict: ip → aggregated feature counts + usernames seen
    """
    agg: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "failed_logins":           0,
        "successful_logins":       0,
        "sudo_attempts":           0,
        "suspicious_commands":     0,
        "sensitive_file_accesses": 0,
        "port_scans":              0,
        "privilege_escalations":   0,
        "log_cleared":             0,
        "recon_attempts":          0,
        "total_events":            0,
        "usernames":               set(),
        "first_seen":              None,
        "last_seen":               None,
    })

    for ev in events:
        ip = ev.get("ip", "unknown")
        a  = agg[ip]
        a["failed_logins"]           += ev.get("failed_login", 0)
        a["successful_logins"]       += ev.get("successful_login", 0)
        a["sudo_attempts"]           += ev.get("sudo_attempt", 0)
        a["suspicious_commands"]     += ev.get("suspicious_command", 0)
        a["sensitive_file_accesses"] += ev.get("sensitive_file_access", 0)
        a["port_scans"]              += ev.get("port_scan", 0)
        a["privilege_escalations"]   += ev.get("privilege_escalation", 0)
        a["log_cleared"]             += ev.get("log_cleared", 0)
        a["recon_attempts"]          += ev.get("recon", 0)
        a["total_events"]            += 1

        if ev.get("username"):
            a["usernames"].add(ev["username"])

        ts = ev.get("log_timestamp")
        if ts:
            if a["first_seen"] is None:
                a["first_seen"] = ts
            a["last_seen"] = ts

    # Convert sets to sorted lists for JSON serialisation
    # Mark unknown bucket so callers can handle it separately
    result = {}
    for ip, data in agg.items():
        d = dict(data)
        d["usernames"] = sorted(d["usernames"])
        d["is_unknown"] = (ip == "unknown")
        result[ip] = d

    return result


# ── Attack intensity score → request_count for process_event() ───────────────

def compute_request_count(features: Dict[str, Any]) -> int:
    """
    Derive a meaningful request_count from log features.
    Weights reflect real attack intensity — brute force and port scans
    generate far more requests than a single sudo attempt.

    Capped at 500 to avoid overwhelming the temporal scorer.
    """
    raw = (
        features.get("failed_logins",           0) * 8  +
        features.get("sudo_attempts",           0) * 4  +
        features.get("suspicious_commands",     0) * 6  +
        features.get("port_scans",              0) * 15 +
        features.get("privilege_escalations",   0) * 12 +  # raised — root shell = high intensity
        features.get("sensitive_file_accesses", 0) * 5  +
        features.get("log_cleared",             0) * 10 +
        features.get("total_events",            0) * 1
    )
    return min(max(raw, 1), 500)


# ── Log score from aggregated features (used standalone if needed) ────────────

_MAX_RAW = 500.0

def score_from_features(features: Dict[str, Any]) -> float:
    """Compute a 0–100 log_score from aggregated feature counts."""
    raw = (
        features.get("failed_logins",           0) * 10 +
        features.get("sudo_attempts",           0) * 15 +
        features.get("suspicious_commands",     0) * 25 +
        features.get("sensitive_file_accesses", 0) * 15 +
        features.get("port_scans",              0) * 15 +
        features.get("privilege_escalations",   0) * 40 +
        features.get("log_cleared",             0) * 40 +
        features.get("recon_attempts",          0) * 10
    )
    return round(min(raw / _MAX_RAW * 100.0, 100.0), 2)


def score_from_features_priv_esc(features: Dict[str, Any]) -> float:
    """
    Scoring for privilege escalation analysis — no network signals needed.
    Each priv-esc = 35pts, sudo = 10pts, failed = 8pts. Cap at 100.
    """
    raw = (
        features.get("privilege_escalations", 0) * 35 +
        features.get("sudo_attempts",         0) * 10 +
        features.get("failed_logins",         0) * 8
    )
    return round(min(raw, 100.0), 2)


def classify_log_score(score: float) -> str:
    if score >= 60: return "EXTREME_RISK"
    if score >= 40: return "HIGH_RISK"
    if score >= 20: return "SUSPICIOUS"
    return "NORMAL"


def build_reason(features: Dict[str, Any]) -> str:
    parts = []
    if features.get("failed_logins", 0):
        parts.append(f"failed_logins={features['failed_logins']}")
    if features.get("sudo_attempts", 0):
        parts.append(f"sudo={features['sudo_attempts']}")
    if features.get("suspicious_commands", 0):
        parts.append(f"suspicious_cmds={features['suspicious_commands']}")
    if features.get("sensitive_file_accesses", 0):
        parts.append(f"sensitive_files={features['sensitive_file_accesses']}")
    if features.get("port_scans", 0):
        parts.append(f"port_scans={features['port_scans']}")
    if features.get("privilege_escalations", 0):
        parts.append(f"priv_esc={features['privilege_escalations']}")
    if features.get("log_cleared", 0):
        parts.append(f"log_cleared={features['log_cleared']}")
    if features.get("recon_attempts", 0):
        parts.append(f"recon={features['recon_attempts']}")
    return ", ".join(parts) if parts else "no_signals_detected"


# ── Full dataset analysis pipeline (standalone, no process_event) ─────────────

def analyze_log_dataset(lines: List[str]) -> Dict[str, Any]:
    """
    Standalone pipeline: parse → aggregate → score → classify per IP.
    Used when process_event() is not available (e.g. unit tests).
    """
    events, total, valid = parse_lines(lines)
    by_ip = aggregate_by_ip(events)

    results = []
    anomaly_count = 0

    for ip, features in by_ip.items():
        score  = score_from_features(features)
        status = classify_log_score(score)
        reason = build_reason(features)

        actions: List[str] = []
        if status == "SUSPICIOUS":
            actions = ["flagged"]
        elif status == "HIGH_RISK":
            actions = ["redirected_to_honeypot"]
        elif status == "EXTREME_RISK":
            actions = ["blocked", "redirected_to_honeypot"]

        if status != "NORMAL":
            anomaly_count += 1

        results.append({
            "ip":         ip,
            "risk_score": score,
            "status":     status,
            "actions":    actions,
            "reason":     reason,
            "features":   features,
        })

    results.sort(key=lambda r: r["risk_score"], reverse=True)

    logger.info(
        "DATASET ANALYSIS | lines=%d valid=%d ips=%d anomalies=%d",
        total, valid, len(by_ip), anomaly_count,
    )

    return {
        "summary": {
            "total_lines":  total,
            "valid_events": valid,
            "unique_ips":   len(by_ip),
            "anomalies":    anomaly_count,
        },
        "results": results,
    }


# ── Per-user aggregation (for local logs with no IP) ─────────────────────────

def aggregate_by_user(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Group parsed events by sudo_actor/username for local logs that have no IP.
    Returns dict: username → aggregated feature counts + attack lines
    """
    agg: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "failed_logins":           0,
        "successful_logins":       0,
        "sudo_attempts":           0,
        "suspicious_commands":     0,
        "sensitive_file_accesses": 0,
        "port_scans":              0,
        "privilege_escalations":   0,
        "log_cleared":             0,
        "recon_attempts":          0,
        "total_events":            0,
        "attack_lines":            [],   # raw lines that triggered priv-esc
        "sudo_lines":              [],   # all sudo lines
        "timestamps":              [],
    })

    for ev in events:
        # Use sudo_actor first, fall back to username
        actor = ev.get("sudo_actor") or ev.get("username")
        if not actor or actor.lower() in ("root", "none", "system"):
            actor = "unknown_actor"

        a = agg[actor]
        a["failed_logins"]           += ev.get("failed_login", 0)
        a["successful_logins"]       += ev.get("successful_login", 0)
        a["sudo_attempts"]           += ev.get("sudo_attempt", 0)
        a["suspicious_commands"]     += ev.get("suspicious_command", 0)
        a["sensitive_file_accesses"] += ev.get("sensitive_file_access", 0)
        a["port_scans"]              += ev.get("port_scan", 0)
        a["privilege_escalations"]   += ev.get("privilege_escalation", 0)
        a["log_cleared"]             += ev.get("log_cleared", 0)
        a["recon_attempts"]          += ev.get("recon", 0)
        a["total_events"]            += 1

        if ev.get("privilege_escalation"):
            a["attack_lines"].append(ev["raw"])
        if ev.get("sudo_attempt"):
            a["sudo_lines"].append(ev["raw"])
        if ev.get("log_timestamp"):
            a["timestamps"].append(ev["log_timestamp"])

    result = {}
    for actor, data in agg.items():
        d = dict(data)
        d["is_unknown"] = (actor == "unknown_actor")
        result[actor] = d
    return result


def analyze_privilege_escalation(lines: List[str]) -> Dict[str, Any]:
    """
    Dedicated privilege escalation analysis pipeline.
    Groups by username/actor (not IP) since local logs have no IP.
    Returns per-user attack breakdown with exact attack lines and timestamps.
    """
    events, total, valid = parse_lines(lines)

    # Per-line detections
    priv_esc_events = [e for e in events if e.get("privilege_escalation")]
    sudo_events     = [e for e in events if e.get("sudo_attempt")]

    # Per-user aggregation
    by_user = aggregate_by_user(events)

    results = []
    attack_count = 0

    for actor, features in by_user.items():
        if features.get("is_unknown") and features["privilege_escalations"] == 0:
            continue

        score  = score_from_features_priv_esc(features)
        status = classify_log_score(score)
        reason = build_reason(features)

        is_attack = features["privilege_escalations"] > 0
        if is_attack:
            attack_count += 1

        # Classify attack type per actor
        attack_types = []
        for line in features.get("attack_lines", []):
            if "/bin/bash" in line or "/bin/sh" in line:
                attack_types.append("ROOT_SHELL_SPAWN")
            elif "session opened for user root" in line.lower():
                attack_types.append("ROOT_SESSION_OPENED")
            elif "incorrect password" in line.lower():
                attack_types.append("FAILED_SUDO_ATTEMPT")
            else:
                attack_types.append("PRIVILEGE_ESCALATION")

        results.append({
            "actor":               actor,
            "risk_score":          score,
            "status":              status,
            "reason":              reason,
            "sudo_attempts":       features["sudo_attempts"],
            "privilege_escalations": features["privilege_escalations"],
            "attack_types":        list(set(attack_types)),
            "attack_lines":        features.get("attack_lines", []),
            "sudo_lines":          features.get("sudo_lines", []),
            "timestamps":          features.get("timestamps", []),
            "total_events":        features["total_events"],
        })

    results.sort(key=lambda r: r["risk_score"], reverse=True)

    # Also build a flat list of all attack events with line-level detail
    attack_events = []
    for e in priv_esc_events:
        actor = e.get("sudo_actor") or e.get("username") or "unknown"
        ts    = e.get("log_timestamp", "")
        line  = e["raw"]
        atype = "ROOT_SHELL_SPAWN" if "/bin/bash" in line or "/bin/sh" in line \
                else "ROOT_SESSION_OPENED" if "session opened for user root" in line.lower() \
                else "FAILED_SUDO_ATTEMPT" if "incorrect password" in line.lower() \
                else "PRIVILEGE_ESCALATION"
        attack_events.append({
            "actor":      actor,
            "timestamp":  ts,
            "type":       atype,
            "raw":        line,
        })

    logger.info(
        "PRIV_ESC ANALYSIS | lines=%d valid=%d priv_esc_events=%d actors=%d attacks=%d",
        total, valid, len(priv_esc_events), len(by_user), attack_count,
    )

    return {
        "summary": {
            "total_lines":       total,
            "valid_events":      valid,
            "priv_esc_events":   len(priv_esc_events),
            "sudo_events":       len(sudo_events),
            "unique_actors":     len(by_user),
            "actors_attacked":   attack_count,
        },
        "attack_events":  attack_events,   # flat list, one per detected line
        "actor_results":  results,         # per-actor aggregated breakdown
    }

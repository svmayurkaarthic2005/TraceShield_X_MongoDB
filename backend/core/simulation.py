"""
simulation.py - Log-dataset-driven generator for TraceShield X++
All attack scenarios are derived from the real intrusion_data.csv dataset.
"""

import os
import random
import copy
import re
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple

# Resolved from this file, not the working directory — the services are started
# from their own folders, where a repo-relative path does not exist.
_REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_PATH = os.path.join(_REPO_ROOT, "backend", "data", "intrusion_data.csv")

# Real Linux log corpora, richest first — these carry the source IPs and attack
# indicators that the risk engine actually scores on.
_LOG_CORPUS_PATHS = [
    os.path.join(_REPO_ROOT, "ingestion", "data", "synthetic", "synthetic_auth_5000.log"),
    os.path.join(_REPO_ROOT, "ingestion", "data", "synthetic", "synthetic_auth_100.log"),
    os.path.join(_REPO_ROOT, "backend", "data", "linux-logs-70-privOnly-log.txt"),
]

# ── Load real dataset rows once at import time ────────────────────────────────

def _load_rows() -> List[Dict[str, Any]]:
    if not os.path.exists(DATASET_PATH):
        return []
    import csv
    with open(DATASET_PATH, newline="") as f:
        rows = list(csv.DictReader(f))
    int_fields   = ["login_attempts","failed_logins","session_duration",
                    "unusual_time_access","network_traffic_volume",
                    "network_packet_size","attack_detected","privilege_escalation","sudo_attempt"]
    float_fields = ["ip_reputation_score"]
    for r in rows:
        for k in int_fields:
            if k in r:
                try: r[k] = int(r[k])
                except: r[k] = 0
        for k in float_fields:
            if k in r:
                try: r[k] = float(r[k])
                except: r[k] = 0.0
    return rows

_ALL_ROWS:    List[Dict[str, Any]] = _load_rows()
_ATTACK_ROWS: List[Dict[str, Any]] = [r for r in _ALL_ROWS if r.get("attack_detected") == 1]
_NORMAL_ROWS: List[Dict[str, Any]] = [r for r in _ALL_ROWS if r.get("attack_detected") == 0]


# ── Real Linux log corpus, grouped per source IP ──────────────────────────────
# The ingestion risk engine scores on log signals, so these patterns mirror the
# ones in ingestion/services/log_parser.py — a group only counts as an attack if
# it carries a signal that survives the engine's clean-baseline guard.

_RE_IP       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_FAILED   = re.compile(r'Failed password|authentication failure|Invalid user|FAILED LOGIN', re.I)
_RE_SUSPECT  = re.compile(r'\bnc\b|netcat|bash\s+-i|sh\s+-i|chmod\s+777|wget\s+http|curl\s+http'
                          r'|python.*socket|perl.*exec|ruby.*exec|/dev/tcp|mkfifo|base64\s+-d', re.I)
_RE_SENSITIVE = re.compile(r'/etc/passwd|/etc/shadow|/etc/sudoers|/root/\.ssh|/var/log/auth'
                           r'|/proc/\d+|/sys/kernel', re.I)


def _load_log_corpus() -> Tuple[Dict[str, List[str]], List[str]]:
    """Group every log line in the first available corpus by its source IP."""
    for path in _LOG_CORPUS_PATHS:
        if not os.path.exists(path):
            continue
        with open(path, "r", errors="replace") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        if not lines:
            continue
        groups: Dict[str, List[str]] = defaultdict(list)
        for line in lines:
            found = _RE_IP.findall(line)
            if found:
                groups[found[0]].append(line)
        return dict(groups), lines
    return {}, []


_LOG_GROUPS, _LOG_LINES = _load_log_corpus()


def _is_attack_group(lines: List[str]) -> bool:
    joined = "\n".join(lines)
    return bool(_RE_FAILED.search(joined) or _RE_SUSPECT.search(joined)
                or _RE_SENSITIVE.search(joined))


_ATTACK_LOG_IPS = [ip for ip, lines in _LOG_GROUPS.items() if _is_attack_group(lines)]
_NORMAL_LOG_IPS = [ip for ip in _LOG_GROUPS if ip not in set(_ATTACK_LOG_IPS)]


def has_log_corpus() -> bool:
    return bool(_LOG_GROUPS)


MAX_BURST_LINES = 6


def sample_log_group(attack_only: bool = True,
                     max_lines: int = MAX_BURST_LINES) -> Optional[Dict[str, Any]]:
    """
    Return one source IP together with a burst of its real log lines, so the
    caller can seed the ingestion service's per-IP log state before scoring.

    Only a slice is returned: the ingestion service accumulates log signals per
    IP and never decays them, so replaying a whole history at once pins the
    score at maximum instead of letting risk build across events.
    """
    pool = _ATTACK_LOG_IPS if attack_only else (_NORMAL_LOG_IPS or _ATTACK_LOG_IPS)
    if not pool:
        pool = list(_LOG_GROUPS)
    if not pool:
        return None

    ip    = random.choice(pool)
    lines = _LOG_GROUPS[ip]
    if len(lines) > max_lines:
        start = random.randint(0, len(lines) - max_lines)
        lines = lines[start:start + max_lines]

    return {"src_ip": ip, "log_lines": lines, "name": _describe_group(lines)}


def _describe_group(lines: List[str]) -> str:
    joined = "\n".join(lines)
    if _RE_SENSITIVE.search(joined): return "Sensitive File Access"
    if _RE_SUSPECT.search(joined):   return "Remote Execution"
    if _RE_FAILED.search(joined):    return "Brute Force"
    return "System Event"


def get_attack_log_groups(max_lines: int = 40) -> Dict[str, List[str]]:
    """Return each attacking source IP with a capped slice of its real log lines."""
    return {ip: _LOG_GROUPS[ip][:max_lines] for ip in _ATTACK_LOG_IPS}


def log_corpus_stats() -> Dict[str, int]:
    return {
        "total_lines":  len(_LOG_LINES),
        "unique_ips":   len(_LOG_GROUPS),
        "attack_ips":   len(_ATTACK_LOG_IPS),
        "normal_ips":   len(_NORMAL_LOG_IPS),
    }


def generate_attack_scenario() -> Dict[str, Any]:
    """Return a real attack row from the dataset."""
    pool = _ATTACK_ROWS if _ATTACK_ROWS else _ALL_ROWS
    if not pool:
        return _synthetic_attack()
    row = copy.deepcopy(random.choice(pool))
    if not row.get("src_ip") or row["src_ip"] == "127.0.0.1":
        row["src_ip"] = (
            f"10.{random.randint(1,254)}."
            f"{random.randint(1,254)}."
            f"{random.randint(1,254)}"
        )
    return row


def generate_synthetic_logs(n: int = 70) -> List[Dict[str, Any]]:
    """Return rows from the real dataset (shuffled). Falls back to synthetic."""
    if _ALL_ROWS:
        pool = (_ALL_ROWS * (n // len(_ALL_ROWS) + 1))[:n]
        random.shuffle(pool)
        return [copy.deepcopy(r) for r in pool]
    return [_synthetic_normal() if random.random() < 0.7 else _synthetic_attack()
            for _ in range(n)]


def get_all_log_lines() -> List[str]:
    """Return every raw log line available — corpus first, dataset column second."""
    if _LOG_LINES:
        return _LOG_LINES
    return [r["raw_log"] for r in _ALL_ROWS if r.get("raw_log")]


# ── Fallback synthetic generators ────────────────────────────────────────────

def _synthetic_normal() -> Dict[str, Any]:
    return {
        "name": "System Event", "src_ip": None,
        "protocol_type": random.choice(["TCP","UDP","HTTP"]),
        "login_attempts": random.randint(1,3), "failed_logins": random.randint(0,1),
        "unusual_time_access": 0, "ip_reputation_score": round(random.uniform(0.0,0.25),4),
        "session_duration": random.randint(30,180),
        "network_traffic_volume": random.randint(500,5000),
        "network_packet_size": random.randint(64,512), "attack_detected": 0,
    }

def _synthetic_attack() -> Dict[str, Any]:
    return {
        "name": "Privilege Escalation", "src_ip": None,
        "protocol_type": "TCP",
        "login_attempts": random.randint(8,15), "failed_logins": random.randint(6,12),
        "unusual_time_access": 1, "ip_reputation_score": round(random.uniform(0.75,0.95),4),
        "session_duration": random.randint(200,600),
        "network_traffic_volume": random.randint(10000,80000),
        "network_packet_size": random.randint(512,2048), "attack_detected": 1,
        "privilege_escalation": 1,
    }


def generate_attack_log_strings(n: int = 100) -> List[str]:
    """Return raw_log lines from the dataset."""
    pool = get_all_log_lines()
    if pool:
        return [random.choice(pool) for _ in range(n)]
    return [f"Apr 11 00:00:00 ubuntu-server sudo: user{i} : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
            for i in range(n)]


def save_synthetic_to_csv(n: int = 70, path: str = "backend/data/synthetic_logs.csv") -> None:
    import pandas as pd
    pd.DataFrame(generate_synthetic_logs(n)).to_csv(path, index=False)
    print(f"Saved {n} rows to {path}")

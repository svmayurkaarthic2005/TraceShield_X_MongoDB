"""
risk_engine.py — Adaptive weighted risk scoring with 4-tier classification.

Weights:
    ML score       → 30%
    Temporal score → 20%
    Count score    → 20%
    Spike score    → 15%
    Trend score    → 10%
    Log score      → 15%  (NEW — Linux system log signals)

Classification (single authoritative variable):
    0–25   → NORMAL
    25–40  → SUSPICIOUS
    40–60  → HIGH_RISK
    60–100 → EXTREME_RISK

Spike override:
    spike > 70 → floor final at 40 (HIGH_RISK minimum)
    spike >= 90 → floor final at 60 (EXTREME_RISK minimum)
"""

import logging
from collections import defaultdict, deque
from datetime import datetime

from ingestion.services.ml_model  import get_ml_score, ML_ANOMALY_THRESHOLD
from ingestion.services.ip_memory import record_event
from ingestion.services.log_parser import compute_log_score

logger = logging.getLogger(__name__)

W_ML       = 0.20   # reduced — ML alone shouldn't dominate
W_TEMPORAL = 0.15
W_COUNT    = 0.20
W_SPIKE    = 0.15
W_TREND    = 0.10
W_LOG      = 0.20   # increased — log signals are the most reliable for real datasets

SPIKE_OVERRIDE_THRESHOLD = 70.0
_WINDOW_SECONDS = 60
_ip_window: dict = defaultdict(lambda: deque())


def reset_state() -> int:
    """Clear the per-IP rate windows. Returns how many were tracked."""
    n = len(_ip_window)
    _ip_window.clear()
    return n


def _count_score(request_count: int) -> float:
    if request_count <= 5:    return 0.0
    if request_count <= 20:   return 10.0
    if request_count <= 50:   return 25.0
    if request_count <= 100:  return 45.0
    if request_count <= 300:  return 70.0
    if request_count <= 1000: return 88.0
    return 100.0


def _temporal_score(ip: str, request_count: int, timestamp: datetime) -> float:
    now_ts = timestamp.timestamp()
    window = _ip_window[ip]
    for _ in range(request_count):
        window.append(now_ts)
    cutoff = now_ts - _WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.popleft()

    rps = len(window) / _WINDOW_SECONDS
    if rps <= 0:    rps_score = 0.0
    elif rps <= 1:  rps_score = rps * 20.0
    elif rps <= 5:  rps_score = 20.0 + (rps - 1) * 10.0
    elif rps <= 10: rps_score = 60.0 + (rps - 5) * 8.0
    else:           rps_score = 100.0

    h = timestamp.hour
    if 0 <= h <= 5:     tod_mult = 1.40
    elif 22 <= h <= 23: tod_mult = 1.25
    elif 6 <= h <= 8:   tod_mult = 1.10
    else:               tod_mult = 1.00

    return round(min(rps_score * tod_mult, 100.0), 2)


def _spike_score(avg_count: float, request_count: int) -> tuple:
    spike_ratio = (request_count - avg_count) / (avg_count + 1e-5)
    spike_ratio = max(spike_ratio, 0.0)
    score = min(spike_ratio * 100.0, 100.0)
    return round(score, 2), round(spike_ratio, 4)


def _classify(score: float) -> str:
    """
    Classification thresholds tuned for dataset-derived signals.
    Lower thresholds ensure real attacks are not under-classified.

        0–20   → NORMAL
        20–35  → SUSPICIOUS
        35–60  → HIGH_RISK
        60–100 → EXTREME_RISK
    """
    if score >= 60.0: return "EXTREME_RISK"
    if score >= 35.0: return "HIGH_RISK"
    if score >= 20.0: return "SUSPICIOUS"
    return "NORMAL"


def _validate_consistency(score: float, status: str) -> None:
    """Assert score falls within the expected range for its status."""
    ranges = {
        "NORMAL":       (0.0,  20.0),
        "SUSPICIOUS":   (20.0, 35.0),
        "HIGH_RISK":    (35.0, 60.0),
        "EXTREME_RISK": (60.0, 100.0),
    }
    lo, hi = ranges[status]
    if not (lo <= score <= hi):
        logger.warning(
            "CONSISTENCY WARNING | score=%.2f outside [%.0f–%.0f] for %s",
            score, lo, hi, status
        )


def compute_risk(ip: str, request_count: int, timestamp: datetime) -> dict:
    """
    Compute adaptive weighted risk score with strict score-status consistency.

    Rule: status is ALWAYS derived from score — never assigned independently.
    Overrides adjust the SCORE first, then classification follows.

    Score ranges:
        0–30   → NORMAL
        30–70  → SUSPICIOUS
        70–90  → HIGH_RISK
        90–100 → EXTREME_RISK
    """
    rec         = record_event(ip, request_count, timestamp)
    avg_count   = rec.avg_count()
    hist_rate   = rec.avg_rate()
    t_score_val = rec.trend_score()

    spike, spike_ratio = _spike_score(avg_count, request_count)

    # Compute log score FIRST so it can feed into ML features
    log_data  = compute_log_score(ip)
    l_score   = log_data["log_score"]

    ml_score = get_ml_score(
        request_count, timestamp,
        deviation=spike_ratio,
        hist_rate=hist_rate,
        failed_logins=log_data.get("failed_logins", 0),
        sudo_attempts=log_data.get("sudo_attempts", 0),
        suspicious_commands=log_data.get("suspicious_commands", 0),
        sensitive_file_access=log_data.get("sensitive_file_accesses", 0),
    )
    t_score = _temporal_score(ip, request_count, timestamp)
    c_score = _count_score(request_count)

    # Weighted sum including log signal
    final = (W_ML * ml_score + W_TEMPORAL * t_score +
             W_COUNT * c_score + W_SPIKE * spike +
             W_TREND * t_score_val + W_LOG * l_score)

    override_triggered = False

    # ── Clean baseline guard ──────────────────────────────────────────────────
    # If NO threat signals exist at all, cap score at 20 and force NORMAL.
    # Volume alone (count, temporal, ML variance) must NOT trigger anomaly.
    log_details = log_data
    failed   = log_details.get("failed_logins", 0)
    sudo     = log_details.get("sudo_attempts", 0)
    susp_cmd = log_details.get("suspicious_commands", 0)
    sens     = log_details.get("sensitive_file_accesses", 0)
    priv_esc = log_details.get("privilege_escalations", 0)

    no_threat_signals = (failed == 0 and sudo == 0 and susp_cmd == 0 and sens == 0 and priv_esc == 0)
    # Safe sudo only (no malicious signals, no privilege escalation root shells) — treat as clean baseline
    safe_sudo_only = (sudo > 0 and failed == 0 and susp_cmd == 0 and sens == 0 and priv_esc == 0)

    if no_threat_signals or safe_sudo_only:
        # Cap final score at 20 — volume/ML variance alone cannot raise risk
        final = min(final, 20.0)
        final = round(max(final, 0.0), 2)
        status = "NORMAL"
        logger.info(
            "CLEAN BASELINE | ip=%s no threat signals → capped score=%.2f status=NORMAL",
            ip, final
        )
        return {
            "risk_score":         final,
            "status":             status,
            "override_triggered": False,
            "components": {
                "ml_score":       round(ml_score, 2),
                "temporal_score": round(t_score, 2),
                "count_score":    round(c_score, 2),
                "spike_score":    spike,
                "trend_score":    t_score_val,
                "log_score":      round(l_score, 2),
                "avg_previous":   round(avg_count, 2),
                "spike_ratio":    spike_ratio,
                "log_details":    log_data,
            },
        }

    # ── Log-signal floor overrides ────────────────────────────────────────────
    # Applied BEFORE spike overrides. Score is set first, status follows.

    # ── Tier 1: EXTREME_RISK floors (score ≥ 60) ─────────────────────────────

    # Multiple privilege escalation events (root shells, service accounts)
    if priv_esc >= 3:
        if final < 65.0:
            final = 65.0
            override_triggered = True
            logger.warning(
                "LOG OVERRIDE [EXTREME/65] | ip=%s priv_esc=%d", ip, priv_esc)

    # Privilege escalation: /etc/shadow + sudo → EXTREME (score 70)
    if sens >= 1 and sudo >= 1:
        if final < 70.0:
            final = 70.0
            override_triggered = True
            logger.warning(
                "LOG OVERRIDE [EXTREME/70] | ip=%s priv_esc: shadow+sudo", ip)

    # Multi-stage attack: failed + suspicious + sudo all present → EXTREME
    if failed >= 1 and susp_cmd >= 1 and sudo >= 1:
        if final < 70.0:
            final = 70.0
            override_triggered = True
            logger.warning(
                "LOG OVERRIDE [EXTREME/70] | ip=%s multi-stage: failed=%d susp=%d sudo=%d",
                ip, failed, susp_cmd, sudo)

    # Reverse shell / multiple malicious commands → EXTREME
    if susp_cmd >= 2:
        if final < 70.0:
            final = 70.0
            override_triggered = True
            logger.warning(
                "LOG OVERRIDE [EXTREME/70] | ip=%s suspicious_cmds=%d", ip, susp_cmd)

    # Brute force extreme: 8+ failed logins → EXTREME
    if failed >= 8:
        if final < 70.0:
            final = 70.0
            override_triggered = True
            logger.warning(
                "LOG OVERRIDE [EXTREME/70] | ip=%s failed_logins=%d", ip, failed)

    # ── Tier 2: HIGH_RISK floors (score ≥ 35) ────────────────────────────────

    # Privilege escalation: root shell spawn (/bin/bash), sudo abuse by daemon account
    if priv_esc >= 1 and final < 45.0:
        final = 45.0
        override_triggered = True
        logger.warning(
            "LOG OVERRIDE [HIGH/45] | ip=%s priv_esc=%d", ip, priv_esc)

    # Single suspicious command (nc, wget, bash, chmod 777) → HIGH
    if susp_cmd >= 1 and final < 35.0:
        final = 35.0
        override_triggered = True
        logger.warning(
            "LOG OVERRIDE [HIGH/35] | ip=%s suspicious_cmds=%d", ip, susp_cmd)

    # Sensitive file access alone (/etc/shadow, /etc/passwd) → HIGH
    if sens >= 1 and final < 35.0:
        final = 35.0
        override_triggered = True
        logger.warning(
            "LOG OVERRIDE [HIGH/35] | ip=%s sensitive_files=%d", ip, sens)

    # 5+ failed logins → HIGH
    if failed >= 5 and final < 35.0:
        final = 35.0
        override_triggered = True
        logger.warning(
            "LOG OVERRIDE [HIGH/35] | ip=%s failed_logins=%d", ip, failed)

    # ── Tier 3: SUSPICIOUS floors (score ≥ 20) ───────────────────────────────

    # 2+ failed logins (or failed sudo attempts) → SUSPICIOUS
    if failed >= 2 and final < 25.0:
        final = 25.0
        override_triggered = True
        logger.warning(
            "LOG OVERRIDE [SUSPICIOUS/25] | ip=%s failed_logins=%d", ip, failed)

    # Spike override: extreme spike (>90) → score must be in EXTREME_RISK range
    if spike >= 90.0 and final < 60.0:
        final = max(final, 60.0)
        override_triggered = True
        logger.warning(
            "SPIKE OVERRIDE [EXTREME] | ip=%s spike=%.1f → score elevated to %.1f",
            ip, spike, final
        )
    # Moderate spike (>70) → score must be at least HIGH_RISK range
    elif spike > SPIKE_OVERRIDE_THRESHOLD and final < 40.0:
        final = max(final, 40.0)
        override_triggered = True
        logger.warning(
            "SPIKE OVERRIDE [HIGH] | ip=%s spike=%.1f → score elevated to %.1f",
            ip, spike, final
        )

    # ML override: anomalous ML must be at least SUSPICIOUS
    if ml_score >= ML_ANOMALY_THRESHOLD and final < 20.0:
        final = 20.0
        override_triggered = True

    # Clamp and classify — status derived ONLY from final score
    final  = round(min(max(final, 0.0), 100.0), 2)
    status = _classify(final)

    # Validation layer
    _validate_consistency(final, status)

    logger.info(
        "RISK | ip=%-16s count=%4d avg=%.1f spike=%.1f(%.2fx) trend=%.1f log=%.1f | "
        "ml=%.1f temporal=%.1f count=%.1f → FINAL=%.2f [%s] override=%s",
        ip, request_count, avg_count, spike, spike_ratio, t_score_val, l_score,
        ml_score, t_score, c_score, final, status, override_triggered
    )

    return {
        "risk_score":         final,
        "status":             status,
        "override_triggered": override_triggered,
        "components": {
            "ml_score":       round(ml_score, 2),
            "temporal_score": round(t_score, 2),
            "count_score":    round(c_score, 2),
            "spike_score":    spike,
            "trend_score":    t_score_val,
            "log_score":      round(l_score, 2),
            "avg_previous":   round(avg_count, 2),
            "spike_ratio":    spike_ratio,
            "log_details":    log_data,
        },
    }

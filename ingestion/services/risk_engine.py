"""
risk_engine.py — Adaptive weighted risk scoring with 4-tier classification.

Weights (see W_* constants below — this table must match them exactly):
    ML score       → 20%
    Temporal score → 15%
    Count score    → 20%
    Spike score    → 15%
    Trend score    → 10%
    Log score      → 20%

Classification — the only authoritative definition is _classify() below:
    0–20   → NORMAL
    20–35  → SUSPICIOUS
    35–60  → HIGH_RISK
    60–100 → EXTREME_RISK

This weighted sum is then subject to a cascade of deterministic log-signal
floor overrides (see compute_risk()) before classification — for any event
with a recognized log signal (sudo, sensitive-file access, suspicious
command, failed login, privilege escalation), these floors — not the
weighted sum — usually determine the final tier. Treat this as a rule
engine with an ML-weighted term, not as ML-driven detection.

Spike override:
    spike > 70  → floor final at 40 (HIGH_RISK minimum)
    spike >= 90 → floor final at 60 (EXTREME_RISK minimum)

Weak vs. strong log evidence (see compute_risk()'s guard before the override
cascade): an event reaches the override cascade — and therefore becomes
eligible for the spike override above — only if it carries at least one
STRONG signal:
    suspicious_commands   >= 1
    sensitive_file_access >= 1
    privilege_escalations >= 1
    failed_logins         >= 2
These are the exact thresholds each signal's own floor below already fires
at, so "strong" here means nothing more than "the system already considers
one occurrence of this enough to act on." Anything weaker — zero signals,
safe sudo-only activity, or a single incidental failed login (alone or with
sudo) — is WEAK evidence and is capped by the ML_ANOMALY_THRESHOLD-gated
baseline guard instead, the same as a clean event, regardless of how extreme
the volume/spike is. This is what stops one unrelated failed password from
letting a legitimate traffic burst's spike reach HIGH_RISK or EXTREME_RISK.
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
    Overrides adjust the SCORE first, then classification follows via
    _classify() (0–20 NORMAL, 20–35 SUSPICIOUS, 35–60 HIGH_RISK, 60–100
    EXTREME_RISK — see that function for the authoritative definition).
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
        trend_score=t_score_val,
    )
    t_score = _temporal_score(ip, request_count, timestamp)
    c_score = _count_score(request_count)

    # Weighted sum including log signal
    final = (W_ML * ml_score + W_TEMPORAL * t_score +
             W_COUNT * c_score + W_SPIKE * spike +
             W_TREND * t_score_val + W_LOG * l_score)

    override_triggered = False

    # ── Weak-signal baseline guard ─────────────────────────────────────────────
    # If the event carries no STRONG log signal, cap score at 20 (or the
    # ML-gated 20-59 band below) regardless of volume/spike. See module
    # docstring for the full weak-vs-strong policy and why these specific
    # thresholds (matching each signal's own floor further down) are the
    # dividing line, not an arbitrary new cutoff.
    log_details = log_data
    failed   = log_details.get("failed_logins", 0)
    sudo     = log_details.get("sudo_attempts", 0)
    susp_cmd = log_details.get("suspicious_commands", 0)
    sens     = log_details.get("sensitive_file_accesses", 0)
    priv_esc = log_details.get("privilege_escalations", 0)

    # A single failed login (alone, or alongside sudo usage — e.g. one
    # mistyped sudo password) is incidental, not corroborated attack
    # evidence: it is weaker than every other signal type below, each of
    # which already floors severity at its very first occurrence. Only
    # REPEATED failed logins (>=2, matching the SUSPICIOUS floor later in
    # this function) count as a strong signal on their own.
    has_strong_signal = susp_cmd >= 1 or sens >= 1 or priv_esc >= 1 or failed >= 2
    weak_evidence_only = not has_strong_signal

    if weak_evidence_only:
        if ml_score >= ML_ANOMALY_THRESHOLD:
            # A genuine ML anomaly (behavioral/volume pattern) must not be
            # silently erased just because no known attack signature was
            # seen in the logs — that would defeat anomaly detection for
            # exactly the "unknown attack, no signature" case it exists for.
            # It is still capped below EXTREME_RISK: absent log evidence this
            # is an unconfirmed behavioral anomaly, not a matched attack
            # pattern, so it is not given the same ceiling as a confirmed
            # signature match.
            #
            # Floor at 20 (SUSPICIOUS) mirrors the existing "ML override:
            # anomalous ML must be at least SUSPICIOUS" rule used later in
            # this same function for the non-clean-baseline path — the raw
            # weighted sum alone is not enough here, since ML is only one of
            # six weighted components (W_ML=0.20) and every other component
            # is near-zero with no log signal, so the plain weighted sum
            # would usually stay under 20 even when ml_score is high. Without
            # this floor the earlier bug (suppression to NORMAL) is only
            # half-fixed: override_triggered becomes True but status still
            # comes back NORMAL.
            final = round(min(max(final, 20.0), 59.0), 2)
            status = _classify(final)
            logger.warning(
                "WEAK-EVIDENCE BASELINE OVERRIDE | ip=%s failed=%d sudo=%d (no strong "
                "signal) but ml_score=%.1f → score=%.2f status=%s (not suppressed to NORMAL)",
                ip, failed, sudo, ml_score, final, status
            )
            return {
                "risk_score":         final,
                "status":             status,
                "override_triggered": True,
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
        # Cap final score below 20 — volume/ML variance alone (including a
        # large spike/count contribution to the raw weighted sum before this
        # cap) cannot raise risk, and neither can a single incidental failed
        # login. The ceiling is 19.99, not 20.0: _classify()'s score>=20
        # check resolves exactly 20.0 to SUSPICIOUS, and any real volume
        # burst's pre-cap weighted sum (spike+count alone) all but always
        # reaches >=20 — capping at 20.0 would therefore hand _classify() a
        # value it calls SUSPICIOUS for virtually every clean, protected
        # burst. Capping at 19.99 instead keeps the result inside the NORMAL
        # band by construction, so status can be derived from the score here
        # exactly like every other return path, with no hardcoded exception.
        final = round(max(min(final, 19.99), 0.0), 2)
        status = _classify(final)
        logger.info(
            "WEAK-EVIDENCE BASELINE | ip=%s failed=%d sudo=%d (no strong signal) "
            "→ capped score=%.2f status=%s",
            ip, failed, sudo, final, status
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

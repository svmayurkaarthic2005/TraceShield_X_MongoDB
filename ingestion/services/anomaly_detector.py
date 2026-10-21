"""
anomaly_detector.py — Detection + automated response + graph storage orchestrator.
"""

import logging
from datetime import datetime

from ingestion.services.risk_engine     import compute_risk
from ingestion.services.response_engine import execute_response, is_blocked
from ingestion.services.log_parser      import get_ip_log_summary
from ingestion.db.neo4j import (
    store_attack_event,
    store_honeypot_redirect,
    store_block_event,
)

logger = logging.getLogger(__name__)


# ── Attack type classification ────────────────────────────────────────────────

def classify_attack_type(log_summary: dict, status: str = "NORMAL") -> str:
    """
    Derive attack type from extracted LOG feature signals — falling back to
    BEHAVIORAL_ANOMALY when risk_engine.py flagged the event as non-NORMAL
    with no recognizable log signature at all (e.g. a pure volume/ML-driven
    anomaly, see risk_engine.py's clean-baseline-guard ML override).

    Priority: PRIVILEGE_ESCALATION > REMOTE_EXECUTION > PATH_TRAVERSAL >
    BRUTE_FORCE > BEHAVIORAL_ANOMALY (if status != NORMAL) > NORMAL_ACTIVITY

    PRIVILEGE_ESCALATION requires either an explicit priv-esc log event, or
    sudo used ALONGSIDE a sensitive-file access (sudo cat /etc/shadow is a
    privilege-escalation attempt by definition — the actor is using elevated
    rights to read a credential file, regardless of exit code), or repeated
    sudo (>=2) combined with any other malicious indicator.
    Pure administrative sudo (apt update, systemctl restart, etc.) = NORMAL_ACTIVITY.

    This labels ATTEMPTED behavior from log evidence; it never claims the
    read/command actually succeeded (no exit-code or output signal is
    available here) — see risk_engine.py for severity, which is scored
    separately from this label. BEHAVIORAL_ANOMALY is weaker still: it means
    "the risk engine found this anomalous" with NO log evidence of what kind
    of attack, if any — it is explicitly not a confirmed attack category, and
    must never be read as one.

    Args:
        log_summary: Output of get_ip_log_summary() — aggregated counts.
        status: The severity status already computed by risk_engine.py's
            compute_risk() for this same event (NORMAL/SUSPICIOUS/HIGH_RISK/
            EXTREME_RISK). Only used for the BEHAVIORAL_ANOMALY fallback —
            every signature-based branch above it is decided from log
            evidence alone, unaffected by status.

    Returns:
        One of: PRIVILEGE_ESCALATION, REMOTE_EXECUTION, PATH_TRAVERSAL,
        BRUTE_FORCE, BEHAVIORAL_ANOMALY, NORMAL_ACTIVITY
    """
    sudo       = log_summary.get("sudo_attempts", 0)
    sensitive  = log_summary.get("sensitive_file_accesses", 0)
    suspicious = log_summary.get("suspicious_commands", 0)
    failed     = log_summary.get("failed_logins", 0)
    priv_esc   = log_summary.get("privilege_escalations", 0)

    # PRIVILEGE_ESCALATION: explicit priv-esc event, sudo+sensitive-file access
    # (matches risk_engine.py's own EXTREME/70 "shadow+sudo" override), or
    # repeated sudo combined with another malicious indicator.
    if priv_esc > 0 or (sudo >= 1 and sensitive > 0) or (sudo >= 2 and (suspicious > 0 or failed > 0)):
        return "PRIVILEGE_ESCALATION"

    # Safe sudo only (no malicious indicators and no privilege escalation) → normal admin activity
    if sudo > 0 and sensitive == 0 and suspicious == 0 and failed == 0 and priv_esc == 0:
        return "NORMAL_ACTIVITY"

    if suspicious >= 1:
        return "REMOTE_EXECUTION"

    if sensitive >= 1:
        return "PATH_TRAVERSAL"

    if failed >= 2:
        return "BRUTE_FORCE"

    # No recognizable log signature at all. If risk_engine still flagged this
    # event as non-NORMAL (e.g. a pure volume/ML anomaly with no log evidence
    # — see risk_engine.py's clean-baseline-guard ML override), say so
    # honestly instead of silently reporting "NORMAL_ACTIVITY" for an event
    # the system itself just escalated.
    if status != "NORMAL":
        return "BEHAVIORAL_ANOMALY"

    return "NORMAL_ACTIVITY"

logger = logging.getLogger(__name__)


def process_event(ip: str, device: str, request_count: int,
                  timestamp: datetime, skip_block_check: bool = False) -> dict:
    """
    Full real-time pipeline:
        1. Compute weighted risk score (ML+temporal+count+spike+trend).
        2. Execute automated response (flag / block / honeypot).
        3. Store graph relationships in Neo4j.
        4. Return structured result.
    """
    logger.info("INGEST | ip=%-16s device=%-20s count=%d ts=%s skip_block=%s",
                ip, device, request_count, timestamp.isoformat(), skip_block_check)

    # Already blocked — short-circuit (applied only to live network packets, never to forensic file uploads)
    if not skip_block_check and is_blocked(ip):
        logger.warning("BLOCKED IP attempted access | ip=%s device=%s", ip, device)
        return {
            "status":       "EXTREME_RISK",
            "risk_score":   100.0,
            "graph_stored": False,
            "components":   {},
            "override_triggered": True,
            # Short-circuit has no log_summary to classify from (the original
            # signature, if any, was determined on an earlier call) — without
            # this, callers defaulting attack_type via .get(..., "NORMAL_ACTIVITY")
            # would report EXTREME_RISK alongside "normal activity".
            "attack_type":  "BEHAVIORAL_ANOMALY",
            "response":     {
                "actions_taken":          ["blocked"],
                "blocked":                True,
                "redirected_to_honeypot": True,
                "honeypot_id":            None,
                "flag_count":             0,
                "reason":                 "previously_blocked",
                "block_expires_at":       None,
                "honeypot_interactions":  0,
            },
            "message": f"EXTREME RISK: {ip} is on the block list.",
        }

    result   = compute_risk(ip, request_count, timestamp)
    score    = result["risk_score"]
    status   = result["status"]
    comps    = result["components"]
    override = result.get("override_triggered", False)
    ts_str   = timestamp.isoformat()

    # Derive attack type from log features — signature-based branches are
    # pure feature-based (no score influence); status is only consulted for
    # the BEHAVIORAL_ANOMALY fallback when there is no log signature at all.
    log_summary = get_ip_log_summary(ip)
    attack_type = classify_attack_type(log_summary, status)

    # Automated response — status is single source of truth
    response = execute_response(ip, score, status, comps)

    _log_result(ip, device, score, status, comps, response, override, attack_type)

    # ── Graph storage ─────────────────────────────────────────────────────────
    graph_stored = False

    # Always store non-normal events as ATTACKED relationship
    if status != "NORMAL":
        graph_stored = store_attack_event(
            ip=ip, device=device,
            risk_score=score, status=status, timestamp=ts_str,
            ml_score=comps.get("ml_score", 0),
            spike_score=comps.get("spike_score", 0),
            trend_score=comps.get("trend_score", 0),
            temporal_score=comps.get("temporal_score", 0),
            count_score=comps.get("count_score", 0),
            log_score=comps.get("log_score", 0),
        )

    # Store honeypot redirect if triggered
    if "redirected_to_honeypot" in response["actions_taken"]:
        hid = response.get("honeypot_id") or "honeypot_unknown"
        store_honeypot_redirect(
            ip=ip, honeypot_id=hid,
            reason=response["reason"], timestamp=ts_str,
        )

    # Store block event if triggered
    if "blocked" in response["actions_taken"]:
        store_block_event(
            ip=ip, reason=response["reason"], timestamp=ts_str,
        )

    return {
        "status":             status,
        "risk_score":         score,
        "graph_stored":       graph_stored,
        "override_triggered": override,
        "attack_type":        attack_type,
        "components":         comps,
        "response":           response,
        "message":            _build_message(ip, device, request_count,
                                             score, status, comps, response),
    }


def _log_result(ip, device, score, status, comps, response, override,
                attack_type="NORMAL_ACTIVITY"):
    reasons = []
    if comps.get("spike_score", 0) > 70:
        reasons.append(f"spike={comps['spike_score']:.1f}")
    if comps.get("trend_score", 0) > 60:
        reasons.append(f"trend={comps['trend_score']:.1f}")
    if comps.get("ml_score", 0) >= 60:
        reasons.append(f"ml={comps['ml_score']:.1f}")
    if comps.get("temporal_score", 0) >= 50:
        reasons.append(f"rate={comps['temporal_score']:.1f}")
    reason  = " + ".join(reasons) if reasons else "combined"
    actions = ", ".join(response["actions_taken"]) or "none"
    ovr     = " [OVERRIDE]" if override else ""

    if status in ("EXTREME_RISK", "HIGH_RISK"):
        logger.warning("%s%s | ip=%s score=%.2f | attack_type=%s | reason: %s | actions: %s",
                       status, ovr, ip, score, attack_type, reason, actions)
    elif status == "SUSPICIOUS":
        logger.warning("SUSPICIOUS%s | ip=%s score=%.2f | attack_type=%s | reason: %s | actions: %s",
                       ovr, ip, score, attack_type, reason, actions)
    else:
        logger.info("NORMAL | ip=%s score=%.2f", ip, score)


def _build_message(ip, device, count, score, status, comps, response) -> str:
    reasons = []
    if comps.get("spike_score", 0) > 70:
        reasons.append("sudden spike detected")
    if comps.get("trend_score", 0) > 60:
        reasons.append("escalating trend")
    if comps.get("ml_score", 0) >= 60:
        reasons.append("behavioral anomaly")
    if not reasons:
        reasons.append("within normal parameters")

    actions    = response["actions_taken"]
    action_str = ""
    if "blocked" in actions:
        action_str = " IP BLOCKED and redirected to honeypot."
    elif "redirected_to_honeypot" in actions:
        action_str = f" Redirected to honeypot ({response.get('honeypot_id', '')})."
    elif "flagged" in actions:
        action_str = f" IP flagged (count={response['flag_count']})."

    prefix = {
        "EXTREME_RISK": "EXTREME RISK",
        "HIGH_RISK":    "HIGH RISK",
        "SUSPICIOUS":   "SUSPICIOUS",
        "NORMAL":       "NORMAL",
    }.get(status, status)

    return (f"{prefix}: {count} reqs from {ip} via {device}. "
            f"Score: {score:.1f}/100. {'; '.join(reasons)}.{action_str}")

"""
routes.py — Thin routing layer for TraceShield X++ (port 8000)

Port 8000 responsibilities:
  - Dataset sampling / synthetic log generation
  - Delegating ALL detection to port 8001 /ingest
  - Mapping IngestResponse → UI response format
  - Graph queries, status, health

Port 8000 does NOT:
  - Score, classify, or override any risk values
  - Run ML inference
  - Modify risk_score or status returned from port 8001
"""

import logging
import os
import random
import re
import datetime
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

_INGEST_BASE    = os.getenv("INGEST_BASE_URL", "http://127.0.0.1:8001")
INGEST_URL      = f"{_INGEST_BASE}/ingest"
INGEST_LOGS_URL = f"{_INGEST_BASE}/ingest/logs"

try:
    from backend.core.ml_model      import get_sample_row
    from backend.core.simulation    import (generate_synthetic_logs, generate_attack_scenario,
                                            get_all_log_lines, sample_log_group, has_log_corpus,
                                            get_attack_log_groups)
    from backend.core.graph_builder import get_attack_graph, clear_graph
    from backend.core.summarizer    import generate_timeline
    from backend.core.neo4j_db      import test_connection
    from backend.core.risk          import get_risk_color
except ImportError:
    from core.ml_model      import get_sample_row
    from core.simulation    import (generate_synthetic_logs, generate_attack_scenario,
                                    get_all_log_lines, sample_log_group, has_log_corpus,
                                    get_attack_log_groups)
    from core.graph_builder import get_attack_graph, clear_graph
    from core.summarizer    import generate_timeline
    from core.neo4j_db      import test_connection
    from core.risk          import get_risk_color

router = APIRouter()


# ── Delegation helper ─────────────────────────────────────────────────────────

THREAT_SCAN_MAX_ROWS = 25

_RE_LOG_TS    = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
_RE_LOG_ACTOR = re.compile(r'for (?:invalid user )?(\w+)|user (\w+)|sudo:\s*(\w+)', re.I)


def _actor_from_lines(lines: List[str]) -> str:
    """Pull the most frequently named account out of a group of log lines."""
    names: Dict[str, int] = {}
    for line in lines:
        m = _RE_LOG_ACTOR.search(line)
        if m:
            name = next((g for g in m.groups() if g), None)
            if name:
                names[name] = names.get(name, 0) + 1
    return max(names, key=names.get) if names else "unknown"


def _log_stamp(line: str) -> str:
    """The syslog timestamp at the head of a line, if it has one."""
    m = _RE_LOG_TS.match(line or "")
    return m.group(1) if m else ""


def _signal_summary(lines: List[str]) -> str:
    """Count the signals the risk engine scores on, across a group of log lines."""
    joined = "\n".join(lines).lower()
    counts = [
        (sum(1 for l in lines if "failed password" in l.lower()
             or "authentication failure" in l.lower()), "failed logins"),
        (sum(1 for l in lines if "invalid user" in l.lower()), "invalid users"),
        (sum(1 for l in lines if "command=" in l.lower()), "sudo commands"),
        (joined.count("/etc/shadow") + joined.count("/etc/passwd"), "sensitive file reads"),
        (sum(1 for l in lines if "ufw block" in l.lower()), "blocked connections"),
    ]
    return " · ".join(f"{n} {label}" for n, label in counts if n) or None


def _timeline_entry(line: str) -> Dict[str, str]:
    """Turn one raw log line into a forensic timeline entry."""
    ts    = _RE_LOG_TS.match(line)
    lower = line.lower()

    if "failed password" in lower or "authentication failure" in lower:
        desc = "FAILED LOGIN — credential guessing attempt"
    elif "invalid user" in lower:
        desc = "INVALID USER — probing for valid accounts"
    elif "accepted password" in lower or "session opened" in lower:
        desc = "SESSION OPENED — authentication succeeded"
    elif "command=" in lower or "sudo" in lower:
        desc = "SUDO COMMAND — privilege escalation attempt"
    elif any(k in lower for k in ("/etc/shadow", "/etc/passwd", "/etc/sudoers")):
        desc = "SENSITIVE FILE ACCESS — credential store touched"
    else:
        desc = "System event"

    return {
        "time":        ts.group(1) if ts else "",
        "source":      "auth.log",
        "description": desc,
        "evidence":    line[:200],
    }


def _seed_log_signals(ip: str, log_lines: List[str]) -> None:
    """
    Push an IP's real log lines to port 8001 before scoring it.

    The risk engine derives its score from log signals and forces NORMAL when an
    IP has none, so an event delegated without this step can never be detected.
    """
    if not log_lines:
        return
    try:
        httpx.post(INGEST_LOGS_URL, json={"ip": ip, "log_lines": log_lines}, timeout=10.0)
    except httpx.HTTPError as exc:
        logger.warning("Could not seed log signals for %s: %s", ip, exc)


def _delegate_to_ingest(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send a log row to port 8001 /ingest and map the response to UI format.
    No scoring, no overrides — values come entirely from port 8001.
    """
    ip     = row.get("src_ip") or (
        f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    )
    device = row.get("name") or row.get("protocol_type", "UNKNOWN")

    _seed_log_signals(ip, row.get("log_lines") or [])

    # request_count: weight attack signals properly
    failed   = int(row.get("failed_logins", 0) or 0)
    attempts = int(row.get("login_attempts", 0) or 0)
    traffic  = int(row.get("network_traffic_volume", 0) or 0)
    priv_esc = int(row.get("privilege_escalation", 0) or 0)
    sudo_att = int(row.get("sudo_attempt", 0) or 0)
    unusual  = int(row.get("unusual_time_access", 0) or 0)
    request_count = min(
        max(
            failed * 8 +
            attempts * 3 +
            priv_esc * 60 +   # priv-esc = very high intensity
            sudo_att * 20 +   # sudo abuse = high
            unusual * 15 +
            (traffic // 10000),
            attempts, 1
        ),
        200,
    )

    payload = {"ip": ip, "device": device, "request_count": request_count}
    logger.info("Delegating to ingestion service: ip=%s, device=%s, count=%d",
                ip, device, request_count)

    try:
        resp = httpx.post(INGEST_URL, json=payload, timeout=10.0)
        resp.raise_for_status()
        ingest_data = resp.json()
    except httpx.ConnectError:
        logger.error("Ingestion service unreachable at %s", INGEST_URL)
        raise HTTPException(
            status_code=502,
            detail="Ingestion service (port 8001) is not reachable. Start it first.",
        )
    except httpx.HTTPStatusError as exc:
        logger.error("Ingestion service HTTP error: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))

    # ── Map IngestResponse → UI format (no value changes) ────────────────────
    status     = ingest_data.get("status", "NORMAL")
    risk_score = ingest_data.get("risk_score", 0.0)   # exact value from port 8001
    components = ingest_data.get("components", {})
    response   = ingest_data.get("response", {})
    ml_score   = components.get("ml_score", 0.0)

    # risk_level and risk_color derived from status (not from score)
    status_to_level = {
        "EXTREME_RISK": "CRITICAL",
        "HIGH_RISK":    "HIGH",
        "SUSPICIOUS":   "MEDIUM",
        "NORMAL":       "LOW",
    }
    risk_level = status_to_level.get(status, "LOW")
    risk_color = get_risk_color(risk_level)

    # anomaly: True whenever ingestion classified as non-normal
    anomaly = status != "NORMAL"

    # flags derived from row features (for UI display only — do not affect score)
    actions  = response.get("actions_taken", [])
    reason   = response.get("reason", "")
    flags    = _derive_flags(row, reason)
    readable = _readable_flags(flags)

    # summary built from ingestion result
    summary  = _build_summary(risk_level, flags, readable, row, anomaly,
                               ingest_data.get("message", ""))
    timeline = generate_timeline(flags, row.get("log_lines"))

    # Each component's actual contribution to the final score. The weights must
    # stay in step with risk_engine.W_* or the bars misstate why a score is what
    # it is; every weighted component is listed so they sum to the score.
    breakdown = {
        "ml_contribution":       round(ml_score * 0.20, 2),
        "log_contribution":      round(components.get("log_score", 0) * 0.20, 2),
        "count_contribution":    round(components.get("count_score", 0) * 0.20, 2),
        "temporal_contribution": round(components.get("temporal_score", 0) * 0.15, 2),
        "spike_contribution":    round(components.get("spike_score", 0) * 0.15, 2),
        "trend_contribution":    round(components.get("trend_score", 0) * 0.10, 2),
    }

    logger.info("Ingestion result: ip=%s status=%s risk_score=%.2f",
                ip, status, risk_score)

    return {
        "risk_score":     risk_score,
        "risk_level":     risk_level,
        "risk_color":     risk_color,
        "anomaly":        anomaly,
        "anomaly_score":  round(ml_score / 100.0, 4),
        "flags":          flags,
        "readable_flags": readable,
        "features":       row,
        "summary":        summary,
        "graph_updated":  False,
        "breakdown":      breakdown,
        "timeline":       timeline,
        "status":         status,
        "components":     components,
        "response":       response,
    }


# ── Flag derivation (UI display only) ────────────────────────────────────────

def _derive_flags(row: Dict[str, Any], reason: str) -> List[str]:
    flags = []
    if row.get("failed_logins", 0) > 0 or row.get("login_attempts", 0) > 3:
        flags.append("BRUTE_FORCE")
    if row.get("ip_reputation_score", 0.0) > 0.6:   # high score = malicious in this dataset
        flags.append("LOW_REPUTATION_IP")
    if row.get("unusual_time_access", 0) == 1:
        flags.append("ODD_ACCESS_TIME")
    if row.get("session_duration", 0) > 300:
        flags.append("LONG_SESSION")
    if row.get("network_traffic_volume", 0) > 50000:
        flags.append("DATA_EXFILTRATION")
    if row.get("privilege_escalation", 0) == 1 or row.get("sudo_attempt", 0) == 1:
        flags.append("PRIVILEGE_ESCALATION")
    if "spike" in reason or "trend" in reason:
        flags.append("TRAFFIC_SPIKE")
    return flags


_FLAG_READABLE = {
    "BRUTE_FORCE":          "Brute Force Attack",
    "LOW_REPUTATION_IP":    "Suspicious IP Address",
    "ODD_ACCESS_TIME":      "Unusual Access Time",
    "LONG_SESSION":         "Abnormal Session Duration",
    "DATA_EXFILTRATION":    "Possible Data Exfiltration",
    "TRAFFIC_SPIKE":        "Traffic Spike Detected",
    "PRIVILEGE_ESCALATION": "Privilege Escalation Detected",
}

def _readable_flags(flags: List[str]) -> List[str]:
    return [_FLAG_READABLE.get(f, f) for f in flags]


def _build_summary(risk_level: str, flags: List[str], readable: List[str],
                   row: Dict[str, Any], anomaly: bool, message: str) -> str:
    """Build human-readable summary from ingestion result — no score manipulation."""
    openers = {
        "CRITICAL": "CRITICAL risk detected.",
        "HIGH":     "HIGH risk activity detected.",
        "MEDIUM":   "Suspicious behavior detected.",
        "LOW":      "LOW risk. System activity appears normal.",
    }
    parts = [openers.get(risk_level, "Activity detected.")]

    if anomaly:
        parts.append("Anomalous behavior confirmed by the detection pipeline.")
    else:
        parts.append("No anomaly detected by the ML model.")

    scenario = row.get("name", "")
    if scenario:
        parts.append(f"Attack pattern: {scenario}.")
    elif readable:
        parts.append(f"Triggered rules: {', '.join(readable)}.")

    indicators = []
    if row.get("failed_logins", 0) > 3:
        indicators.append(f"{row['failed_logins']} failed login attempts")
    if row.get("network_traffic_volume", 0) > 50000:
        indicators.append(f"high traffic volume ({row['network_traffic_volume']:,} bytes)")
    if row.get("unusual_time_access", 0):
        indicators.append("off-hours access")
    if row.get("ip_reputation_score", 1.0) < 0.4:
        indicators.append(f"low-reputation IP (score {row.get('ip_reputation_score', 0):.2f})")
    if indicators:
        parts.append(f"Indicators: {'; '.join(indicators)}.")

    recs = {
        "CRITICAL": "Immediate investigation required.",
        "HIGH":     "Potential threat — monitor closely.",
        "MEDIUM":   "Suspicious activity — review recommended.",
        "LOW":      "System behavior appears normal.",
    }
    parts.append(recs.get(risk_level, ""))

    return " ".join(p for p in parts if p)


# ── Endpoints ─────────────────────────────────────────────────────────────────

def _sample_event(df, attack_only: bool) -> Dict[str, Any]:
    """
    Build one event to score. Prefers a real log group (which carries the source
    IP and the signals the risk engine scores on) and falls back to a raw
    dataset row when no log corpus is present.
    """
    group = sample_log_group(attack_only=attack_only) if has_log_corpus() else None
    if group is None:
        return get_sample_row(df)

    lines = group["log_lines"]
    return {
        **group,
        "protocol_type":  "TCP",
        "login_attempts": len(lines),
        "failed_logins":  sum(1 for l in lines if "Failed password" in l or "authentication failure" in l),
    }


@router.get("/analyze")
def analyze(request: Request) -> Dict[str, Any]:
    """Sample a real log group (or dataset row) and delegate to port 8001."""
    try:
        row = _sample_event(request.app.state.df, attack_only=False)
        return _delegate_to_ingest(row)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("/analyze error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


class SimulateRequest(BaseModel):
    count: int = 1


@router.post("/simulate")
def simulate(request: Request, body: SimulateRequest) -> List[Dict[str, Any]]:
    """Sample attack rows from the real dataset and delegate each to port 8001."""
    count = max(1, min(body.count, 50))
    try:
        df = request.app.state.df
        if not has_log_corpus() and "attack_detected" in df.columns:
            # No log corpus — fall back to attack rows from the dataset
            attack_df = df[df["attack_detected"] == 1]
            df = attack_df if len(attack_df) else df
        rows = [_sample_event(df, attack_only=True) for _ in range(count)]
        return [_delegate_to_ingest(row) for row in rows]
    except HTTPException:
        raise
    except Exception as e:
        logger.error("/simulate error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/graph")
def graph() -> Dict[str, Any]:
    try:
        data = get_attack_graph()
        return {"nodes": data.get("nodes", []), "edges": data.get("edges", []),
                "count": len(data.get("nodes", []))}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/graph/clear")
def graph_clear() -> Dict[str, str]:
    try:
        clear_graph()
        return {"message": "Graph cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
def status(request: Request) -> Dict[str, Any]:
    try:
        df = request.app.state.df
        return {
            "neo4j":        test_connection(),
            "model_loaded": request.app.state.model is not None,
            "dataset_rows": len(df),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics")
def analytics(request: Request) -> Dict[str, Any]:
    """Run all 70 dataset rows through port 8001 and aggregate pattern data."""
    try:
        df   = request.app.state.df
        logs = df.to_dict(orient="records")
        results = [_delegate_to_ingest(log) for log in logs]

        flag_counts: Dict[str, int] = {}
        for r in results:
            for f in r.get("flags", []):
                flag_counts[f] = flag_counts.get(f, 0) + 1

        risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in results:
            lvl = r.get("risk_level", "LOW").upper()
            if lvl in risk_dist:
                risk_dist[lvl] += 1

        buckets = []
        for i in range(0, len(results), 10):
            chunk     = results[i:i+10]
            a_count   = sum(1 for r in chunk if r.get("anomaly"))
            avg_score = round(sum(r.get("anomaly_score", 0) for r in chunk) / max(len(chunk),1), 4)
            buckets.append({"bucket": i // 10, "anomalies": a_count, "avg_score": avg_score})

        proto_counts: Dict[str, int] = {}
        for log in logs:
            p = log.get("protocol_type", "UNKNOWN")
            proto_counts[p] = proto_counts.get(p, 0) + 1

        multi_flag = [
            {
                "flags":         r.get("flags", []),
                "risk_score":    r.get("risk_score", 0),
                "anomaly_score": r.get("anomaly_score", 0),
                "features": {k: r.get("features", {}).get(k) for k in [
                    "failed_logins", "login_attempts", "session_duration",
                    "ip_reputation_score", "unusual_time_access",
                    "network_traffic_volume", "protocol_type",
                ]},
            }
            for r in results if len(r.get("flags", [])) >= 1
        ][:15]

        return {
            "total_logs":    len(results),
            "anomaly_count": sum(1 for r in results if r.get("anomaly")),
            "flag_counts":   flag_counts,
            "risk_dist":     risk_dist,
            "buckets":       buckets,
            "proto_counts":  proto_counts,
            "multi_flag":    multi_flag,
            "rows":          results,   # full rows for frontend IP table
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

        proto_counts: Dict[str, int] = {}
        for log in logs:
            p = log.get("protocol_type", "UNKNOWN")
            proto_counts[p] = proto_counts.get(p, 0) + 1

        multi_flag = [
            {
                "flags":         r.get("flags", []),
                "risk_score":    r.get("risk_score", 0),
                "anomaly_score": r.get("anomaly_score", 0),
                "features": {k: r.get("features", {}).get(k) for k in [
                    "failed_logins", "login_attempts", "session_duration",
                    "ip_reputation_score", "unusual_time_access",
                    "network_traffic_volume", "protocol_type",
                ]},
            }
            for r in results if len(r.get("flags", [])) >= 2
        ][:10]

        return {
            "total_logs":    len(results),
            "anomaly_count": sum(1 for r in results if r.get("anomaly")),
            "flag_counts":   flag_counts,
            "risk_dist":     risk_dist,
            "buckets":       buckets,
            "proto_counts":  proto_counts,
            "multi_flag":    multi_flag,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threat-scan")
def threat_scan(request: Request) -> Dict[str, Any]:
    """Build forensic report from real attack rows in the dataset."""
    try:
        df = request.app.state.df
        # Get all attack rows
        if "attack_detected" in df.columns:
            attack_df = df[df["attack_detected"] == 1]
        else:
            attack_df = df
        if len(attack_df) == 0:
            attack_df = df

        # Score one event per attacking IP. Delegating every matching dataset row
        # instead means thousands of sequential calls to port 8001.
        groups = get_attack_log_groups()
        if groups:
            attack_rows = [
                {"src_ip": ip, "log_lines": lines, "name": "Attack",
                 "actor": _actor_from_lines(lines), "raw_log": lines[0] if lines else "",
                 "login_attempts": len(lines)}
                for ip, lines in groups.items()
            ]
        else:
            attack_rows = attack_df.head(THREAT_SCAN_MAX_ROWS).to_dict(orient="records")

        results = [_delegate_to_ingest(row) for row in attack_rows]
        worst   = max(results, key=lambda r: r.get("risk_score", 0))
        features = worst.get("features", {})

        # Use real attacker identity from the logs
        attacker_ip       = features.get("src_ip") or "10.0.1.55"
        attacker_username = features.get("actor") or "ubuntu"
        now = datetime.datetime.utcnow()

        # Timeline is built from the worst attacker's actual log lines
        evidence_lines = groups.get(attacker_ip, []) if groups else []

        # Build timeline from the worst attacker's real log lines
        events = [_timeline_entry(line) for line in evidence_lines[:8]]
        if not events:
            events = [
                _timeline_entry(row.get("raw_log", ""))
                for row in attack_rows[:8] if row.get("raw_log")
            ]

        # Identify unique attackers — count their observed log events, not rows
        attackers = {}
        for row in attack_rows:
            actor = row.get("actor","unknown")
            ip    = row.get("src_ip","")
            if actor not in attackers:
                attackers[actor] = {"ip": ip, "count": 0, "types": set()}
            attackers[actor]["count"] += len(row.get("log_lines") or [1])
            attackers[actor]["types"].add(row.get("name","Attack"))

        attacker_summary = [
            {"actor": a, "ip": v["ip"], "count": v["count"], "types": list(v["types"])}
            for a, v in sorted(attackers.items(), key=lambda x: -x[1]["count"])
        ]

        flags_readable = worst.get("readable_flags", worst.get("flags", []))
        return {
            "incidentId":       f"INC-{now.strftime('%Y%m%d')}-{random.randint(100,999)}",
            "incidentDate":     now.strftime("%Y-%m-%d"),
            "incidentTime":     now.strftime("%H:%M"),
            "analystName":      "TraceShield X AutoAnalyst",
            "systemAffected":   "ubuntu-server",
            "severity":         worst.get("risk_level", "HIGH"),
            "attackerIp":       attacker_ip,
            "attackerUsername": attacker_username,
            # A log line carries no MAC, OS or geolocation, so the panel reports
            # what the logs do establish about the attacker instead.
            "targetedAccounts": ", ".join(sorted({
                _actor_from_lines([l]) for l in evidence_lines
            } - {"unknown"})) or None,
            "firstSeen":      _log_stamp(evidence_lines[0])  if evidence_lines else None,
            "lastSeen":       _log_stamp(evidence_lines[-1]) if evidence_lines else None,
            "observedEvents": len(groups.get(attacker_ip, [])) if groups else None,
            "signalSummary":  _signal_summary(evidence_lines),
            "events":           events,
            "attackers":        attacker_summary,
            "totalAttackEvents": sum(len(r.get("log_lines") or [1]) for r in attack_rows),
            "summary": (
                f"TraceShield detected {sum(len(r.get('log_lines') or [1]) for r in attack_rows)} "
                f"malicious events across "
                f"{len(attackers)} actors. Worst actor: {attacker_username} ({attacker_ip}). "
                f"Risk score: {worst.get('risk_score',0):.2f}/100. "
                f"Triggered: {', '.join(flags_readable) if flags_readable else 'Privilege Escalation'}."
            ),
            "impact": (
                f"Session duration: {features.get('session_duration','N/A')}s. "
                f"Traffic: {features.get('network_traffic_volume','N/A')} bytes. "
                f"Sudo attempts: {features.get('sudo_attempt','N/A')}."
            ),
            "recommendations": (
                "1. Audit all sudo usage — restrict COMMAND=/bin/bash.\n"
                "2. Review /var/log/auth.log for all session opens as root.\n"
                "3. Enforce sudo policy: require password for all commands.\n"
                "4. Rotate credentials for: ubuntu, deploy, mayur, www-data.\n"
                "5. Enable auditd for real-time privilege escalation alerts."
            ),
            "riskScore":    worst.get("risk_score", 0),
            "anomalyScore": worst.get("anomaly_score", 0),
            "flags":        worst.get("flags", []),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("/threat-scan error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
def health(request: Request) -> Dict[str, Any]:
    try:
        return {"status": "ok", "neo4j": test_connection(),
                "model_loaded": request.app.state.model is not None}
    except Exception:
        return {"status": "ok", "neo4j": False, "model_loaded": False}


@router.get("/dataset/logs")
def dataset_logs() -> Dict[str, Any]:
    """Return all raw log lines from the intrusion dataset."""
    lines = get_all_log_lines()
    return {"lines": lines, "count": len(lines)}


@router.get("/dataset/rows")
def dataset_rows(request: Request) -> Dict[str, Any]:
    """Return all 70 dataset rows as JSON for frontend analytics."""
    try:
        df = request.app.state.df
        rows = df.to_dict(orient="records")
        return {"rows": rows, "count": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
def health(request: Request) -> Dict[str, Any]:
    try:
        return {"status": "ok", "neo4j": test_connection(),
                "model_loaded": request.app.state.model is not None}
    except Exception:
        return {"status": "ok", "neo4j": False, "model_loaded": False}


@router.get("/dataset/logs")
def dataset_logs() -> Dict[str, Any]:
    """Return all raw log lines from the intrusion dataset."""
    lines = get_all_log_lines()
    return {"lines": lines, "count": len(lines)}

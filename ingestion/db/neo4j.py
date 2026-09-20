"""
neo4j.py — Time-aware, duplicate-free attack graph for TraceShield.

Node types:
    (:IP     {address, status, risk_score, severity_level, last_seen})
    (:Device {name})
    (:Honeypot {id})
    (:System {name: "TraceShield"})

Relationships (MERGE — no duplicates):
    (:IP)-[:ATTACKED      {timestamp, risk_score, status, reason, severity_level, ...}]->(:Device)
    (:IP)-[:REDIRECTED_TO {timestamp, reason}]->(:Honeypot)
    (:IP)-[:BLOCKED       {timestamp, reason}]->(:System)

All relationships guaranteed to have: timestamp, reason (never None).
"""

import os
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from neo4j import GraphDatabase, Driver
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_URI      = os.getenv("NEO4J_URI",      "neo4j://127.0.0.1:7687")
_USER     = os.getenv("NEO4J_USER",     "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

_driver: Optional[Driver] = None

SEVERITY_MAP = {
    "NORMAL":       0,
    "SUSPICIOUS":   1,
    "HIGH_RISK":    2,
    "EXTREME_RISK": 3,
}


# ── Connection ────────────────────────────────────────────────────────────────

def get_driver() -> Optional[Driver]:
    global _driver
    if _driver is not None:
        return _driver
    try:
        _driver = GraphDatabase.driver(
            _URI, auth=(_USER, _PASSWORD), connection_timeout=3
        )
        logger.info("Neo4j connected at %s", _URI)
        return _driver
    except Exception as e:
        logger.warning("Neo4j unavailable: %s", e)
        return None


def close_driver() -> None:
    global _driver
    if _driver:
        try:
            _driver.close()
        except Exception:
            pass
        finally:
            _driver = None


def _run(query: str, **params) -> List[Dict[str, Any]]:
    driver = get_driver()
    if not driver:
        return []
    try:
        with driver.session() as s:
            return [r.data() for r in s.run(query, **params)]
    except Exception as e:
        logger.warning("Neo4j query failed: %s", e)
        return []


def _now() -> str:
    """Return current UTC timestamp as ISO string — never None."""
    return datetime.now(timezone.utc).isoformat()


def _build_reason(ml: float, spike: float, trend: float, temporal: float,
                  log: float = 0.0) -> str:
    """Build non-empty explainable reason string from component scores."""
    parts = []
    if ml >= 60:       parts.append(f"ml={ml:.1f}")
    if spike >= 70:    parts.append(f"spike={spike:.1f}")
    if trend >= 60:    parts.append(f"trend={trend:.1f}")
    if temporal >= 50: parts.append(f"rate={temporal:.1f}")
    if log >= 30:      parts.append(f"logs={log:.1f}")
    return "+".join(parts) if parts else "combined_score"


# ── Write operations ──────────────────────────────────────────────────────────

def store_attack_event(
    ip: str, device: str,
    risk_score: float, status: str, timestamp: str,
    ml_score: float = 0.0, spike_score: float = 0.0,
    trend_score: float = 0.0, temporal_score: float = 0.0,
    count_score: float = 0.0, log_score: float = 0.0,
) -> bool:
    """
    MERGE IP and Device nodes.
    MERGE ATTACKED relationship keyed on (ip, device, status) —
    updates metadata if same event type recurs, preventing duplicates.
    """
    severity = SEVERITY_MAP.get(status, 0)
    reason   = _build_reason(ml_score, spike_score, trend_score,
                             temporal_score, log_score)
    ts       = timestamp or _now()

    query = (
        # Merge IP — always update latest state
        "MERGE (i:IP {address: $ip}) "
        "SET i.status         = $status, "
        "    i.risk_score      = $risk_score, "
        "    i.severity_level  = $severity, "
        "    i.last_seen       = $ts "
        # Merge Device
        "MERGE (d:Device {name: $device}) "
        # MERGE relationship keyed on ip+device+status to prevent duplicates
        # ON CREATE sets initial values; ON MATCH updates to latest
        "MERGE (i)-[r:ATTACKED {status: $status}]->(d) "
        "ON CREATE SET "
        "  r.timestamp      = $ts, "
        "  r.risk_score     = $risk_score, "
        "  r.reason         = $reason, "
        "  r.severity_level = $severity, "
        "  r.ml_score       = $ml_score, "
        "  r.spike_score    = $spike_score, "
        "  r.trend_score    = $trend_score, "
        "  r.temporal_score = $temporal_score, "
        "  r.count_score    = $count_score, "
        "  r.log_score      = $log_score, "
        "  r.hit_count      = 1 "
        "ON MATCH SET "
        "  r.timestamp      = $ts, "
        "  r.risk_score     = $risk_score, "
        "  r.reason         = $reason, "
        "  r.severity_level = $severity, "
        "  r.ml_score       = $ml_score, "
        "  r.spike_score    = $spike_score, "
        "  r.trend_score    = $trend_score, "
        "  r.temporal_score = $temporal_score, "
        "  r.count_score    = $count_score, "
        "  r.log_score      = $log_score, "
        "  r.hit_count      = coalesce(r.hit_count, 1) + 1"
    )
    _run(query,
         ip=ip, device=device, ts=ts,
         risk_score=risk_score, status=status,
         severity=severity, reason=reason,
         ml_score=ml_score, spike_score=spike_score,
         trend_score=trend_score, temporal_score=temporal_score,
         count_score=count_score, log_score=log_score)

    logger.info(
        "Graph updated: IP(%s) → ATTACKED → Device(%s) [%s score=%.1f reason=%s]",
        ip, device, status, risk_score, reason
    )
    return True


def store_honeypot_redirect(
    ip: str, honeypot_id: str, reason: str, timestamp: str,
) -> bool:
    """
    MERGE IP and Honeypot nodes.
    MERGE REDIRECTED_TO relationship — update timestamp on repeat.
    """
    ts     = timestamp or _now()
    reason = reason or "combined_score"

    query = (
        "MERGE (i:IP {address: $ip}) "
        "MERGE (h:Honeypot {id: $hid}) "
        "MERGE (i)-[r:REDIRECTED_TO]->(h) "
        "ON CREATE SET r.timestamp = $ts, r.reason = $reason, r.redirect_count = 1 "
        "ON MATCH  SET r.timestamp = $ts, r.reason = $reason, "
        "              r.redirect_count = coalesce(r.redirect_count, 1) + 1"
    )
    _run(query, ip=ip, hid=honeypot_id, ts=ts, reason=reason)
    logger.info(
        "Graph updated: IP(%s) → REDIRECTED_TO → Honeypot(%s) reason=%s",
        ip, honeypot_id, reason
    )
    return True


def store_block_event(ip: str, reason: str, timestamp: str) -> bool:
    """
    MERGE IP and System nodes.
    MERGE BLOCKED relationship — update timestamp on repeat.
    """
    ts     = timestamp or _now()
    reason = reason or "combined_score"

    query = (
        "MERGE (i:IP {address: $ip}) "
        "MERGE (sys:System {name: 'TraceShield'}) "
        "MERGE (i)-[r:BLOCKED]->(sys) "
        "ON CREATE SET r.timestamp = $ts, r.reason = $reason, r.block_count = 1 "
        "ON MATCH  SET r.timestamp = $ts, r.reason = $reason, "
        "              r.block_count = coalesce(r.block_count, 1) + 1"
    )
    _run(query, ip=ip, ts=ts, reason=reason)
    logger.info(
        "Graph updated: IP(%s) → BLOCKED → System(TraceShield) reason=%s",
        ip, reason
    )
    return True


# ── Query helpers ─────────────────────────────────────────────────────────────

def get_attack_graph(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Fetch clean attack-only relationships ordered by timestamp DESC.
    Supports attack chain traversal visualization.
    """
    query = (
        "MATCH (ip:IP)-[r]->(n) "
        "WHERE type(r) IN ['ATTACKED', 'REDIRECTED_TO', 'BLOCKED'] "
        "RETURN ip.address        AS source_ip, "
        "       ip.status         AS ip_status, "
        "       ip.risk_score     AS ip_risk_score, "
        "       ip.severity_level AS ip_severity, "
        "       type(r)           AS relationship, "
        "       properties(r)     AS rel_props, "
        "       labels(n)[0]      AS target_type, "
        "       CASE labels(n)[0] "
        "         WHEN 'Device'   THEN n.name "
        "         WHEN 'Honeypot' THEN n.id "
        "         WHEN 'System'   THEN n.name "
        "         ELSE 'unknown' END AS target_name "
        "ORDER BY r.timestamp DESC "
        f"LIMIT {limit}"
    )
    return _run(query)


def get_recent_attacks(limit: int = 20) -> List[Dict[str, Any]]:
    """Fetch most recent ATTACKED relationships with full metadata."""
    query = (
        "MATCH (i:IP)-[r:ATTACKED]->(d:Device) "
        "RETURN i.address AS ip, d.name AS device, "
        "       r.risk_score AS risk_score, r.status AS status, "
        "       r.timestamp AS timestamp, r.reason AS reason, "
        "       r.ml_score AS ml_score, r.spike_score AS spike_score, "
        "       r.severity_level AS severity_level, "
        "       r.hit_count AS hit_count "
        "ORDER BY r.timestamp DESC "
        f"LIMIT {limit}"
    )
    return _run(query)


def get_attack_chain(ip: str) -> List[Dict[str, Any]]:
    """
    Fetch full attack chain for an IP — all hops ordered by timestamp.
    Supports path-based visualization: IP → Device → Honeypot → System.
    """
    query = (
        "MATCH path = (i:IP {address: $ip})-[*1..3]->(n) "
        "WHERE ALL(r IN relationships(path) "
        "          WHERE type(r) IN ['ATTACKED','REDIRECTED_TO','BLOCKED']) "
        "UNWIND relationships(path) AS r "
        "RETURN type(r) AS relationship, "
        "       properties(r) AS props, "
        "       labels(startNode(r))[0] AS from_type, "
        "       CASE labels(startNode(r))[0] "
        "         WHEN 'IP'      THEN startNode(r).address "
        "         WHEN 'Device'  THEN startNode(r).name "
        "         ELSE startNode(r).name END AS from_node, "
        "       labels(endNode(r))[0] AS to_type, "
        "       CASE labels(endNode(r))[0] "
        "         WHEN 'Device'   THEN endNode(r).name "
        "         WHEN 'Honeypot' THEN endNode(r).id "
        "         WHEN 'System'   THEN endNode(r).name "
        "         ELSE 'unknown' END AS to_node "
        "ORDER BY r.timestamp ASC"
    )
    return _run(query, ip=ip)


def get_ip_history(ip: str) -> List[Dict[str, Any]]:
    """Fetch all attack-graph relationships for a specific IP."""
    query = (
        "MATCH (i:IP {address: $ip})-[r]->(n) "
        "WHERE type(r) IN ['ATTACKED', 'REDIRECTED_TO', 'BLOCKED'] "
        "RETURN type(r) AS relationship, "
        "       properties(r) AS props, "
        "       labels(n)[0] AS target_type, "
        "       CASE labels(n)[0] "
        "         WHEN 'Device'   THEN n.name "
        "         WHEN 'Honeypot' THEN n.id "
        "         WHEN 'System'   THEN n.name "
        "         ELSE 'unknown' END AS target "
        "ORDER BY r.timestamp DESC"
    )
    return _run(query, ip=ip)


def get_graph_summary() -> Dict[str, Any]:
    """Return attack-graph node and relationship counts."""
    nodes = _run(
        "MATCH (n) WHERE n:IP OR n:Device OR n:Honeypot OR n:System "
        "RETURN labels(n)[0] AS label, count(n) AS count"
    )
    rels = _run(
        "MATCH ()-[r]->() "
        "WHERE type(r) IN ['ATTACKED','REDIRECTED_TO','BLOCKED'] "
        "RETURN type(r) AS type, count(r) AS count"
    )
    return {"nodes": nodes, "relationships": rels}


def get_all_relationships(limit: int = 100) -> List[Dict[str, Any]]:
    """Alias for get_attack_graph."""
    return get_attack_graph(limit)

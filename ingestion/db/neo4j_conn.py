"""
neo4j_conn.py — Singleton Neo4j driver for the ingestion service.
"""

import os
import logging
from typing import Optional
from neo4j import GraphDatabase, Driver
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_driver: Optional[Driver] = None

_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
_USER     = os.getenv("NEO4J_USER",     "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")


def get_driver() -> Optional[Driver]:
    """Return a singleton Neo4j driver, creating it if needed."""
    global _driver
    if _driver is not None:
        return _driver
    try:
        _driver = GraphDatabase.driver(
            _URI,
            auth=(_USER, _PASSWORD),
            connection_timeout=3,
        )
        logger.info("Neo4j driver initialised at %s", _URI)
        return _driver
    except Exception as exc:
        logger.warning("Neo4j unavailable: %s", exc)
        return None


def close_driver() -> None:
    """Close the driver and release resources."""
    global _driver
    if _driver:
        try:
            _driver.close()
        except Exception:
            pass
        finally:
            _driver = None


def store_suspicious_activity(ip: str, device: str, request_count: int,
                              timestamp: str, risk_score: float = 0.0,
                              status: str = "SUSPICIOUS",
                              ml_score: float = 0.0,
                              temporal_score: float = 0.0,
                              count_score: float = 0.0,
                              spike_score: float = 0.0) -> bool:
    """Persist event with full component breakdown including spike score."""
    driver = get_driver()
    if driver is None:
        logger.warning("Skipping Neo4j write — driver unavailable.")
        return False

    query = (
        "MERGE (i:IP {address: $ip}) "
        "MERGE (d:Device {name: $device}) "
        "CREATE (i)-[:SUSPICIOUS_ACTIVITY {"
        "  request_count: $request_count, timestamp: $timestamp, "
        "  risk_score: $risk_score, status: $status, "
        "  ml_score: $ml_score, temporal_score: $temporal_score, "
        "  count_score: $count_score, spike_score: $spike_score"
        "}]->(d)"
    )
    try:
        with driver.session() as session:
            session.run(query, ip=ip, device=device,
                        request_count=request_count, timestamp=timestamp,
                        risk_score=risk_score, status=status,
                        ml_score=ml_score, temporal_score=temporal_score,
                        count_score=count_score, spike_score=spike_score)
        logger.info("Stored [%s] ip=%s score=%.2f spike=%.1f",
                    status, ip, risk_score, spike_score)
        return True
    except Exception as exc:
        logger.warning("Neo4j write failed: %s", exc)
        return False

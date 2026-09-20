"""
anomaly.py — Real-time anomaly detection service.
Uses ML ensemble (IsolationForest + LOF) instead of a hard threshold.
"""

import logging
from datetime import datetime

from ingestion.db.neo4j_conn import store_suspicious_activity
from ingestion.services.ml_engine import get_model, _extract_features

logger = logging.getLogger(__name__)


def process_event(ip: str, device: str, request_count: int, timestamp: datetime) -> dict:
    """
    Process a single ingestion event in real time.

    Steps:
        1. Extract features from raw fields.
        2. Run ML ensemble prediction.
        3. If anomaly, persist to Neo4j.
        4. Return structured result.

    Args:
        ip:            Source IP address.
        device:        Device identifier.
        request_count: Number of requests observed.
        timestamp:     Event timestamp.

    Returns:
        Dict with anomaly flag, confidence score, message, and graph_stored.
    """
    logger.info(
        "Received event | ip=%s device=%s request_count=%d ts=%s",
        ip, device, request_count, timestamp.isoformat()
    )

    # Feature extraction + ML prediction
    model   = get_model()
    x       = _extract_features(request_count, timestamp)
    anomaly, confidence = model.predict(x)

    graph_stored = False

    if anomaly:
        logger.warning(
            "ANOMALY DETECTED | ip=%s device=%s request_count=%d confidence=%.4f",
            ip, device, request_count, confidence
        )
        graph_stored = store_suspicious_activity(
            ip, device, request_count, timestamp.isoformat()
        )

    return {
        "anomaly":      anomaly,
        "confidence":   confidence,
        "graph_stored": graph_stored,
        "message": (
            f"Anomaly detected (confidence={confidence:.2f}): "
            f"{request_count} requests from {ip} via {device}."
            if anomaly else
            f"Normal activity (confidence={confidence:.2f}) from {ip} via {device}."
        ),
    }

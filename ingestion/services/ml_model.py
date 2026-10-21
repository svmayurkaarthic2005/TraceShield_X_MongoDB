"""
ml_model.py — Thin inference wrapper for TraceShield ML pipeline.

Delegates ALL feature engineering and inference to ml_training.py.
Single source of truth: 8 unified features.

Lifecycle:
    Startup  → try loading saved model; if missing, log warning, set None
    Inference → if model None, return fallback score (no crash)
    Training → POST /ml/train trains + saves + reloads into memory
"""

import logging
from datetime import datetime
from typing import Optional

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ingestion.services.ml_training import (
    FEATURE_COLS,
    load_saved_model,
    train,
    predict,
)

logger = logging.getLogger(__name__)

# Selected from the VALIDATION split's per-scenario ml_score distribution
# (ingestion/services/ml_training.py's normal_benign_spike / attack_volume_only
# scenarios — see `ingestion.services.ml_training.describe_splits` /
# `evaluate(scenario=...)`), never from the held-out test split:
#   normal_benign_spike (legitimate volume burst, no log signal): max  72.42
#   attack_volume_only  (flood/scraper, no log signal):           min  73.30
# 60.0 (the prior value) sat well inside the benign-spike range, so the
# clean-baseline-guard ML override it feeds (risk_engine.py) flagged 100% of
# benign volume spikes as an anomaly — confirmed via
# evaluate(scenario="normal_benign_spike") returning false_positive_rate=1.0.
# 73.0 sits in the gap between the two distributions; confirmed afterward
# (not re-tuned) against the test split, where the same gap holds (benign
# spike max 71.22, attack-volume-only min 74.00).
#
# Caveat: this clean separation is a property of THIS synthetic dataset's
# construction (attack_volume_only was deliberately generated more extreme
# than normal_benign_spike as a modeling assumption — see ml_training.py's
# _generate_synthetic_dataset docstring). It demonstrates the threshold
# mechanism works as intended under that assumption; it is not evidence that
# real floods and real traffic bursts are this cleanly separable in practice.
# Trade-off if real attacks turn out closer to benign spikes than assumed:
# raising this threshold trades away some volume-only-attack recall (for any
# real attack whose ml_score lands in [60, 73)) to eliminate the benign-spike
# false-positive rate measured here. Revisit with real captured traffic
# before relying on this number operationally.
ML_ANOMALY_THRESHOLD = 73.0

_model:  Optional[IsolationForest] = None
_scaler: Optional[StandardScaler]  = None
_model_loaded: bool = False


def load_model() -> bool:
    """
    Try loading saved model from disk.
    Does NOT train if missing — returns False instead.

    Returns:
        True if model loaded successfully, False if not found.
    """
    global _model, _scaler, _model_loaded
    saved_model, saved_scaler = load_saved_model()
    if saved_model is not None:
        _model        = saved_model
        _scaler       = saved_scaler
        _model_loaded = True
        logger.info(
            "ML model loaded successfully (%d features: %s).",
            len(FEATURE_COLS), FEATURE_COLS
        )
        return True

    logger.warning(
        "No trained model found at ingestion/models/. "
        "Run POST /ml/train to train and save the model."
    )
    _model_loaded = False
    return False


def reload_model() -> bool:
    """Force reload model from disk after training. Returns True on success."""
    global _model, _scaler, _model_loaded
    _model        = None
    _scaler       = None
    _model_loaded = False
    return load_model()


def is_loaded() -> bool:
    return _model_loaded and _model is not None


def _fallback_score(request_count: int, deviation: float,
                    failed_logins: float, suspicious_commands: float) -> float:
    """
    Rule-based fallback score when ML model is not loaded.
    Approximates anomaly likelihood from raw signals.
    """
    score = 0.0
    if request_count > 300:   score += 35.0
    elif request_count > 100: score += 20.0
    elif request_count > 50:  score += 10.0
    if deviation > 3.0:       score += 25.0
    elif deviation > 1.0:     score += 10.0
    if failed_logins > 5:     score += 20.0
    if suspicious_commands > 0: score += 15.0
    return min(score, 100.0)


def get_ml_score(
    request_count: int,
    timestamp: datetime,
    deviation: float = 0.0,
    hist_rate: float = 0.0,
    failed_logins: float = 0.0,
    sudo_attempts: float = 0.0,
    suspicious_commands: float = 0.0,
    sensitive_file_access: float = 0.0,
    trend_score: float = 0.0,
) -> float:
    """
    Return ML anomaly score (0–100). Uses trained model if loaded,
    otherwise returns a rule-based fallback score.

    Feature vector shape: (1, 8) — validated before inference.

    trend_score must be the same definition training uses (0-100 escalation
    score over an IP's recent request-count history — see
    ip_memory.IPRecord.trend_score(), the sole real-time source for this
    signal). Callers must pass it; it is never fabricated or left at 0 here
    (a prior version hardcoded 0.0, silently zeroing out the single most
    class-discriminating feature in the training data for every real event).
    """
    if not is_loaded():
        score = _fallback_score(request_count, deviation,
                                failed_logins, suspicious_commands)
        logger.warning(
            "ML model not loaded — using fallback score=%.2f. "
            "Run POST /ml/train to enable ML inference.", score
        )
        return score

    rps = hist_rate if hist_rate > 0 else request_count / 60.0

    # spike_score is documented (FEATURE_COLS, ml_training.py) and trained as
    # a 0-100 quantity, and risk_engine.py's OWN weighted-sum component
    # (_spike_score()) already clips it to that range. This raw `deviation`
    # (a ratio, e.g. 11.5 for a 1150% spike) was being multiplied straight
    # through with no such clip, so any large relative spike fed the model an
    # out-of-distribution value the scaler was never calibrated for (e.g.
    # spike_score=1150) — confirmed live: a 20->250 request burst produced
    # ml_score=73, statistically indistinguishable from a 10->4000 flood
    # (ml_score=75), because both saturated past the trained 0-100 range.
    # Clipping here makes the ML feature consistent with the same signal's
    # other use in this same request (risk_engine's weighted-sum component).
    feature_dict = {
        "request_count":         float(request_count),
        "requests_per_second":   float(rps),
        "spike_score":           float(min(deviation * 100.0, 100.0)),
        "trend_score":           float(trend_score),
        "failed_logins":         float(failed_logins),
        "sudo_attempts":         float(sudo_attempts),
        "suspicious_commands":   float(suspicious_commands),
        "sensitive_file_access": float(sensitive_file_access),
    }

    # Validate feature count before inference
    if len(feature_dict) != len(FEATURE_COLS):
        logger.error(
            "Feature mismatch: expected %d got %d — using fallback.",
            len(FEATURE_COLS), len(feature_dict)
        )
        return _fallback_score(request_count, deviation,
                               failed_logins, suspicious_commands)

    result = predict(_model, _scaler, feature_dict)
    score  = result["ml_score"]

    logger.debug(
        "ML inference | shape=(1,%d) score=%.2f anomaly=%s decision=%.4f",
        len(FEATURE_COLS), score, result["anomaly"], result["decision_score"]
    )

    if result["anomaly"]:
        logger.warning(
            "ML anomaly detected: score=%.2f prediction=%d decision=%.4f",
            score, result["prediction"], result["decision_score"]
        )

    return score

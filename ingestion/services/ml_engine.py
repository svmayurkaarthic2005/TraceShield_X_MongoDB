"""
ml_engine.py — ML-based anomaly detection engine for TraceShield ingestion.

Ensemble approach:
  - Isolation Forest  (global outlier detection)
  - Local Outlier Factor (density-based local anomaly)
  - Feature engineering on raw ingestion fields
  - Calibrated score fusion → final anomaly probability

Trained on synthetic data that mirrors real attack distributions.
Drop-in replacement for the threshold rule in anomaly.py.
"""

import logging
import numpy as np
from datetime import datetime
from typing import Tuple

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

logger = logging.getLogger(__name__)

# ── Feature engineering ───────────────────────────────────────────────────────

def _extract_features(request_count: int, timestamp: datetime) -> np.ndarray:
    """
    Build a feature vector from raw ingestion fields.

    Features:
        0  request_count          — raw volume
        1  log1p_request_count    — log-scaled volume (reduces skew)
        2  hour_of_day            — 0-23 (night access = suspicious)
        3  is_night               — 1 if hour in [0,6] or [22,23]
        4  is_weekend             — 1 if Saturday/Sunday
        5  requests_per_minute    — rate proxy (count / 60)
        6  burst_flag             — 1 if count > 200
    """
    h = timestamp.hour
    dow = timestamp.weekday()

    return np.array([[
        request_count,
        np.log1p(request_count),
        h,
        1 if (h <= 6 or h >= 22) else 0,
        1 if dow >= 5 else 0,
        request_count / 60.0,
        1 if request_count > 200 else 0,
    ]])


# ── Synthetic training data ───────────────────────────────────────────────────

def _generate_training_data(n: int = 8000) -> np.ndarray:
    """
    Generate labelled synthetic training data.

    Distribution:
        80% normal  — low request counts, business hours
        20% attack  — high counts, night/weekend, bursts
    """
    import random
    random.seed(42)
    np.random.seed(42)

    rows = []
    n_normal = int(n * 0.80)
    n_attack = n - n_normal

    # Normal traffic
    for _ in range(n_normal):
        count = int(np.random.lognormal(mean=3.5, sigma=0.8))  # ~33 median
        count = max(1, min(count, 95))
        h     = random.randint(8, 20)
        dow   = random.randint(0, 4)
        ts    = datetime(2025, 1, 1, h, 0)
        ts    = ts.replace(day=1 + dow)
        rows.append(_extract_features(count, ts)[0])

    # Attack traffic
    for _ in range(n_attack):
        count = int(np.random.lognormal(mean=5.5, sigma=1.0))  # ~245 median
        count = max(101, min(count, 5000))
        h     = random.choice(list(range(0, 6)) + list(range(22, 24)))
        dow   = random.randint(0, 6)
        ts    = datetime(2025, 1, 1, h, 0)
        rows.append(_extract_features(count, ts)[0])

    return np.array(rows)


# ── Model training ────────────────────────────────────────────────────────────

class AnomalyEnsemble:
    """
    Two-model ensemble:
      - IsolationForest  (contamination=0.20)
      - LocalOutlierFactor (novelty=True, contamination=0.20)

    Scores are fused via weighted average then thresholded.
    """

    def __init__(self):
        self.scaler = StandardScaler()
        self.iso    = IsolationForest(
            n_estimators=200,
            contamination=0.20,
            max_features=0.8,
            random_state=42,
        )
        self.lof    = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.20,
            novelty=True,
        )
        self._trained = False

    def train(self, X: np.ndarray) -> None:
        X_scaled = self.scaler.fit_transform(X)
        self.iso.fit(X_scaled)
        self.lof.fit(X_scaled)
        self._trained = True
        logger.info("AnomalyEnsemble trained on %d samples.", len(X))

    def predict(self, x: np.ndarray) -> Tuple[bool, float]:
        """
        Returns (is_anomaly, confidence_score 0-1).
        Higher score = more anomalous.
        """
        if not self._trained:
            raise RuntimeError("Model not trained.")

        x_scaled = self.scaler.transform(x)

        # IsolationForest: decision_function → lower = more anomalous
        iso_score = self.iso.decision_function(x_scaled)[0]   # typically [-0.5, 0.5]
        iso_norm  = 1 - (iso_score + 0.5)                     # flip: high = anomalous

        # LOF: decision_function → lower = more anomalous
        lof_score = self.lof.decision_function(x_scaled)[0]
        lof_norm  = 1 - (lof_score + 0.5)

        # Weighted fusion (ISO slightly more weight for global outliers)
        fused = np.clip(0.55 * iso_norm + 0.45 * lof_norm, 0.0, 1.0)

        # Hard rule override: very high counts are always anomalous
        raw_count = x[0][0]
        if raw_count > 300:
            fused = max(fused, 0.90)

        is_anomaly = bool(fused >= 0.50)
        return is_anomaly, round(float(fused), 4)


# ── Singleton ─────────────────────────────────────────────────────────────────

_model: AnomalyEnsemble = None


def get_model() -> AnomalyEnsemble:
    global _model
    if _model is None:
        _model = AnomalyEnsemble()
        X = _generate_training_data(8000)
        _model.train(X)
    return _model

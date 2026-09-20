"""
ml_training.py — Single ML pipeline for TraceShield hybrid detection.

This module is the SINGLE SOURCE OF TRUTH for:
    - Feature engineering (8 unified features)
    - Model training
    - Model persistence (model.pkl + scaler.pkl)
    - Inference
    - Evaluation

ml_model.py is a thin wrapper that delegates to this module.
No separate feature sets exist anywhere in the codebase.

Unified feature set (8):
    0  request_count          — raw network request volume
    1  requests_per_second    — request rate
    2  spike_score            — deviation from IP historical average (0-100)
    3  trend_score            — escalation trend score (0-100)
    4  failed_logins          — count from Linux auth logs
    5  sudo_attempts          — count from Linux auth logs
    6  suspicious_commands    — count from Linux syslog
    7  sensitive_file_access  — count from Linux syslog
"""

import os
import logging
import pickle
import numpy as np
import pandas as pd
from typing import Tuple, Optional, Dict, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

logger = logging.getLogger(__name__)

MODEL_PATH  = os.path.join("ingestion", "models", "isolation_forest.pkl")
SCALER_PATH = os.path.join("ingestion", "models", "scaler.pkl")

# Feature columns used for training and inference
FEATURE_COLS = [
    "request_count",
    "requests_per_second",
    "spike_score",
    "trend_score",
    "failed_logins",
    "sudo_attempts",
    "suspicious_commands",
    "sensitive_file_access",
]


# ── Feature engineering ───────────────────────────────────────────────────────

def build_feature_vector(
    request_count: float = 0,
    requests_per_second: float = 0,
    spike_score: float = 0,
    trend_score: float = 0,
    failed_logins: float = 0,
    sudo_attempts: float = 0,
    suspicious_commands: float = 0,
    sensitive_file_access: float = 0,
) -> np.ndarray:
    """Convert raw signals into a normalized feature vector."""
    return np.array([[
        request_count,
        requests_per_second,
        spike_score,
        trend_score,
        failed_logins,
        sudo_attempts,
        suspicious_commands,
        sensitive_file_access,
    ]])


def features_from_dict(d: Dict[str, Any]) -> np.ndarray:
    """Build feature vector from a dict (missing keys default to 0)."""
    return build_feature_vector(
        request_count         = d.get("request_count", 0),
        requests_per_second   = d.get("requests_per_second", 0),
        spike_score           = d.get("spike_score", 0),
        trend_score           = d.get("trend_score", 0),
        failed_logins         = d.get("failed_logins", 0),
        sudo_attempts         = d.get("sudo_attempts", 0),
        suspicious_commands   = d.get("suspicious_commands", 0),
        sensitive_file_access = d.get("sensitive_file_access", 0),
    )


# ── Dataset loading ───────────────────────────────────────────────────────────

def load_dataset(csv_path: Optional[str] = None) -> pd.DataFrame:
    """
    Load training dataset from CSV or generate synthetic data.

    CSV must contain columns matching FEATURE_COLS.
    Optional 'label' column: 0=normal, 1=attack (used for evaluation only).
    """
    if csv_path and os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        logger.info("Loaded dataset: %s (%d rows)", csv_path, len(df))
        # Ensure all feature columns exist
        for col in FEATURE_COLS:
            if col not in df.columns:
                df[col] = 0
        return df

    logger.info("No dataset found — generating synthetic training data.")
    return _generate_synthetic_dataset(n=10000)


def _generate_synthetic_dataset(n: int = 10000) -> pd.DataFrame:
    """
    Generate synthetic hybrid dataset with realistic distributions.

    Distribution: 80% normal, 20% attack
    """
    import random
    random.seed(42)
    np.random.seed(42)

    rows = []
    n_normal = int(n * 0.80)
    n_attack = n - n_normal

    # Normal traffic
    for _ in range(n_normal):
        rows.append({
            "request_count":         int(np.clip(np.random.lognormal(3.0, 0.7), 1, 80)),
            "requests_per_second":   round(np.random.uniform(0.01, 1.5), 3),
            "spike_score":           round(np.random.uniform(0, 15), 2),
            "trend_score":           round(np.random.uniform(0, 20), 2),
            "failed_logins":         int(np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1])),
            "sudo_attempts":         int(np.random.choice([0, 1], p=[0.9, 0.1])),
            "suspicious_commands":   0,
            "sensitive_file_access": int(np.random.choice([0, 1], p=[0.95, 0.05])),
            "label":                 0,
        })

    # Attack traffic
    for _ in range(n_attack):
        rows.append({
            "request_count":         int(np.clip(np.random.lognormal(5.5, 1.0), 100, 5000)),
            "requests_per_second":   round(np.random.uniform(5.0, 100.0), 3),
            "spike_score":           round(np.random.uniform(60, 100), 2),
            "trend_score":           round(np.random.uniform(50, 100), 2),
            "failed_logins":         int(np.random.randint(3, 20)),
            "sudo_attempts":         int(np.random.randint(1, 5)),
            "suspicious_commands":   int(np.random.randint(1, 8)),
            "sensitive_file_access": int(np.random.randint(1, 5)),
            "label":                 1,
        })

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


# ── Training ──────────────────────────────────────────────────────────────────

def train(
    csv_path: Optional[str] = None,
    contamination: float = 0.20,
    save: bool = True,
) -> Tuple[IsolationForest, StandardScaler]:
    """
    Train Isolation Forest on hybrid feature dataset.

    Args:
        csv_path:      Path to CSV dataset. Uses synthetic if None.
        contamination: Expected anomaly fraction (default 0.20).
        save:          Whether to persist model to disk.

    Returns:
        (trained IsolationForest, fitted StandardScaler)
    """
    df = load_dataset(csv_path)

    # Train only on normal data if label column exists
    if "label" in df.columns:
        normal_df = df[df["label"] == 0]
        logger.info("Training on %d normal samples (of %d total)",
                    len(normal_df), len(df))
        X_train = normal_df[FEATURE_COLS].fillna(0).values
    else:
        X_train = df[FEATURE_COLS].fillna(0).values
        logger.info("Training on %d samples (no label column)", len(X_train))

    scaler  = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    model = IsolationForest(
        n_estimators=300,
        contamination=contamination,
        max_features=1.0,
        bootstrap=False,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)
    logger.info("IsolationForest trained on %d samples.", len(X_train))

    if save:
        _save_model(model, scaler)

    return model, scaler


def _save_model(model: IsolationForest, scaler: StandardScaler) -> None:
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    logger.info("Model saved to %s", MODEL_PATH)


def load_saved_model() -> Tuple[Optional[IsolationForest], Optional[StandardScaler]]:
    """Load persisted model and scaler from disk."""
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)
        logger.info("Loaded saved model from %s", MODEL_PATH)
        return model, scaler
    return None, None


# ── Inference ─────────────────────────────────────────────────────────────────

def predict(
    model: IsolationForest,
    scaler: StandardScaler,
    feature_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run inference on a single feature dict.

    Returns:
        {
            ml_score:   float (0-100, higher = more anomalous),
            prediction: int   (-1 = anomaly, 1 = normal),
            anomaly:    bool
        }
    """
    X = features_from_dict(feature_dict)
    X_scaled = scaler.transform(X)

    prediction    = model.predict(X_scaled)[0]          # -1 or 1
    decision_score = model.decision_function(X_scaled)[0]  # lower = more anomalous

    # Normalize to 0-100: lower decision score → higher anomaly score
    # Typical range: [-0.5, 0.5] → map to [0, 100]
    ml_score = (0.5 - decision_score) / 1.0 * 100.0
    ml_score = float(np.clip(ml_score, 0.0, 100.0))

    anomaly = prediction == -1

    if anomaly:
        logger.warning(
            "ML anomaly detected: score=%.2f prediction=%d decision=%.4f",
            ml_score, prediction, decision_score
        )
    else:
        logger.debug(
            "ML normal: score=%.2f prediction=%d decision=%.4f",
            ml_score, prediction, decision_score
        )

    return {
        "ml_score":      round(ml_score, 2),
        "prediction":    int(prediction),
        "anomaly":       anomaly,
        "decision_score": round(float(decision_score), 4),
    }


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(csv_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluate trained model on dataset.
    Prints anomaly ratio and classification report if labels exist.

    Returns:
        Dict with evaluation metrics.
    """
    model, scaler = load_saved_model()
    if model is None:
        model, scaler = train(csv_path, save=True)

    df = load_dataset(csv_path)
    X  = df[FEATURE_COLS].fillna(0).values
    X_scaled = scaler.transform(X)

    predictions    = model.predict(X_scaled)
    decision_scores = model.decision_function(X_scaled)

    anomaly_count = int((predictions == -1).sum())
    total         = len(predictions)
    anomaly_ratio = round(anomaly_count / total * 100, 2)

    logger.info("Evaluation: %d/%d anomalies (%.1f%%)",
                anomaly_count, total, anomaly_ratio)

    result = {
        "total_samples":  total,
        "anomaly_count":  anomaly_count,
        "normal_count":   total - anomaly_count,
        "anomaly_ratio":  anomaly_ratio,
    }

    # If labels exist, compute classification metrics
    if "label" in df.columns:
        y_true = df["label"].values
        y_pred = (predictions == -1).astype(int)
        report = classification_report(y_true, y_pred,
                                       target_names=["normal", "attack"],
                                       output_dict=True)
        result["classification_report"] = report
        attack_recall = report.get("attack", {}).get("recall", 0)
        logger.info("Attack recall: %.2f", attack_recall)
        result["attack_recall"] = round(attack_recall, 4)

    return result

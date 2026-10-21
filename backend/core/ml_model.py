"""
ml_model.py — Anomaly detection module for TraceShield X++
Uses Isolation Forest with StandardScaler preprocessing.
"""

import os
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Resolved from this file, not the working directory — the backend is started
# from backend/, where a repo-relative path does not exist.
_REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_PATH = os.path.join(_REPO_ROOT, "backend", "data", "intrusion_data.csv")

REQUIRED_FEATURES = [
    "login_attempts",
    "failed_logins",
    "session_duration",
    "ip_reputation_score",
    "unusual_time_access",
]


def load_dataset() -> pd.DataFrame:
    """
    Load the intrusion dataset from disk or fall back to synthetic data.

    Returns:
        pd.DataFrame: Raw dataset with all columns.
    """
    local_data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "intrusion_data.csv")
    target_path = DATASET_PATH if os.path.exists(DATASET_PATH) else local_data_path
    if os.path.exists(target_path):
        df = pd.read_csv(target_path)
        print(f"Loaded real dataset with {len(df)} rows from {target_path}")
        return df

    try:
        from backend.core.simulation import generate_synthetic_logs
    except ImportError:
        from core.simulation import generate_synthetic_logs

    records = generate_synthetic_logs(5000)
    df = pd.DataFrame(records)
    print(
        "Using synthetic training data — place real dataset at "
        "backend/data/intrusion_data.csv for production mode."
    )
    return df


def _select_and_clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    Select required features and fill missing values with column medians.

    Args:
        df: Raw dataframe.

    Returns:
        pd.DataFrame: Cleaned feature matrix.
    """
    available = [col for col in REQUIRED_FEATURES if col in df.columns]
    X = df[available].copy()

    # Add any missing required columns as NaN so median-fill handles them
    for col in REQUIRED_FEATURES:
        if col not in X.columns:
            X[col] = np.nan

    X = X[REQUIRED_FEATURES]
    X = X.fillna(X.median(numeric_only=True))
    return X


def train_model() -> Tuple[IsolationForest, StandardScaler, pd.DataFrame]:
    """
    Load data, preprocess, and train an Isolation Forest model.

    Returns:
        Tuple of (trained IsolationForest, fitted StandardScaler, raw DataFrame).

    Raises:
        RuntimeError: If training fails for any reason.
    """
    try:
        df = load_dataset()
        X = _select_and_clean(df)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_scaled)

        print(f"Model trained successfully on {len(X)} samples")
        return model, scaler, df

    except Exception as e:
        raise RuntimeError(f"Model training failed: {e}") from e


def predict_anomaly(
    model: IsolationForest,
    scaler: StandardScaler,
    input_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Predict whether a single input record is anomalous.

    Args:
        model:      Trained IsolationForest instance.
        scaler:     Fitted StandardScaler instance.
        input_dict: Dictionary with feature values for one record.

    Returns:
        Dict with keys:
            "anomaly" (bool) — True if anomalous.
            "score"   (float) — Normalized anomaly score in [0, 1].

    Raises:
        ValueError: If input cannot be processed.
    """
    try:
        row = pd.DataFrame([input_dict])

        # Ensure all required features exist; fill missing with NaN then median
        for col in REQUIRED_FEATURES:
            if col not in row.columns:
                row[col] = np.nan

        row = row[REQUIRED_FEATURES]
        row = row.fillna(row.median(numeric_only=True))

        # If still NaN (all-NaN column), fill with 0
        row = row.fillna(0)

        X_scaled = scaler.transform(row)

        prediction = model.predict(X_scaled)          # 1 = normal, -1 = anomaly
        raw_score = model.decision_function(X_scaled)  # higher = more normal

        # Normalize to [0, 1] where 1 = most anomalous
        normalized_score = 1 - (raw_score - raw_score.min()) / (
            raw_score.max() - raw_score.min() + 1e-8
        )
        normalized_score = float(np.clip(normalized_score[0], 0.0, 1.0))

        return {
            "anomaly": bool(prediction[0] == -1),
            "score": normalized_score,
        }

    except Exception as e:
        raise ValueError(f"Prediction failed: {e}") from e


def get_sample_row(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Return a random row from the dataframe as a dictionary.

    Args:
        df: Source dataframe.

    Returns:
        Dict representing one record.
    """
    return df.sample(1).to_dict(orient="records")[0]

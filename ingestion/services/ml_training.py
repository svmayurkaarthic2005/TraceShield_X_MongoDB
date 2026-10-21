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
import json
import uuid
import logging
import pickle
import numpy as np
import pandas as pd
from typing import Tuple, Optional, Dict, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

logger = logging.getLogger(__name__)

# Fixed split of the synthetic dataset so train/validation/test never overlap.
# A row's split is assigned once, by position, in _generate_synthetic_dataset —
# train() only ever fits on "train", evaluate() only ever scores "test" by
# default, so a held-out evaluation can no longer re-score training rows.
SPLIT_SEED  = 42
TRAIN_FRAC  = 0.60
VAL_FRAC    = 0.20  # remaining 0.20 is test

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

def load_dataset(csv_path: Optional[str] = None, split: Optional[str] = None,
                 master_seed: int = 42) -> pd.DataFrame:
    """
    Load training dataset from CSV or generate synthetic data.

    CSV must contain columns matching FEATURE_COLS.
    Optional 'label' column: 0=normal, 1=attack (used for evaluation only).

    split: None returns every row (legacy behavior). "train"/"val"/"test"
    returns only that held-out slice. A CSV without its own "split" column
    gets one assigned deterministically by row position (same TRAIN_FRAC/
    VAL_FRAC cut as the synthetic generator) so real datasets can use the
    same held-out evaluation path — a best-effort fallback, not a claim that
    it is equivalent to a dataset designed for splitting.

    master_seed: which independently-generated synthetic dataset to build
    (ignored for a real CSV). Default 42 is the one the persisted production
    model is trained on — every existing caller that doesn't pass this gets
    byte-identical behavior to before. Other values produce a genuinely
    different random draw, used only for seed-robustness checks (see
    test_threshold_robustness.py) — never for the production model itself.
    """
    if csv_path and os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        logger.info("Loaded dataset: %s (%d rows)", csv_path, len(df))
        # Ensure all feature columns exist
        for col in FEATURE_COLS:
            if col not in df.columns:
                df[col] = 0
        if "split" not in df.columns:
            df["split"] = _assign_splits(len(df))
    else:
        logger.info("No dataset found — generating synthetic training data.")
        df = _generate_synthetic_dataset(n=10000, master_seed=master_seed)

    if split is not None:
        df = df[df["split"] == split].reset_index(drop=True)
    return df


def _assign_splits(n: int) -> list:
    """Deterministic positional train/val/test labels, no shuffling (caller's
    row order is assumed already randomized, as the synthetic generator's is)."""
    n_train = int(n * TRAIN_FRAC)
    n_val   = int(n * VAL_FRAC)
    return ["train"] * n_train + ["val"] * n_val + ["test"] * (n - n_train - n_val)


def _stratified_tag(rows: list, rng_seed: int) -> pd.DataFrame:
    """Shuffle one category's rows with its own reproducible seed and tag
    each with a split — so every category contributes the same TRAIN_FRAC/
    VAL_FRAC proportion to train/val/test, instead of relying on a single
    global shuffle to statistically average out by chance."""
    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=rng_seed).reset_index(drop=True)
    df["split"] = _assign_splits(len(df))
    return df


def _generate_synthetic_dataset(n: int = 10000, master_seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic hybrid dataset with realistic distributions.

    Four categories, not two — distinguishing "has a volume spike" from "is
    malicious" (they are not the same axis):
      - normal_typical       (76%): ordinary low-volume traffic.      label=0
      - normal_benign_spike  (4%):  legitimate traffic burst (sale,
                                     batch job) — high volume, ZERO
                                     log signals.                     label=0
      - attack_signature     (18%): attack with recognizable log
                                     signals (sudo/failed/sensitive/
                                     suspicious).                     label=1
      - attack_volume_only   (2%):  flood/scraper — high volume, ZERO
                                     log signals, same blind spot as
                                     normal_benign_spike but deliberately
                                     generated MORE extreme (assumption:
                                     floods are statistically more intense
                                     than organic bursts — an assumption,
                                     not a verified real-world fact).  label=1

    Each category is independently shuffled and split (see _stratified_tag)
    so train/val/test each get the same proportion of every category —
    not left to chance from one global shuffle. A "scenario" column records
    which category produced each row, for the separate volume-only-vs-
    benign-spike evaluation this enables.

    Distribution overall: ~80% normal, ~20% attack (same prevalence
    assumption as before; see module docstring / contamination discussion
    for why this is illustrative, not a measured real-world base rate).
    """
    np.random.seed(master_seed)

    n_normal = int(n * 0.80)
    n_attack = n - n_normal
    n_normal_typical = int(n_normal * 0.95)
    n_normal_spike   = n_normal - n_normal_typical
    n_attack_sig     = int(n_attack * 0.90)
    n_attack_volume  = n_attack - n_attack_sig

    normal_typical = [{
        "request_count":         int(np.clip(np.random.lognormal(3.0, 0.7), 1, 80)),
        "requests_per_second":   round(np.random.uniform(0.01, 1.5), 3),
        "spike_score":           round(np.random.uniform(0, 15), 2),
        "trend_score":           round(np.random.uniform(0, 20), 2),
        "failed_logins":         int(np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1])),
        "sudo_attempts":         int(np.random.choice([0, 1], p=[0.9, 0.1])),
        "suspicious_commands":   0,
        "sensitive_file_access": int(np.random.choice([0, 1], p=[0.95, 0.05])),
        "label":                 0,
        "scenario":              "normal_typical",
    } for _ in range(n_normal_typical)]

    normal_benign_spike = [{
        "request_count":         int(np.clip(np.random.lognormal(5.2, 0.4), 80, 400)),
        "requests_per_second":   round(np.random.uniform(2.0, 20.0), 3),
        "spike_score":           round(np.random.uniform(40, 85), 2),
        "trend_score":           round(np.random.uniform(15, 55), 2),
        "failed_logins":         0,
        "sudo_attempts":         int(np.random.choice([0, 1], p=[0.95, 0.05])),
        "suspicious_commands":   0,
        "sensitive_file_access": 0,
        "label":                 0,
        "scenario":              "normal_benign_spike",
    } for _ in range(n_normal_spike)]

    attack_signature = [{
        "request_count":         int(np.clip(np.random.lognormal(5.5, 1.0), 100, 5000)),
        "requests_per_second":   round(np.random.uniform(5.0, 100.0), 3),
        "spike_score":           round(np.random.uniform(60, 100), 2),
        "trend_score":           round(np.random.uniform(50, 100), 2),
        "failed_logins":         int(np.random.randint(3, 20)),
        "sudo_attempts":         int(np.random.randint(1, 5)),
        "suspicious_commands":   int(np.random.randint(1, 8)),
        "sensitive_file_access": int(np.random.randint(1, 5)),
        "label":                 1,
        "scenario":              "attack_signature",
    } for _ in range(n_attack_sig)]

    attack_volume_only = [{
        "request_count":         int(np.clip(np.random.lognormal(6.3, 0.6), 300, 5000)),
        "requests_per_second":   round(np.random.uniform(15.0, 100.0), 3),
        "spike_score":           round(np.random.uniform(80, 100), 2),
        "trend_score":           round(np.random.uniform(65, 100), 2),
        "failed_logins":         0,
        "sudo_attempts":         0,
        "suspicious_commands":   0,
        "sensitive_file_access": 0,
        "label":                 1,
        "scenario":              "attack_volume_only",
    } for _ in range(n_attack_volume)]

    # i+0..3 offsets reproduce the exact original seeds (42,43,44,45) when
    # master_seed=42 — the default path's output is unchanged from before
    # this parameter existed.
    parts = [
        _stratified_tag(normal_typical,      master_seed),
        _stratified_tag(normal_benign_spike, master_seed + 1),
        _stratified_tag(attack_signature,    master_seed + 2),
        _stratified_tag(attack_volume_only,  master_seed + 3),
    ]
    df = pd.concat(parts, ignore_index=True)
    # Cosmetic re-shuffle of row ORDER only — split/label/scenario travel
    # with each row, so this cannot move a row across its assigned split.
    df = df.sample(frac=1, random_state=master_seed).reset_index(drop=True)
    return df


def check_no_cross_split_duplicates(csv_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify no identical feature row appears in more than one split. The
    positional-cut construction already makes this structurally impossible
    for a single generated frame (a row occupies exactly one position, hence
    exactly one split) — this additionally catches the weaker case of two
    DIFFERENT rows that happen to carry an identical feature vector landing
    in different splits, which would still be a leakage-equivalent outcome.
    """
    full = load_dataset(csv_path, split=None)
    grouped = full.groupby(list(FEATURE_COLS))["split"].nunique()
    collisions = int((grouped > 1).sum())
    return {
        "total_rows":              len(full),
        "unique_feature_vectors":  len(grouped),
        "cross_split_collisions":  collisions,
    }


def describe_splits(csv_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Report each split's size, class balance and scenario composition —
    the evidence needed to verify the split isn't silently imbalanced.
    """
    full = load_dataset(csv_path, split=None)
    out = {}
    for split in ("train", "val", "test"):
        sub = full[full["split"] == split]
        row = {
            "n": int(len(sub)),
            "pct_of_total": round(len(sub) / len(full) * 100, 2),
        }
        if "label" in sub.columns:
            row["normal_count"] = int((sub["label"] == 0).sum())
            row["attack_count"] = int((sub["label"] == 1).sum())
            row["pct_attack"] = round(row["attack_count"] / len(sub) * 100, 2) if len(sub) else 0.0
        if "scenario" in sub.columns:
            row["scenario_counts"] = sub["scenario"].value_counts().to_dict()
        out[split] = row
    return out


# ── Training ──────────────────────────────────────────────────────────────────

def train(
    csv_path: Optional[str] = None,
    contamination: float = 0.20,
    save: bool = True,
    master_seed: int = 42,
) -> Tuple[IsolationForest, StandardScaler]:
    """
    Train Isolation Forest on hybrid feature dataset.

    Args:
        csv_path:      Path to CSV dataset. Uses synthetic if None.
        contamination: Expected anomaly fraction (default 0.20).
        save:          Whether to persist model to disk.
        master_seed:   Which independently-generated synthetic dataset to use
                       (default 42 — the production dataset). Pass save=False
                       with a different seed for seed-robustness experiments;
                       never save=True with a non-default seed, that would
                       silently replace the production artifact.

    Returns:
        (trained IsolationForest, fitted StandardScaler)
    """
    if save and master_seed != 42:
        raise ValueError(
            "refusing to save a model trained on a non-production seed "
            f"(master_seed={master_seed}) — pass save=False for experiments."
        )
    df = load_dataset(csv_path, split="train", master_seed=master_seed)

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


META_PATH = os.path.join("ingestion", "models", "model_meta.json")

# Bump this whenever the synthetic dataset's distribution/semantics change in
# a way that makes an old model mismatched even though its feature COUNT is
# still 8 (same shape, silently different meaning) — e.g. this round's
# 2-category -> 4-category generator redesign. A shape mismatch already
# raises a hard error from sklearn/scaler; this catches the more dangerous
# same-shape-but-different-distribution case, which would otherwise silently
# load and produce miscalibrated scores with no error at all.
DATASET_VERSION = "v2-4category-stratified"


def _save_model(model: IsolationForest, scaler: StandardScaler) -> None:
    """
    Persist model + scaler + metadata as one atomic unit.

    Writes everything to .tmp paths first, then renames each into place only
    after ALL writes succeeded — os.replace is atomic on both POSIX and
    Windows, so a crash or kill partway through can never leave load_saved_model()
    looking at a half-written file, or a stale meta.json paired with a
    freshly (but not fully) written model/scaler.

    Tags both model and scaler with the SAME training_run_id before pickling
    them, and records it in meta.json too. load_saved_model() checks that all
    three agree — this is what actually detects a mismatched model/scaler
    pair (e.g. someone replaces scaler.pkl alone with one from a different
    training run): the run_id can only agree if both files came from this
    exact call.
    """
    run_id = uuid.uuid4().hex
    model._ts_run_id  = run_id
    scaler._ts_run_id = run_id

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    tmp_model, tmp_scaler, tmp_meta = MODEL_PATH + ".tmp", SCALER_PATH + ".tmp", META_PATH + ".tmp"

    with open(tmp_model, "wb") as f:
        pickle.dump(model, f)
    with open(tmp_scaler, "wb") as f:
        pickle.dump(scaler, f)
    meta = {
        "feature_cols":          FEATURE_COLS,
        "dataset_version":       DATASET_VERSION,
        "training_run_id":       run_id,
        # Self-reported shape from the fitted objects themselves, not just
        # len(FEATURE_COLS) — lets load_saved_model() catch a meta.json that
        # LIES about feature_cols while the actual pickled objects differ.
        "model_n_features_in":  int(model.n_features_in_),
        "scaler_n_features_in": int(scaler.n_features_in_),
        "model_contamination":  (float(model.contamination)
                                 if isinstance(model.contamination, (int, float)) else model.contamination),
        "model_n_estimators":   int(model.n_estimators),
    }
    with open(tmp_meta, "w") as f:
        json.dump(meta, f)

    os.replace(tmp_model, MODEL_PATH)
    os.replace(tmp_scaler, SCALER_PATH)
    os.replace(tmp_meta, META_PATH)
    logger.info("Model saved to %s (run_id=%s)", MODEL_PATH, run_id)


def load_saved_model() -> Tuple[Optional[IsolationForest], Optional[StandardScaler]]:
    """
    Load persisted model and scaler from disk — refuses, rather than
    silently loading, any of:
      - no artifact on disk at all
      - no model_meta.json sidecar (predates this safety check, or a crashed
        save left tmp files behind without ever reaching the meta rename)
      - malformed meta.json (not valid JSON, or missing required keys)
      - feature_cols/dataset_version mismatch (same shape, different meaning)
      - a tampered/stale meta.json that disagrees with the ACTUAL loaded
        objects' own self-reported n_features_in_
      - a mismatched model/scaler pair: either file's embedded
        training_run_id disagrees with meta.json's, or with each other
        (e.g. scaler.pkl swapped in from a different training run)

    A same-shape (1, 8) incompatible artifact would NOT raise an error from
    sklearn — it would just score every real event against a distribution it
    was never trained on. These checks exist specifically to catch that
    silent case; a true shape mismatch already fails loudly on its own.
    """
    if not (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(META_PATH)):
        if os.path.exists(MODEL_PATH) or os.path.exists(SCALER_PATH):
            logger.warning(
                "Incomplete model artifact set at %s (missing one of model/"
                "scaler/meta) — refusing to load a partial artifact. "
                "Re-run POST /ml/train.", os.path.dirname(MODEL_PATH)
            )
        return None, None

    try:
        with open(META_PATH) as f:
            meta = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Malformed model_meta.json (%s) — refusing to load. Re-run POST /ml/train.", exc)
        return None, None

    required_keys = ("feature_cols", "dataset_version", "training_run_id",
                     "model_n_features_in", "scaler_n_features_in")
    if any(k not in meta or not meta[k] for k in required_keys):
        logger.warning(
            "model_meta.json is missing required field(s) (predates this "
            "safety check, or was only partially written) — refusing to "
            "load. Re-run POST /ml/train."
        )
        return None, None

    if meta["feature_cols"] != FEATURE_COLS or meta["dataset_version"] != DATASET_VERSION:
        logger.warning(
            "Model artifact was trained with feature_cols=%s dataset_version=%s, "
            "but this code expects feature_cols=%s dataset_version=%s — "
            "refusing to silently reuse an incompatible artifact. Re-run POST /ml/train.",
            meta["feature_cols"], meta["dataset_version"], FEATURE_COLS, DATASET_VERSION,
        )
        return None, None

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)

    model_run_id  = getattr(model, "_ts_run_id", None)
    scaler_run_id = getattr(scaler, "_ts_run_id", None)
    if not model_run_id or model_run_id != scaler_run_id or model_run_id != meta["training_run_id"]:
        logger.warning(
            "Model/scaler run_id mismatch (model=%s scaler=%s meta=%s) — "
            "these artifacts were not saved together as a pair, or one was "
            "replaced independently. Refusing to load. Re-run POST /ml/train.",
            model_run_id, scaler_run_id, meta["training_run_id"],
        )
        return None, None

    actual_model_feat  = getattr(model, "n_features_in_", None)
    actual_scaler_feat = getattr(scaler, "n_features_in_", None)
    if (actual_model_feat != meta["model_n_features_in"]
            or actual_scaler_feat != meta["scaler_n_features_in"]
            or actual_model_feat != len(FEATURE_COLS)
            or actual_scaler_feat != len(FEATURE_COLS)):
        logger.warning(
            "Loaded model/scaler's own n_features_in_ (model=%s scaler=%s) "
            "disagrees with model_meta.json (model=%s scaler=%s) or with "
            "the current %d-feature schema — meta.json may be stale or "
            "tampered. Refusing to load. Re-run POST /ml/train.",
            actual_model_feat, actual_scaler_feat,
            meta["model_n_features_in"], meta["scaler_n_features_in"], len(FEATURE_COLS),
        )
        return None, None

    logger.info("Loaded saved model from %s (run_id=%s)", MODEL_PATH, meta["training_run_id"])
    return model, scaler


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

def evaluate(csv_path: Optional[str] = None, split: Optional[str] = "test",
            scenario: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluate the PERSISTED model (never retrains here) on a dataset split.

    split="test" (default) scores only the held-out test slice that train()
    never fits on — fixes a prior bug where evaluate(csv_path=None) silently
    scored the exact same fixed-seed data the model was trained on, making
    every reported metric meaningless as a held-out measurement. Pass
    split=None to intentionally score every row (e.g. to inspect training-fit
    behavior) — the result is labeled accordingly so it can't be mistaken for
    a held-out number.

    When no model is on disk, this does NOT silently train one — it raises,
    since evaluating a model that doesn't exist is not a valid operation.

    Returns a dict including a confusion matrix, precision, recall, F1,
    false-positive rate and false-negative rate when labels exist. All
    results are from generated synthetic data unless csv_path points at real
    captured data — `dataset_source` and `is_synthetic` say which.
    """
    model, scaler = load_saved_model()
    if model is None:
        raise RuntimeError(
            "No trained model on disk — POST /ml/train first. "
            "evaluate() does not implicitly train, to keep training and "
            "evaluation as distinct, explicit operations."
        )

    df = load_dataset(csv_path, split=split)
    if scenario is not None:
        if "scenario" not in df.columns:
            raise ValueError("dataset has no 'scenario' column to filter by")
        df = df[df["scenario"] == scenario].reset_index(drop=True)
    if len(df) == 0:
        raise ValueError(f"split={split!r} scenario={scenario!r} produced 0 rows — nothing to evaluate.")
    X  = df[FEATURE_COLS].fillna(0).values
    X_scaled = scaler.transform(X)

    predictions    = model.predict(X_scaled)
    decision_scores = model.decision_function(X_scaled)

    anomaly_count = int((predictions == -1).sum())
    total         = len(predictions)
    anomaly_ratio = round(anomaly_count / total * 100, 2)

    logger.info("Evaluation (split=%s): %d/%d anomalies (%.1f%%)",
                split, anomaly_count, total, anomaly_ratio)

    result = {
        "split":          split,
        "scenario":       scenario,
        "dataset_source": csv_path or "synthetic (fixed seed)",
        "is_synthetic":   csv_path is None,
        "total_samples":  total,
        "anomaly_count":  anomaly_count,
        "normal_count":   total - anomaly_count,
        "anomaly_ratio":  anomaly_ratio,
    }

    # If labels exist, compute classification metrics
    if "label" in df.columns:
        y_true = df["label"].values
        y_pred = (predictions == -1).astype(int)
        # labels=[0,1] forced explicitly: a scenario-filtered subset (e.g.
        # attack_volume_only) can contain only one true class, which would
        # otherwise raise "number of classes does not match target_names".
        report = classification_report(y_true, y_pred, labels=[0, 1],
                                       target_names=["normal", "attack"],
                                       output_dict=True, zero_division=0)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        fnr = fn / (fn + tp) if (fn + tp) else 0.0

        result["classification_report"] = report
        result["confusion_matrix"] = {
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp),
        }
        result["precision"] = round(report.get("attack", {}).get("precision", 0), 4)
        result["recall"]    = round(report.get("attack", {}).get("recall", 0), 4)
        result["f1"]        = round(report.get("attack", {}).get("f1-score", 0), 4)
        result["false_positive_rate"] = round(fpr, 4)
        result["false_negative_rate"] = round(fnr, 4)
        result["attack_recall"] = result["recall"]  # kept for API compatibility

    return result


def compare_contamination(candidates=(0.05, 0.10, 0.15, 0.20, 0.30),
                          csv_path: Optional[str] = None) -> list:
    """
    Fit a fresh model at each candidate contamination on the TRAIN split and
    score it on the VALIDATION split (never test) — for documenting the
    precision/recall trade-off of the contamination hyperparameter.

    IMPORTANT: this compares the RAW IsolationForest decision only
    (model.predict() at each contamination's own internal threshold). It
    does NOT run the hybrid risk_engine (log-signal floors, clean-baseline
    guard, ML_ANOMALY_THRESHOLD) — those are a completely different decision
    mechanism layered on top in production, evaluated separately in
    test_hybrid_pipeline.py. Do not read this table as "the system's"
    false-positive rate; it is specifically the unsupervised model's.

    This is a reporting/calibration helper: it does not change the persisted
    model or the default used by train(); a human picks the value afterward
    based on the operational objective (favor recall vs. favor fewer false
    positives). Never call this against the test split — doing so would
    turn the "held-out" test set into a tuning set.

    Returns one dict per candidate with precision, recall, f1,
    false_positive_rate, false_negative_rate and the raw confusion matrix —
    labels are the synthetic generator's own ground truth (label column),
    split="val" (never test).
    """
    out = []
    for c in candidates:
        model, scaler = train(csv_path=csv_path, contamination=c, save=False)
        df = load_dataset(csv_path, split="val")
        X = df[FEATURE_COLS].fillna(0).values
        X_scaled = scaler.transform(X)
        y_pred = (model.predict(X_scaled) == -1).astype(int)
        row = {"contamination": c, "split": "val", "mechanism": "raw_isolation_forest",
              "n": len(df)}
        if "label" in df.columns:
            y_true = df["label"].values
            report = classification_report(y_true, y_pred, labels=[0, 1],
                                           target_names=["normal", "attack"],
                                           output_dict=True, zero_division=0)
            cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel()
            row["precision"] = round(report["attack"]["precision"], 4)
            row["recall"]    = round(report["attack"]["recall"], 4)
            row["f1"]        = round(report["attack"]["f1-score"], 4)
            row["false_positive_rate"] = round(fp / (fp + tn) if (fp + tn) else 0.0, 4)
            row["false_negative_rate"] = round(fn / (fn + tp) if (fn + tp) else 0.0, 4)
            row["confusion_matrix"] = {
                "true_negative": int(tn), "false_positive": int(fp),
                "false_negative": int(fn), "true_positive": int(tp),
            }
        out.append(row)
    return out

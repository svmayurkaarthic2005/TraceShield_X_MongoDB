"""
Feature/parser integrity + model-artifact compatibility checks (no server
required):
  - training/inference feature order and transformation consistency
  - spike_score clipping is applied consistently
  - model_meta.json: missing, malformed, stale, incompatible, and
    mismatched-model/scaler-pair artifacts are all refused, never silently
    loaded
  - save+load round-trips correctly for a genuinely valid artifact

Run from the repo root with the ingestion venv's Python:
    python test_model_integrity.py
"""
import json
import os
import pickle
import shutil

from ingestion.services import ml_training as mt
from ingestion.services import ml_model


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}: {name}")
    assert cond, name


MODEL_PATH = mt.MODEL_PATH
SCALER_PATH = mt.SCALER_PATH
META_PATH = mt.META_PATH


def write_pkl(path, obj):
    with open(path, "wb") as f:
        pickle.dump(obj, f)


def write_meta(d):
    with open(META_PATH, "w") as f:
        json.dump(d, f)


# ── 1. Feature order: dict -> array matches FEATURE_COLS exactly ──────────────

sample = {
    "request_count": 11, "requests_per_second": 22, "spike_score": 33,
    "trend_score": 44, "failed_logins": 55, "sudo_attempts": 66,
    "suspicious_commands": 77, "sensitive_file_access": 88,
}
vec = mt.features_from_dict(sample)[0]
expected = [sample[c] for c in mt.FEATURE_COLS]
check("features_from_dict produces values in exact FEATURE_COLS order",
      list(vec) == expected)
vec2 = mt.build_feature_vector(*expected)[0]
check("build_feature_vector's positional order matches FEATURE_COLS",
      list(vec2) == expected)

# ── 2. spike_score clipping is applied in get_ml_score (ml_model.py) ──────────

ml_model.load_model()
check("model is loaded for this check", ml_model.is_loaded())

from datetime import datetime
score_at_ratio_1 = ml_model.get_ml_score(request_count=100, timestamp=datetime.now(), deviation=1.0)
score_at_ratio_50 = ml_model.get_ml_score(request_count=100, timestamp=datetime.now(), deviation=50.0)
check("an extreme deviation (50x) produces the SAME ml_score as deviation=1.0 "
      "(both clip to spike_score=100 — proves the clip is active)",
      abs(score_at_ratio_1 - score_at_ratio_50) < 0.01)

# ── 3. Model/scaler/meta artifact compatibility ────────────────────────────────

backup_dir = "ingestion/models/_integrity_test_backup"
os.makedirs(backup_dir, exist_ok=True)
for fname in ("isolation_forest.pkl", "scaler.pkl", "model_meta.json"):
    src = os.path.join("ingestion/models", fname)
    if os.path.exists(src):
        shutil.copy(src, os.path.join(backup_dir, fname))

try:
    # Establish one known-good, fully consistent artifact via the real save path.
    model_a, scaler_a = mt.train(csv_path=None, contamination=0.20, save=True)
    with open(META_PATH) as f:
        good_meta = json.load(f)

    # A. No files at all
    for p in (MODEL_PATH, SCALER_PATH, META_PATH):
        if os.path.exists(p):
            os.remove(p)
    check("no artifact at all -> refused", mt.load_saved_model() == (None, None))

    # B. Only model.pkl present (partial artifact set, e.g. crash mid-save pre-atomic-write)
    write_pkl(MODEL_PATH, model_a)
    check("model.pkl present but scaler.pkl/meta missing -> refused",
          mt.load_saved_model() == (None, None))

    # C. model.pkl + scaler.pkl present, meta.json missing
    write_pkl(SCALER_PATH, scaler_a)
    check("model+scaler present but meta.json missing -> refused",
          mt.load_saved_model() == (None, None))

    # D. Malformed meta.json (not valid JSON)
    with open(META_PATH, "w") as f:
        f.write("{not valid json")
    check("malformed (non-JSON) meta.json -> refused",
          mt.load_saved_model() == (None, None))

    # E. Meta missing required keys (old pre-upgrade schema)
    write_meta({"feature_cols": mt.FEATURE_COLS, "dataset_version": mt.DATASET_VERSION})
    check("meta missing training_run_id/n_features_in keys (old schema) -> refused",
          mt.load_saved_model() == (None, None))

    # F. Stale dataset_version (everything else correct)
    stale = dict(good_meta); stale["dataset_version"] = "stale-v1"
    write_meta(stale)
    check("stale dataset_version -> refused", mt.load_saved_model() == (None, None))

    # G. Mismatched feature_cols
    bad_cols = dict(good_meta); bad_cols["feature_cols"] = mt.FEATURE_COLS[:-1]
    write_meta(bad_cols)
    check("mismatched feature_cols -> refused", mt.load_saved_model() == (None, None))

    # H. Tampered meta claiming a different n_features_in_ than the real
    #    pickled objects actually have (run_id still matches — this is the
    #    "metadata lies about the artifact it describes" case).
    tampered = dict(good_meta); tampered["model_n_features_in"] = 5
    write_meta(tampered)
    check("meta's n_features_in_ disagrees with the real loaded model -> refused",
          mt.load_saved_model() == (None, None))

    # I. Mismatched model/scaler PAIR: swap in a scaler from a different,
    #    independently-trained run (different run_id) while meta/model stay "good".
    _, scaler_b = mt.train(csv_path=None, contamination=0.20, save=False, master_seed=101)
    write_pkl(MODEL_PATH, model_a)
    write_pkl(SCALER_PATH, scaler_b)   # mismatched: scaler_b was never saved with model_a
    write_meta(good_meta)              # claims model_a's original run_id
    check("scaler swapped from a different training run (run_id mismatch) -> refused",
          mt.load_saved_model() == (None, None))

    # J. Fully valid, consistent artifact (sanity check: the guard isn't just always-refuse)
    model_fresh, scaler_fresh = mt.train(csv_path=None, contamination=0.20, save=True)
    loaded_model, loaded_scaler = mt.load_saved_model()
    check("a genuinely valid, consistently-saved artifact loads normally",
          loaded_model is not None and loaded_scaler is not None)
    check("loaded model/scaler share the same training_run_id",
          getattr(loaded_model, "_ts_run_id", None) == getattr(loaded_scaler, "_ts_run_id", None)
          and getattr(loaded_model, "_ts_run_id", None) is not None)

    # K. Saving twice produces two DIFFERENT run_ids (each save is its own pair)
    with open(META_PATH) as f:
        meta1 = json.load(f)
    mt.train(csv_path=None, contamination=0.20, save=True)
    with open(META_PATH) as f:
        meta2 = json.load(f)
    check("re-saving the model produces a fresh training_run_id each time",
          meta1["training_run_id"] != meta2["training_run_id"])

finally:
    # Restore whatever was really there before this test ran, and clean up
    # any leftover .tmp files from the atomic-write path.
    for fname in ("isolation_forest.pkl", "scaler.pkl", "model_meta.json"):
        dest = os.path.join("ingestion/models", fname)
        backup = os.path.join(backup_dir, fname)
        if os.path.exists(backup):
            shutil.copy(backup, dest)
        elif os.path.exists(dest):
            os.remove(dest)
        tmp = dest + ".tmp"
        if os.path.exists(tmp):
            os.remove(tmp)
    shutil.rmtree(backup_dir, ignore_errors=True)
    ml_model.reload_model()

print("\nAll checks passed.")

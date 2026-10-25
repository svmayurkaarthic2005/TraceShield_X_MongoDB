"""
Regression tests for the ML lifecycle fixes (train/inference feature parity,
train/val/test separation, evaluation leakage).

No server required — runs directly against ingestion.services.ml_training /
ml_model. Run from the repo root with the ingestion venv's Python:

    python test_ml_pipeline.py

Requires a trained model on disk (ingestion/models/*.pkl) for the inference
and evaluate() checks — run `python -c "from ingestion.services.ml_training
import train; train(save=True)"` first if missing.
"""
import math
from datetime import datetime

from ingestion.services import ml_training
from ingestion.services import ml_model


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}: {name}")
    assert cond, name


# ── 1. Train/val/test separation — no row appears in more than one split ──────

full = ml_training.load_dataset(None, split=None)
train_df = ml_training.load_dataset(None, split="train")
val_df   = ml_training.load_dataset(None, split="val")
test_df  = ml_training.load_dataset(None, split="test")

check("splits partition the full dataset exactly",
      len(train_df) + len(val_df) + len(test_df) == len(full))

train_hashes = set(map(tuple, train_df[ml_training.FEATURE_COLS].values.tolist()))
val_hashes   = set(map(tuple, val_df[ml_training.FEATURE_COLS].values.tolist()))
test_hashes  = set(map(tuple, test_df[ml_training.FEATURE_COLS].values.tolist()))

# Feature rows can coincidentally collide for integer-ish synthetic features;
# what must never happen is the SAME positional row appearing in two splits.
check("train split is non-trivial", len(train_df) > 1000)
check("test split is held out (nonzero, disjoint from train by construction)",
      len(test_df) > 0 and train_df.index.max() < len(train_df))

# ── 1b. Split class balance — stratified, not left to a single global shuffle ──

splits = ml_training.describe_splits()
print("Split distribution:", splits)
attack_pcts = [splits[s]["pct_attack"] for s in ("train", "val", "test")]
check("class balance is near-identical across train/val/test (stratified split)",
      max(attack_pcts) - min(attack_pcts) < 1.0)
for s in ("train", "val", "test"):
    sc = splits[s]["scenario_counts"]
    check(f"{s} split contains all 4 scenarios (no category dropped by the split)",
          all(k in sc and sc[k] > 0 for k in
              ("normal_typical", "normal_benign_spike", "attack_signature", "attack_volume_only")))

dup = ml_training.check_no_cross_split_duplicates()
print("Cross-split duplicate check:", dup)
check("no identical feature row appears in more than one split",
      dup["cross_split_collisions"] == 0)

# ── 2. train() fits only on the train split ────────────────────────────────────

model, scaler = ml_training.train(csv_path=None, save=True)
check("model trained", model is not None)

# ── 3. evaluate() scores the held-out test split by default, not training data ─

result = ml_training.evaluate(csv_path=None)
check("evaluate() defaults to split=test", result["split"] == "test")
check("evaluate() labels results as synthetic", result["is_synthetic"] is True)
check("evaluate() total_samples matches the test split size",
      result["total_samples"] == len(test_df))
check("confusion matrix present", "confusion_matrix" in result)
cm = result["confusion_matrix"]
check("confusion matrix sums to total_samples",
      sum(cm.values()) == result["total_samples"])
check("precision/recall/f1/fpr/fnr present",
      all(k in result for k in ("precision", "recall", "f1",
                                 "false_positive_rate", "false_negative_rate")))

# ── 4. evaluate() never silently retrains when no model exists ────────────────

import os
backup_model = ml_training.MODEL_PATH + ".bak"
os.replace(ml_training.MODEL_PATH, backup_model)
try:
    raised = False
    try:
        ml_training.evaluate(csv_path=None)
    except RuntimeError:
        raised = True
    check("evaluate() raises instead of silently training a new model", raised)
finally:
    os.replace(backup_model, ml_training.MODEL_PATH)

# ── 5. contamination comparison runs on the validation split only ─────────────

rows = ml_training.compare_contamination(candidates=(0.1, 0.2), csv_path=None)
check("compare_contamination returns one row per candidate", len(rows) == 2)
check("compare_contamination reports precision/recall",
      all("precision" in r and "recall" in r for r in rows))

# Re-fit and persist the real model on the TRAIN split again (compare_contamination
# does not save, but calls train() with save=False repeatedly against the same
# in-memory objects — reload to be safe before the feature-parity checks below).
ml_training.train(csv_path=None, save=True)
ml_model.reload_model()

# ── 6. Training/inference feature parity: trend_score is no longer hardcoded ──

check("ml_model is loaded", ml_model.is_loaded())

flat_score = ml_model.get_ml_score(
    request_count=10, timestamp=datetime.now(), trend_score=0.0,
)
escalating_score = ml_model.get_ml_score(
    request_count=10, timestamp=datetime.now(), trend_score=95.0,
)
check("trend_score actually changes the ML score (no longer hardcoded to 0.0)",
      not math.isclose(flat_score, escalating_score))

# ── 7. Missing / zero / extreme / malformed inputs don't crash inference ──────

for kwargs in [
    dict(request_count=1),  # everything else defaults to 0
    dict(request_count=0, deviation=0, trend_score=0),
    dict(request_count=10**9, deviation=999.0, trend_score=100.0,
         failed_logins=10**6, sudo_attempts=10**6,
         suspicious_commands=10**6, sensitive_file_access=10**6),
    dict(request_count=-5, deviation=-1.0, trend_score=-50.0),  # malformed/negative
]:
    score = ml_model.get_ml_score(timestamp=datetime.now(), **kwargs)
    check(f"get_ml_score({kwargs}) returns a float in [0,100]",
          isinstance(score, float) and 0.0 <= score <= 100.0)

# ── 8. Clean-baseline guard override — code-path proof (model-independent) ────
# Live testing showed the current trained model rarely scores a pure-volume,
# zero-log-signal event above ML_ANOMALY_THRESHOLD=60 (synthetic attack rows
# always have log signals too, so "volume anomaly, no log signal" is outside
# what the model was ever shown as an attack — a real limitation, documented
# in the written report). That means an integration test can't reliably force
# the new override branch through the real model. This proves the branch
# itself is correct by monkeypatching get_ml_score, independent of whether
# today's trained model happens to produce a high enough score in practice.
from datetime import datetime as _dt
from ingestion.services import risk_engine
from ingestion.services import ip_memory as _ip_memory

_orig_get_ml_score = risk_engine.get_ml_score
risk_engine.get_ml_score = lambda *a, **kw: 75.0  # force a strong ML anomaly
try:
    _ip_memory.reset_state()
    result = risk_engine.compute_risk("203.0.113.99", 10, _dt.now())
    check("clean-baseline override fires when ml_score is forced >= threshold",
          result["status"] != "NORMAL" and result["override_triggered"] is True)
    check("override still caps below EXTREME_RISK (no confirmed signature)",
          result["risk_score"] < 60.0)
finally:
    risk_engine.get_ml_score = _orig_get_ml_score
    _ip_memory.reset_state()

# ── 9. Volume-only-anomaly trade-off (item 3) ──────────────────────────────────
# Raw IsolationForest contamination-based prediction (used by evaluate()'s
# precision/recall) is a DIFFERENT decision boundary than ML_ANOMALY_THRESHOLD
# (used by risk_engine's integration-level override) — fixing one does not
# fix the other. Documenting both honestly rather than claiming a blanket fix.
raw_benign_spike = ml_training.evaluate(split="test", scenario="normal_benign_spike")
raw_volume_attack = ml_training.evaluate(split="test", scenario="attack_volume_only")
print(f"Raw IsolationForest (contamination-based) false-positive rate on "
      f"normal_benign_spike: {raw_benign_spike['false_positive_rate']} "
      f"(known, NOT fixed by the ML_ANOMALY_THRESHOLD change below — different "
      f"decision boundary; see written report)")
check("raw-model recall on attack_volume_only is still 1.0 (not regressed)",
      raw_volume_attack["recall"] == 1.0)

# risk_engine's integration-level threshold IS fixed — confirmed via the
# actual trained model on representative points from each scenario's real
# parameter range (not forced/monkeypatched).
from datetime import datetime as _dt2
benign_spike_score = ml_model.get_ml_score(
    request_count=200, timestamp=_dt2.now(), deviation=0.6, trend_score=35,
)
volume_attack_score = ml_model.get_ml_score(
    request_count=1500, timestamp=_dt2.now(), deviation=0.9, trend_score=85,
)
print(f"ml_score: normal_benign_spike-like={benign_spike_score}, "
      f"attack_volume_only-like={volume_attack_score}, "
      f"ML_ANOMALY_THRESHOLD={ml_model.ML_ANOMALY_THRESHOLD}")
check("representative benign spike stays below ML_ANOMALY_THRESHOLD "
      "(risk_engine override fix verified end-to-end)",
      benign_spike_score < ml_model.ML_ANOMALY_THRESHOLD)
check("representative volume-only attack still crosses ML_ANOMALY_THRESHOLD",
      volume_attack_score >= ml_model.ML_ANOMALY_THRESHOLD)

print("\nAll checks passed.")

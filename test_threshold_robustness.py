"""
Seed-robustness check for ML_ANOMALY_THRESHOLD=73 (ingestion/services/ml_model.py).

The threshold was selected ONCE from the validation split of the production
dataset (master_seed=42). This script asks: does that same fixed threshold
still hold up against INDEPENDENTLY generated datasets (different seeds)? It
never re-picks the threshold — it only measures how a value chosen on one
draw generalizes to others, which is the actual question "is the margin
robust or a seed-specific artifact" is asking.

For each seed: train in-memory only (never saved — see train()'s own guard
against save=True with a non-production seed), score the VALIDATION split
for that seed (never that seed's test split — test is scored once at the end
purely as a confirmatory check, consistent with "never retune on test").

Run from the repo root with the ingestion venv's Python:
    python test_threshold_robustness.py

Requires no running server; trains throwaway models in-memory.
"""
import numpy as np

from ingestion.services import ml_training as mt
from ingestion.services.ml_model import ML_ANOMALY_THRESHOLD

SEEDS = [42, 101, 202, 303, 404]  # 42 = production dataset; rest = independent draws


def ml_scores_for(model, scaler, df):
    X = df[mt.FEATURE_COLS].fillna(0).values
    Xs = scaler.transform(X)
    dec = model.decision_function(Xs)
    return np.clip((0.5 - dec) / 1.0 * 100.0, 0.0, 100.0)


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}: {name}")
    assert cond, name


print(f"Fixed threshold under test: ML_ANOMALY_THRESHOLD = {ML_ANOMALY_THRESHOLD}\n")

val_results = []
test_results = []
raw_if_results = []

for seed in SEEDS:
    model, scaler = mt.train(csv_path=None, contamination=0.20, save=False, master_seed=seed)

    val_df = mt.load_dataset(None, split="val", master_seed=seed)
    benign_val = val_df[val_df["scenario"] == "normal_benign_spike"]
    attack_val = val_df[val_df["scenario"] == "attack_volume_only"]
    benign_scores = ml_scores_for(model, scaler, benign_val)
    attack_scores = ml_scores_for(model, scaler, attack_val)

    # ── Mechanism 1: HYBRID risk_engine override (ml_score vs ML_ANOMALY_THRESHOLD) ──
    # This is what production actually uses (risk_engine.py's clean-baseline
    # ML override). ml_score here is the same normalized decision_function
    # output the hybrid engine computes — not the raw contamination decision.
    fpr = float((benign_scores >= ML_ANOMALY_THRESHOLD).mean()) if len(benign_scores) else float("nan")
    fnr = float((attack_scores < ML_ANOMALY_THRESHOLD).mean()) if len(attack_scores) else float("nan")
    gap = float(attack_scores.min() - benign_scores.max()) if len(benign_scores) and len(attack_scores) else float("nan")

    val_results.append(dict(seed=seed, n_benign=len(benign_scores), n_attack=len(attack_scores),
                            benign_min=round(benign_scores.min(), 2), benign_max=round(benign_scores.max(), 2),
                            attack_min=round(attack_scores.min(), 2), attack_max=round(attack_scores.max(), 2),
                            gap=round(gap, 2), fpr_at_73=round(fpr, 4), fnr_at_73=round(fnr, 4)))

    # ── Mechanism 2: RAW IsolationForest decision (model.predict(), contamination=0.20) ──
    # A completely different decision boundary — the model's own internal
    # threshold, not ML_ANOMALY_THRESHOLD. Never conflate the two.
    benign_pred_anomaly = (model.predict(scaler.transform(
        benign_val[mt.FEATURE_COLS].fillna(0).values)) == -1)
    attack_pred_anomaly = (model.predict(scaler.transform(
        attack_val[mt.FEATURE_COLS].fillna(0).values)) == -1)
    raw_if_results.append(dict(
        seed=seed,
        fpr=round(float(benign_pred_anomaly.mean()), 4) if len(benign_pred_anomaly) else float("nan"),
        fnr=round(float((~attack_pred_anomaly).mean()), 4) if len(attack_pred_anomaly) else float("nan"),
    ))

    # Confirmatory-only pass on this seed's TEST split (never used to pick anything)
    test_df = mt.load_dataset(None, split="test", master_seed=seed)
    benign_test = test_df[test_df["scenario"] == "normal_benign_spike"]
    attack_test = test_df[test_df["scenario"] == "attack_volume_only"]
    bt = ml_scores_for(model, scaler, benign_test)
    at = ml_scores_for(model, scaler, attack_test)
    test_results.append(dict(
        seed=seed,
        fpr_at_73=round(float((bt >= ML_ANOMALY_THRESHOLD).mean()), 4) if len(bt) else float("nan"),
        fnr_at_73=round(float((at < ML_ANOMALY_THRESHOLD).mean()), 4) if len(at) else float("nan"),
    ))

print("=== MECHANISM: hybrid risk_engine override (ml_score vs ML_ANOMALY_THRESHOLD) ===")
print("Validation split, per seed (threshold selection data):")
for r in val_results:
    print(f"  seed={r['seed']:4d}  n_benign={r['n_benign']:3d} n_attack={r['n_attack']:3d}  "
          f"benign=[{r['benign_min']},{r['benign_max']}]  attack=[{r['attack_min']},{r['attack_max']}]  "
          f"gap={r['gap']:+.2f}  FPR@73={r['fpr_at_73']}  FNR@73={r['fnr_at_73']}")

print("\nTest split, per seed (confirmatory only, never tuned on):")
for r in test_results:
    print(f"  seed={r['seed']:4d}  FPR@73={r['fpr_at_73']}  FNR@73={r['fnr_at_73']}")

print("\n=== MECHANISM: raw IsolationForest decision (model.predict(), contamination=0.20) ===")
print("Validation split, per seed — a DIFFERENT decision boundary than ML_ANOMALY_THRESHOLD above:")
for r in raw_if_results:
    print(f"  seed={r['seed']:4d}  FPR(benign_spike flagged anomalous)={r['fpr']}  "
          f"FNR(volume_attack missed)={r['fnr']}")

# ── Verdict on robustness, not a pass/fail on "the model is good" ──────────────
gaps = [r["gap"] for r in val_results]
n_positive_gap = sum(1 for g in gaps if g > 0)
print(f"\nSeeds with a positive (non-overlapping) gap at threshold=73: "
      f"{n_positive_gap}/{len(SEEDS)}")
print(f"Gap range across seeds: min={min(gaps):.2f}, max={max(gaps):.2f}")

if n_positive_gap == len(SEEDS):
    print("VERDICT: the separation holds across all tested independent seeds — "
          "consistent with the generator's deliberate intensity gap between "
          "normal_benign_spike and attack_volume_only, not a fluke of seed 42. "
          "Still NOT evidence this holds for real traffic (see written report).")
else:
    print("VERDICT: the separation does NOT hold for every seed — threshold=73 "
          "is more fragile than the single-seed (42) analysis suggested. "
          "Reported honestly, no threshold change made based on this script alone.")

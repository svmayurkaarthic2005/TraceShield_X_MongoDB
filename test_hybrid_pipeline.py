"""
Full hybrid-pipeline validation across 7 traffic categories, through the
REAL supported ingestion API (/dataset/logs for log-line scenarios, /ingest
for pure-volume scenarios) — not unit-level shortcuts.

For every case we supply our OWN ground truth (is this traffic malicious?
what attack_type, if any, would a human analyst assign?) since these are
constructed test cases, not a real labeled security dataset. This is
SYNTHETIC, hand-constructed evidence — it demonstrates the pipeline's
behavior on cases we designed, not real-world detection accuracy.

A non-NORMAL status/attack_type here means "the pipeline classified this
attempt as category X" — never "this attack succeeded" or "the command's
effect was confirmed." Suspicious-command and failed-login cases test
ATTEMPT classification only.

Reports two separate confusion matrices, per the explicit instruction to
separate these two failure modes:
  1. Binary severity confusion matrix: malicious (non-NORMAL) vs benign (NORMAL)
  2. Attack-type confusion: among correctly-flagged-malicious cases, did the
     attack_type label match what a human would assign?

Run with the ingestion service already running:
    uvicorn ingestion.main:app --port 8001   (from repo root)
    python test_hybrid_pipeline.py
"""
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("INGEST_BASE", "http://127.0.0.1:8011")


def post(path, data, timeout=30):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def dataset_logs_case(lines):
    """/dataset/logs resets all state per call — cases are naturally isolated."""
    status, body = post("/dataset/logs", {"log_lines": lines})
    assert status == 200, f"request failed: {status} {body}"
    return body["results"][0]


def ingest_case(ip, baseline, spike):
    """/ingest-based volume cases: unique IP + explicit reset avoids state bleed."""
    post("/state/reset", {})
    for _ in range(5):
        post("/ingest", {"ip": ip, "device": "d1", "request_count": baseline})
    status, body = post("/ingest", {"ip": ip, "device": "d1", "request_count": spike})
    assert status == 200, f"request failed: {status} {body}"
    return body


# ── Ground-truth test cases ──────────────────────────────────────────────────
# Each: (category, expected_malicious, expected_attack_type_or_None, runner)

CASES = []

for i in range(5):
    CASES.append(("clean_traffic", False, None, lambda i=i: dataset_logs_case([
        f"Jan 1 00:00:0{i} web01 CRON[{300+i}]: (root) CMD (/usr/bin/logrotate)"
    ])))

for i in range(5):
    CASES.append(("legitimate_burst", False, None,
                 lambda i=i: ingest_case(f"203.0.113.{10+i}", 50, 90)))  # ratio 0.8

for i in range(5):
    CASES.append(("suspicious_commands", True, "REMOTE_EXECUTION", lambda i=i: dataset_logs_case([
        f"Jan 1 00:00:0{i} web01 sudo[{100+i}]: mallory : TTY=pts/0 ; PWD=/tmp ; "
        f"USER=root ; COMMAND=/bin/chmod 777 /tmp/payload{i}.sh"
    ])))

for i in range(5):
    CASES.append(("failed_logins", True, "BRUTE_FORCE", lambda i=i: dataset_logs_case([
        f"Jan 1 00:00:0{j} web01 sshd[{100+j}]: Failed password for root from 10.0.0.9 port 22 ssh2"
        for j in range(2 + i)
    ])))

for i in range(5):
    CASES.append(("path_traversal", True, "PATH_TRAVERSAL", lambda i=i: dataset_logs_case([
        f"Jan 1 00:00:0{i} web01 CRON[{200+i}]: (www-data) CMD (cat /etc/passwd)"
    ])))

for i in range(5):
    CASES.append(("privilege_escalation", True, "PRIVILEGE_ESCALATION", lambda i=i: dataset_logs_case([
        f"Jan 1 00:00:0{i} web01 sudo[{100+i}]: mallory : TTY=pts/0 ; PWD=/root ; "
        f"USER=root ; COMMAND=/bin/cat /etc/shadow"
    ])))

for i in range(5):
    # BEHAVIORAL_ANOMALY, not a specific attack label — fixed by this round's
    # anomaly_detector.py change: a non-NORMAL event with no log signature
    # now says so honestly instead of reporting NORMAL_ACTIVITY.
    CASES.append(("volume_only_attack", True, "BEHAVIORAL_ANOMALY",
                 lambda i=i: ingest_case(f"203.0.113.{20+i}", 10, 4000 + i * 200)))


# ── Run every case through the real API ────────────────────────────────────────

rows = []
for category, expected_malicious, expected_type, runner in CASES:
    result = runner()
    predicted_malicious = result["status"] != "NORMAL"
    predicted_type = result.get("attack_type", "NORMAL_ACTIVITY")
    predicted_status = result["status"]
    rows.append(dict(category=category, expected_malicious=expected_malicious,
                     expected_type=expected_type, predicted_malicious=predicted_malicious,
                     predicted_type=predicted_type, predicted_status=predicted_status,
                     ml_score=result.get("components", {}).get("ml_score")))

# ── 1. Binary severity confusion matrix ─────────────────────────────────────────

tp = sum(1 for r in rows if r["expected_malicious"] and r["predicted_malicious"])
fp = sum(1 for r in rows if not r["expected_malicious"] and r["predicted_malicious"])
fn = sum(1 for r in rows if r["expected_malicious"] and not r["predicted_malicious"])
tn = sum(1 for r in rows if not r["expected_malicious"] and not r["predicted_malicious"])

precision = tp / (tp + fp) if (tp + fp) else 0.0
recall    = tp / (tp + fn) if (tp + fn) else 0.0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
fpr       = fp / (fp + tn) if (fp + tn) else 0.0

print("=== Binary severity confusion matrix (malicious vs benign) ===")
print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
print(f"precision={precision:.4f} recall={recall:.4f} f1={f1:.4f} FPR={fpr:.4f}")

print("\nPer-category breakdown:")
by_cat = {}
for r in rows:
    by_cat.setdefault(r["category"], []).append(r)
for cat, items in by_cat.items():
    correct = sum(1 for r in items if r["expected_malicious"] == r["predicted_malicious"])
    print(f"  {cat:22s} {correct}/{len(items)} correctly classified malicious/benign  "
          f"(statuses: {[r['predicted_status'] for r in items]})")

# ── 2. Attack-type confusion — ONLY among correctly-flagged-malicious cases ────
# Separates "wrong severity" (above) from "wrong attack label" (here).

print("\n=== Attack-type agreement (only where severity was already correct: TP cases) ===")
type_matches = 0
type_total = 0
for r in rows:
    if r["expected_malicious"] and r["predicted_malicious"] and r["expected_type"] is not None:
        type_total += 1
        match = r["predicted_type"] == r["expected_type"]
        type_matches += match
        print(f"  {r['category']:22s} expected={r['expected_type']:20s} "
              f"predicted={r['predicted_type']:20s} {'OK' if match else 'MISMATCH'}")
if type_total:
    print(f"\nattack_type agreement: {type_matches}/{type_total} "
          f"({type_matches/type_total*100:.1f}%)")

print("\n=== Raw result table ===")
for r in rows:
    print(f"  {r['category']:22s} expected_mal={str(r['expected_malicious']):5s} "
          f"predicted_mal={str(r['predicted_malicious']):5s} status={r['predicted_status']:10s} "
          f"type={r['predicted_type']}")

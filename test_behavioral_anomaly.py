"""
Regression tests for the BEHAVIORAL_ANOMALY fix (anomaly_detector.py /
risk_engine.py): a HIGH_RISK (or otherwise non-NORMAL) event with no
recognizable log signature must no longer report attack_type=NORMAL_ACTIVITY.

Covers the 5 scenarios the fix was specifically required to handle:
  1. Clean traffic -> NORMAL severity.
  2. A benign traffic spike -> stays NORMAL.
  3. A suspicious volume-only event -> classified as anomalous (not NORMAL,
     not silently NORMAL_ACTIVITY either).
  4. A signature-based attack -> keeps its correct SPECIFIC classification
     (not downgraded to the generic BEHAVIORAL_ANOMALY bucket).
  5. Missing/incomplete telemetry -> handled gracefully, not a crash.

Run with the ingestion service already running:
    uvicorn ingestion.main:app --port 8001   (from repo root)
    python test_behavioral_anomaly.py
"""
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("INGEST_BASE", "http://127.0.0.1:8011")


def post(path, data, timeout=20):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}: {name}")
    assert cond, name


def burst(ip, baseline, spike):
    post("/state/reset", {})
    for _ in range(5):
        post("/ingest", {"ip": ip, "device": "d1", "request_count": baseline})
    status, body = post("/ingest", {"ip": ip, "device": "d1", "request_count": spike})
    check(f"burst request to {ip} succeeded", status == 200)
    return body


# ── 1. Clean traffic -> NORMAL severity ─────────────────────────────────────────

r = burst("203.0.113.201", 10, 12)   # flat, trivial volume — no spike at all
check("clean traffic stays NORMAL", r["status"] == "NORMAL")
check("clean traffic reports NORMAL_ACTIVITY (there is genuinely nothing to report)",
      r["attack_type"] == "NORMAL_ACTIVITY")

# ── 2. Benign traffic spike -> stays NORMAL ─────────────────────────────────────
# Moderate ratio, well below ML_ANOMALY_THRESHOLD with the spike_score clip fix.

r = burst("203.0.113.202", 50, 90)   # ratio 0.8 -> spike_score 80, ml_score ~68 (< 73)
check("benign moderate spike stays NORMAL", r["status"] == "NORMAL")
check("benign moderate spike reports NORMAL_ACTIVITY", r["attack_type"] == "NORMAL_ACTIVITY")

# ── 3. Suspicious volume-only event -> classified as anomalous ─────────────────
# No log signal at all; severity must be non-NORMAL AND the label must say so
# honestly instead of claiming "normal activity" for an elevated event.

r = burst("203.0.113.203", 10, 4000)
check("volume-only anomaly is NOT classified NORMAL severity", r["status"] != "NORMAL")
check("volume-only anomaly reports BEHAVIORAL_ANOMALY, not NORMAL_ACTIVITY "
      "(the exact bug this fix addresses)",
      r["attack_type"] == "BEHAVIORAL_ANOMALY")
check("BEHAVIORAL_ANOMALY is not a confirmed/specific attack label",
      r["attack_type"] not in ("PRIVILEGE_ESCALATION", "REMOTE_EXECUTION",
                               "PATH_TRAVERSAL", "BRUTE_FORCE"))

# ── 4. Signature-based attack -> correct SPECIFIC classification preserved ─────
# Must NOT be downgraded to the generic BEHAVIORAL_ANOMALY bucket just because
# that bucket now exists.

status, body = post("/dataset/logs", {"log_lines": [
    "Jan 1 00:00:01 web01 sudo[100]: mallory : TTY=pts/0 ; PWD=/root ; "
    "USER=root ; COMMAND=/bin/cat /etc/shadow"
]})
check("signature-based request succeeded", status == 200)
res = body["results"][0]
check("signature-based attack keeps its SPECIFIC label (PRIVILEGE_ESCALATION), "
      "not the generic BEHAVIORAL_ANOMALY fallback",
      res["attack_type"] == "PRIVILEGE_ESCALATION")
check("signature-based attack severity is EXTREME_RISK", res["status"] == "EXTREME_RISK")

# ── 5. Missing / incomplete telemetry -> handled gracefully, not a crash ──────

# 5a. Missing required field on /ingest -> FastAPI/Pydantic validation error,
#     not a 500 or an unhandled exception.
status, body = post("/ingest", {"device": "d1", "request_count": 10})  # no "ip"
check("missing required field on /ingest returns a client error (4xx), not a crash",
      400 <= status < 500)

# 5b. A log line with no parseable signal at all -> must not crash, and with
#     no signal and no spike, must resolve to NORMAL, not an error.
status, body = post("/dataset/logs", {"log_lines": ["completely unparseable garbage !!! 42"]})
check("an unparseable log line doesn't crash the pipeline", status == 200)
res = body["results"][0]
check("a line with zero extractable signal resolves to NORMAL",
      res["status"] == "NORMAL" and res["attack_type"] == "NORMAL_ACTIVITY")

# 5c. Empty log_lines -> explicit 400, not a crash (regression, already covered
#     in test_dataset_logs.py — repeated here since it's part of this same
#     "incomplete telemetry" requirement).
status, body = post("/dataset/logs", {"log_lines": []})
check("empty log_lines returns 400, not a crash", status == 400)

print("\nAll checks passed.")

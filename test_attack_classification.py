"""
Regression tests for:
  - attack-type classification fix (anomaly_detector.classify_attack_type)
  - clean-baseline guard balance fix (risk_engine.compute_risk)
  - concurrent /dataset/logs batch isolation

Run with the ingestion service already running:
    uvicorn ingestion.main:app --port 8001   (from repo root)
    python test_attack_classification.py
"""
import concurrent.futures
import json
import os
import urllib.error
import urllib.request

from ingestion.services.ml_model import ML_ANOMALY_THRESHOLD

BASE = os.environ.get("INGEST_BASE", "http://127.0.0.1:8001")


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


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}: {name}")
    assert cond, name


def result_for(log_lines):
    status, body = post("/dataset/logs", {"log_lines": log_lines})
    check(f"request succeeded ({log_lines[0][:40]}...)", status == 200)
    return body["results"][0]


# ── Section 5: attack-type classification ──────────────────────────────────────

# a) The /etc/shadow example — single sudo + sensitive file access must be
#    PRIVILEGE_ESCALATION, not PATH_TRAVERSAL, matching risk_engine's own
#    EXTREME/70 "shadow+sudo" override.
r = result_for([
    "Jan 1 00:00:01 web01 sudo[100]: mallory : TTY=pts/0 ; PWD=/home/mallory ; USER=root ; COMMAND=/bin/cat /etc/shadow"
])
check("sudo + /etc/shadow => PRIVILEGE_ESCALATION (was PATH_TRAVERSAL)",
      r["attack_type"] == "PRIVILEGE_ESCALATION")
check("severity is EXTREME_RISK", r["status"] == "EXTREME_RISK")

# b) Sensitive-file access with NO sudo — genuine path traversal signal, no
#    privilege-escalation evidence (no elevated-rights indicator present).
r = result_for([
    "Jan 1 00:00:02 web01 CRON[200]: (www-data) CMD (cat /etc/passwd)"
])
check("sensitive file access without sudo => PATH_TRAVERSAL",
      r["attack_type"] == "PATH_TRAVERSAL")

# c) Failed SSH authentication (brute force), no sudo/sensitive signal.
r = result_for([f"Jan 1 00:00:0{i} web01 sshd[10{i}]: Failed password for root from 10.0.0.9 port 22 ssh2"
                for i in range(3)])
check("repeated failed SSH logins => BRUTE_FORCE",
      r["attack_type"] == "BRUTE_FORCE")

# d) Suspicious sudo command (world-writable chmod), no sensitive file.
#    (Deliberately not an `nc <ip> <port>`-style line: linux_log_parser's IP
#    extraction grabs ANY ip-shaped token in the line, not just one following
#    "from" — such a line gets attributed to that IP as its own actor instead
#    of the host, which would silently split this single-actor scenario into
#    two. Flagged in the written report as a separate, out-of-scope finding;
#    not fixed here since it's an IP-attribution issue, not a classification
#    or scoring one, and changing it risks reshaping unrelated aggregation
#    behavior.)
r = result_for([
    "Jan 1 00:00:01 web01 sudo[100]: mallory : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chmod 777 /tmp/payload.sh"
])
check("suspicious command => REMOTE_EXECUTION", r["attack_type"] == "REMOTE_EXECUTION")

# e) Mixed/overlapping signal: repeated sudo (>=2) plus a suspicious command —
#    must win out over the single-signal REMOTE_EXECUTION label from case (d);
#    a more specific, higher-severity category shouldn't be hidden by a
#    broader fallback.
r = result_for([
    "Jan 1 00:00:01 web01 sudo[100]: mallory : TTY=pts/0 ; PWD=/home/mallory ; USER=root ; COMMAND=/usr/bin/whoami",
    "Jan 1 00:00:02 web01 sudo[101]: mallory : TTY=pts/0 ; PWD=/home/mallory ; USER=root ; COMMAND=/usr/bin/id",
    "Jan 1 00:00:03 web01 sudo[102]: mallory : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chmod 777 /tmp/payload.sh",
])
check("repeated sudo (>=2) + suspicious command => PRIVILEGE_ESCALATION (overrides REMOTE_EXECUTION)",
      r["attack_type"] == "PRIVILEGE_ESCALATION")

# f) Pure benign admin sudo — must stay NORMAL_ACTIVITY, not be relabeled by
#    the broadened privilege-escalation rule above.
r = result_for([
    "Jan 1 00:00:01 web01 sudo[100]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
])
check("benign sudo-only activity stays NORMAL_ACTIVITY", r["attack_type"] == "NORMAL_ACTIVITY")
check("benign sudo-only activity stays NORMAL severity", r["status"] == "NORMAL")


# ── Section 6: clean-baseline guard — high ML anomaly without a log signature ──
# A severe, signature-free flood (huge request burst, no auth/log signals at
# all) must not be silently forced to NORMAL just because no known attack
# signature matched. It also must NOT be promoted all the way to EXTREME_RISK
# on ML alone (no confirmed log evidence) — the fix caps it below that tier.
post("/state/reset", {})
high_volume_flood = [
    f"Jan 1 00:{i//60:02d}:{i%60:02d} web01 kernel: TCP SYN flood detected from 203.0.113.50 port {40000+i}"
    for i in range(300)
]
status, body = post("/dataset/logs", {"log_lines": high_volume_flood})
check("flood batch processed", status == 200)
fr = body["results"][0]
ml_score = fr["components"].get("ml_score", 0)
print(f"  (flood result: status={fr['status']} score={fr['risk_score']} "
      f"ml_score={ml_score}, ML_ANOMALY_THRESHOLD={ML_ANOMALY_THRESHOLD})")
if ml_score >= ML_ANOMALY_THRESHOLD:
    # Genuinely crossed ML_ANOMALY_THRESHOLD with zero log signal — this is the
    # exact case the guard previously force-suppressed to NORMAL/<=20.
    check(f"ML genuinely flagged this (>={ML_ANOMALY_THRESHOLD}) and was NOT suppressed to NORMAL",
          fr["status"] != "NORMAL")
    check("signature-free anomaly is still capped below EXTREME_RISK (unconfirmed, not a matched attack)",
          fr["risk_score"] < 60.0)
else:
    print(f"  NOTE: this batch's ml_score ({ml_score}) did not reach ML_ANOMALY_THRESHOLD "
          f"({ML_ANOMALY_THRESHOLD}) with the currently trained model, so the override branch "
          "was not exercised by this run. Not claiming a false pass — rerun with a "
          "larger/more extreme synthetic flood if this matters.")

# Clean baseline must still hold for genuinely ordinary traffic.
post("/state/reset", {})
r = result_for(["Jan 1 00:00:01 web01 CRON[300]: (root) CMD (/usr/bin/logrotate)"])
check("ordinary cron activity stays NORMAL", r["status"] == "NORMAL")


# ── Section 7: concurrent batch isolation ──────────────────────────────────────
# NOTE: aggregate_by_ip's "usernames" field cannot be used as the isolation
# signal here — it is populated only from _extract_username(), whose regex
# requires "USER= <space> name" and never matches this repo's own sudo log
# format ("USER=root", no space), so it comes back empty for every batch
# regardless of isolation. That is a separate, real bug (see written report,
# "username extraction never matches") — not fixed here, out of scope for
# the concurrency fix. Isolation is instead verified via attack_type/status,
# which genuinely does flow through the shared per-IP state this lock
# protects.

def submit_extreme():
    # sudo + /etc/shadow -> deterministically EXTREME_RISK / PRIVILEGE_ESCALATION
    return post("/dataset/logs", {"log_lines": [
        "Jan 1 00:00:01 web01 sudo[999]: x : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    ]})


def submit_normal():
    # single benign cron line -> deterministically NORMAL
    return post("/dataset/logs", {"log_lines": [
        "Jan 1 00:00:01 web01 CRON[300]: (root) CMD (/usr/bin/logrotate)"
    ]})


with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
    fut_a = ex.submit(submit_extreme)
    fut_b = ex.submit(submit_normal)
    status_a, body_a = fut_a.result()
    status_b, body_b = fut_b.result()

check("concurrent extreme batch succeeded", status_a == 200)
check("concurrent normal batch succeeded", status_b == 200)
res_a = body_a["results"][0]
res_b = body_b["results"][0]
check("extreme batch is not diluted to NORMAL by the concurrent normal batch's reset",
      res_a["status"] == "EXTREME_RISK" and res_a["attack_type"] == "PRIVILEGE_ESCALATION")
check("normal batch is not elevated by the concurrent extreme batch's state",
      res_b["status"] == "NORMAL")

print("\nAll checks passed.")

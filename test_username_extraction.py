"""
Regression tests for the username-extraction fix in linux_log_parser.py.

No server required. Run from the repo root with the ingestion venv's Python:
    python test_username_extraction.py
"""
from ingestion.services.linux_log_parser import (
    _extract_username, _extract_sudo_actor, parse_lines, aggregate_by_ip,
)


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}: {name}")
    assert cond, name


# ── Positive cases ──────────────────────────────────────────────────────────────

check("USER=root (no space) is now extracted — the bug that started this fix",
      _extract_username("sudo[100]: mallory : TTY=pts/0 ; PWD=/home/mallory ; "
                        "USER=root ; COMMAND=/bin/cat /etc/shadow") == "root")

check("sudo_actor extracts the real actor from the same line",
      _extract_sudo_actor("sudo[100]: mallory : TTY=pts/0 ; PWD=/home/mallory ; "
                          "USER=root ; COMMAND=/bin/cat /etc/shadow") == "mallory")

check('"Failed password for alice from X" extracts alice (not the literal word "for")',
      _extract_username("sshd[100]: Failed password for alice from 10.0.0.5 port 22 ssh2") == "alice")

check('"Invalid user bob from X" extracts bob',
      _extract_username("sshd[100]: Invalid user bob from 10.0.0.9 port 22 ssh2") == "bob")

check('"session closed for user carol" extracts carol, not the literal word "user" '
      '(the old regex\'s priority bug)',
      _extract_username("sshd[100]: pam_unix(sshd:session): session closed for user carol") == "carol")

check('audit acct="dave" (quoted key=value) extracts dave',
      _extract_username('type=USER_AUTH msg=audit(1700000000.123): pid=1 uid=0 '
                        'acct="dave" exe="/usr/bin/sudo" res=success') == "dave")

check('"New session 5 of user erin" extracts erin via the generic "user X" fallback',
      _extract_username("systemd-logind: New session 5 of user erin.") == "erin")


# ── Negative cases: must NOT extract command arguments as usernames ────────────

check("a shell loop inside COMMAND= is not mistaken for a username pattern",
      _extract_username("sudo[100]: mallory : TTY=pts/0 ; PWD=/tmp ; USER=root ; "
                        "COMMAND=/bin/bash -c 'for h in a b c; do ping $h; done'") == "root")

check("CRON CMD() with an embedded 'for' loop and no USER=/acct= extracts nothing",
      _extract_username("CRON[100]: (root) CMD (for i in /etc/*; do echo $i; done)") is None)

check('"by" inside another word ("nearby") is not matched (word boundary)',
      _extract_username("kernel: suspicious traffic nearby_host flagged") is None)

check("a line with no recognizable username pattern at all returns None",
      _extract_username("kernel: TCP SYN flood detected from 203.0.113.50 port 40001") is None)


# ── End-to-end: aggregate_by_ip now attributes sudo lines to the real actor ────

events, total, valid = parse_lines([
    "Jan 1 00:00:01 web01 sudo[100]: mallory : TTY=pts/0 ; PWD=/home/mallory ; "
    "USER=root ; COMMAND=/bin/cat /etc/shadow",
])
by_ip = aggregate_by_ip(events)
features = next(iter(by_ip.values()))
check("aggregate_by_ip attributes the sudo line to the real actor (mallory), not USER=root",
      "mallory" in features["usernames"] and "root" not in features["usernames"])

print("\nAll checks passed.")

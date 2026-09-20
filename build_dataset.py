"""
build_dataset.py — Convert linux-logs-70-privOnly-log.txt into intrusion_data.csv
50 normal events + 20 privilege escalation attack events = 70 rows
Run: python build_dataset.py
"""
import csv, re, random, os

LOG_FILE = "backend/data/linux-logs-70-privOnly-log.txt"
OUT_FILE = "backend/data/intrusion_data.csv"

# Known actors with their IPs and threat reputation (0=clean, 1=malicious)
ACTORS = {
    "mayur":    {"ip": "10.0.1.42",  "rep": 0.82, "threat": True},
    "ubuntu":   {"ip": "10.0.1.55",  "rep": 0.91, "threat": True},
    "deploy":   {"ip": "10.0.1.67",  "rep": 0.88, "threat": True},
    "admin":    {"ip": "10.0.1.23",  "rep": 0.75, "threat": True},
    "www-data": {"ip": "10.0.1.88",  "rep": 0.70, "threat": True},
    "root":     {"ip": "127.0.0.1",  "rep": 0.05, "threat": False},
}

RE_SUDO_ACTOR  = re.compile(r'sudo\s*:\s*([a-zA-Z0-9_\-]+)\s*:', re.I)
RE_PAM_ACTOR   = re.compile(r'session opened for user root by ([a-zA-Z0-9_\-]+)\(', re.I)
RE_PRIV_ESC    = re.compile(
    r'COMMAND=/bin/bash|COMMAND=/bin/sh'
    r'|session opened for user root'
    r'|incorrect password attempt', re.I)
RE_SUDO        = re.compile(r'sudo\s*:.*COMMAND=', re.I)
RE_FAILED      = re.compile(r'Failed password|authentication failure|incorrect password', re.I)
RE_SUCCESS     = re.compile(r'session opened for user|Accepted password', re.I)
RE_TIMESTAMP   = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')

with open(LOG_FILE) as f:
    lines = [l.strip() for l in f if l.strip()]

rows = []
for line in lines:
    # Determine actor
    actor = None
    m = RE_SUDO_ACTOR.search(line)
    if m and m.group(1).lower() not in ('pam_unix','pam','session'):
        actor = m.group(1).lower()
    if not actor:
        m = RE_PAM_ACTOR.search(line)
        if m:
            actor = m.group(1).lower()

    info = ACTORS.get(actor, {
        "ip": f"10.0.{random.randint(2,9)}.{random.randint(1,254)}",
        "rep": round(random.uniform(0.05, 0.25), 2),
        "threat": False
    })

    priv_esc = 1 if RE_PRIV_ESC.search(line) else 0
    sudo_att = 1 if RE_SUDO.search(line) else 0
    failed   = 1 if RE_FAILED.search(line) else 0
    success  = 1 if RE_SUCCESS.search(line) else 0

    # Attack classification — 20 attack events:
    # priv_esc lines (7) + sudo commands by threat actors (13 more)
    is_threat_actor = info.get("threat", False)

    if priv_esc and "COMMAND=/bin/bash" in line:
        name = "Privilege Escalation"
        attack_detected = 1
    elif priv_esc and "session opened for user root" in line.lower():
        name = "Root Session Opened"
        attack_detected = 1
    elif priv_esc and "incorrect password" in line.lower():
        name = "Failed Sudo Attempt"
        attack_detected = 1
    elif sudo_att and is_threat_actor:
        # Sudo commands by known threat actors = attack
        name = "Sudo Privilege Abuse"
        attack_detected = 1
    elif failed:
        name = "Failed Login"
        attack_detected = 1
    elif success and is_threat_actor:
        name = "Suspicious Login"
        attack_detected = 0
    elif sudo_att:
        name = "Sudo Command"
        attack_detected = 0
    else:
        name = "System Event"
        attack_detected = 0

    # Numeric features — attack rows get high rep score (threat actor)
    login_attempts   = (2 if sudo_att else 0) + (failed * 3) + (1 if success else 0)
    failed_logins    = failed * 2 + (1 if "incorrect password" in line.lower() else 0)
    session_duration = 600 if priv_esc else (300 if (sudo_att and is_threat_actor) else random.randint(10, 180))
    unusual_time     = 1 if (priv_esc or (sudo_att and is_threat_actor)) else 0
    # ip_reputation_score: high = malicious (matches ingestion service convention)
    ip_rep = info["rep"] if attack_detected else round(random.uniform(0.05, 0.3), 2)
    traffic = random.randint(80000, 200000) if attack_detected else random.randint(500, 5000)
    packet_size = random.randint(512, 2048) if attack_detected else random.randint(64, 512)

    ts_m = RE_TIMESTAMP.match(line)
    timestamp = ts_m.group(1) if ts_m else "Apr 11 00:00:00"

    rows.append({
        "src_ip":                 info["ip"],
        "name":                   name,
        "protocol_type":          "TCP",
        "login_attempts":         login_attempts,
        "failed_logins":          failed_logins,
        "session_duration":       session_duration,
        "ip_reputation_score":    ip_rep,
        "unusual_time_access":    unusual_time,
        "network_traffic_volume": traffic,
        "network_packet_size":    packet_size,
        "attack_detected":        attack_detected,
        "privilege_escalation":   priv_esc,
        "sudo_attempt":           sudo_att,
        "actor":                  actor or "system",
        "raw_log":                line,
        "log_timestamp":          timestamp,
    })

os.makedirs("backend/data", exist_ok=True)

# Pad to exactly 20 attack rows by duplicating the most severe ones
attack_rows = [r for r in rows if r["attack_detected"]]
normal_rows = [r for r in rows if not r["attack_detected"]]

# Pick the priv-esc rows to duplicate
priv_rows = [r for r in attack_rows if r["privilege_escalation"]]
needed = 20 - len(attack_rows)
import copy
extras = []
for i in range(needed):
    base = copy.deepcopy(priv_rows[i % len(priv_rows)])
    # Slightly vary the IP and timestamp to make them distinct
    ip_parts = base["src_ip"].split(".")
    ip_parts[-1] = str((int(ip_parts[-1]) + i + 10) % 254 + 1)
    base["src_ip"] = ".".join(ip_parts)
    base["log_timestamp"] = f"Apr 11 00:5{i}:00"
    base["network_traffic_volume"] = random.randint(80000, 200000)
    extras.append(base)

# Trim normal rows to exactly 50
normal_rows = normal_rows[:50]

# Final dataset: 50 normal + 20 attacks
final_rows = normal_rows + attack_rows + extras
random.shuffle(final_rows)

with open(OUT_FILE, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=final_rows[0].keys())
    writer.writeheader()
    writer.writerows(final_rows)

attacks = sum(1 for r in final_rows if r["attack_detected"])
normals = sum(1 for r in final_rows if not r["attack_detected"])
priv    = sum(1 for r in final_rows if r["privilege_escalation"])
print(f"Written {len(final_rows)} rows: {attacks} attacks, {normals} normal, {priv} priv-esc")
actors = {}
for r in final_rows:
    if r["attack_detected"]:
        a = r["actor"]
        actors[a] = actors.get(a, 0) + 1
print("Attack actors:", actors)

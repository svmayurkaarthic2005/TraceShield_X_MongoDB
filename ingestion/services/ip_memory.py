"""
ip_memory.py — Per-IP behavioral history with trend detection.
Tracks last N request counts and timestamps per IP.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, List
import statistics

MAX_HISTORY = 20


@dataclass
class IPRecord:
    counts:     Deque[int]      = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    timestamps: Deque[datetime] = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))

    def add(self, count: int, ts: datetime) -> None:
        self.counts.append(count)
        self.timestamps.append(ts)

    def history_size(self) -> int:
        return len(self.counts)

    def avg_count(self) -> float:
        """Mean of all historical counts excluding the latest."""
        if len(self.counts) < 2:
            return float(self.counts[0]) if self.counts else 0.0
        return statistics.mean(list(self.counts)[:-1])

    def avg_rate(self) -> float:
        """Mean requests-per-second over historical window."""
        if len(self.timestamps) < 2:
            return 0.0
        deltas = []
        ts_list = list(self.timestamps)
        cnt_list = list(self.counts)
        for i in range(1, len(ts_list)):
            diff = (ts_list[i] - ts_list[i - 1]).total_seconds()
            if diff > 0:
                deltas.append(cnt_list[i] / diff)
        return statistics.mean(deltas) if deltas else 0.0

    def trend_score(self) -> float:
        """
        Detect increasing trend in request counts (0-100).

        Two signals combined:
          1. Monotonic rise ratio — fraction of consecutive increases
          2. Ramp-up ratio — (latest - earliest) / (earliest + 1e-5)

        Returns 0-100 where 100 = strong sustained upward trend.
        """
        counts = list(self.counts)
        n = len(counts)
        if n < 3:
            return 0.0

        # Signal 1: monotonic rise ratio
        rises = sum(1 for i in range(1, n) if counts[i] > counts[i - 1])
        rise_ratio = rises / (n - 1)          # 0-1

        # Signal 2: ramp-up from earliest to latest
        earliest = counts[0]
        latest   = counts[-1]
        ramp = (latest - earliest) / (earliest + 1e-5)
        ramp_score = min(ramp * 20.0, 100.0)  # 5x ramp = 100

        # Combine: weight monotonic rise 40%, ramp 60%
        combined = 0.40 * (rise_ratio * 100.0) + 0.60 * ramp_score
        return round(min(combined, 100.0), 2)


# Singleton store
_store: dict = defaultdict(IPRecord)


def get_record(ip: str) -> IPRecord:
    return _store[ip]


def record_event(ip: str, count: int, ts: datetime) -> IPRecord:
    """Add event to IP history and return updated record."""
    rec = _store[ip]
    rec.add(count, ts)
    return rec


def reset_state() -> int:
    """Forget every IP's behavioural history. Returns how many were tracked."""
    n = len(_store)
    _store.clear()
    return n

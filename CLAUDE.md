# CLAUDE.md — TraceShield X++ Project Guide

## Overview

**TraceShield X++** is an AI-powered cybersecurity forensics and anti-forensics detection platform. It combines machine learning anomaly detection, rule-based threat engines, graph-based attack chain visualization, and an automated incident response system into a SOC-grade dashboard.

---

## System Architecture

The project is structured into three main components:

```
┌───────────────────────────────────────────────────────────┐
│                 FRONTEND (React 18 + Vite)                │
│                 Port: 5173 (Tailwind CSS)                 │
└──────────────┬────────────────────────────┬───────────────┘
               │ HTTP (Axios)               │ HTTP (Axios)
               ▼                            ▼
┌───────────────────────────┐  ┌────────────────────────────┐
│    CORE BACKEND (:8000)   │  │  INGESTION SERVICE (:8001) │
│  • FastAPI REST API       │  │  • Real-time stream ingest │
│  • ML Training (IsoForest)│  │  • Ensemble (IsoForest+LOF)│
│  • Rule engine & AFRS     │  │  • Sliding window IP memory│
│  • Attack graph builder   │  │  • 4-tier automated response│
│  • Forensic summarizer    │  │  • Linux auth log parsing  │
└──────────────┬────────────┘  └────────────┬───────────────┘
               │                            │
               └────────────┬───────────────┘
                            ▼ Bolt Protocol (:7687)
             ┌─────────────────────────────┐
             │    NEO4J GRAPH DATABASE     │
             │   (:IP)-[:ATTACKED]->(:Dev) │
             │   (:IP)-[:REDIRECTED]->(:Hn)│
             │   (:IP)-[:BLOCKED]->(:Sys)  │
             └─────────────────────────────┘
```

| Service | Port | Directory | Tech Stack | Role |
|---|---|---|---|---|
| **Core Backend** | `8000` | `backend/` | Python 3.10+, FastAPI, scikit-learn, neo4j | Training, static scoring, graph querying, forensic reporting |
| **Ingestion Service** | `8001` | `ingestion/` | Python 3.10+, FastAPI, scikit-learn, neo4j | Real-time event ingestion, live ensemble ML, automated response |
| **Frontend** | `5173` | `frontend/` | React 18, Vite 5, Tailwind CSS 3.4, Axios | SOC-style cyberpunk dashboard & threat hunting UI |
| **Neo4j** | `7687` | Local/Docker | Neo4j Graph DB | Attack chain graph storage & relationship tracking |

---

## Development & Execution Commands

### Prerequisites
- Python 3.10+
- Node.js 18+ & npm
- Neo4j Desktop / Server (running on `bolt://127.0.0.1:7687` or configured URI)

### Quick Start (All-in-One)
```bash
# From repository root (Linux/WSL/Git Bash)
chmod +x start.sh
./start.sh
```

### Running Services Independently

#### 1. Core Backend (`:8000`)
```bash
cd backend
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

#### 2. Ingestion Service (`:8001`)
```bash
cd ingestion
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload --port 8001
```

#### 3. Frontend (`:5173`)
```bash
cd frontend
npm install
npm run dev        # Starts Vite dev server on http://localhost:5173
npm run build      # Production bundle to dist/
npm run preview    # Preview production build
```

---

## Testing & Helper Scripts

- **Test Log Ingestion**:
  ```bash
  python test_logs.py
  ```
  Sends Linux auth logs to `http://127.0.0.1:8001/ingest/logs` and executes test network event ingestion.

- **Test Log Dataset Upload**:
  ```bash
  python test_upload.py
  ```
  Tests multipart log upload via `http://127.0.0.1:8001/dataset/upload`.

- **Build / Rebuild Dataset**:
  ```bash
  python build_dataset.py
  ```
  Parses raw `linux-logs-70-privOnly-log.txt` into `backend/data/intrusion_data.csv`.

- **Neo4j Relationship Patch**:
  ```bash
  python patch_neo4j.py
  ```
  Backfills default properties (`reason`, `timestamp`) on legacy graph edges.

- **Bash Ingest Test**:
  ```bash
  cd ingestion && ./test_ingest.sh
  ```

---

## Project Structure

```
TraceShield-X-main/
├── backend/
│   ├── api/
│   │   └── routes.py           # Core backend endpoints (predict, risk, graph, train, forensic report)
│   ├── core/
│   │   ├── detection.py        # Rule-based threat engine (brute force, odd hours, high duration)
│   │   ├── graph_builder.py    # Neo4j graph construction and Cypher query execution
│   │   ├── ml_model.py         # Isolation Forest model (5 features) trained on intrusion_data.csv
│   │   ├── neo4j_db.py         # Neo4j connection pool and driver lifecycle
│   │   ├── risk.py             # AFRS scoring algorithm (ML + rules + weights)
│   │   ├── simulation.py       # Attack log and synthetic data generator
│   │   └── summarizer.py       # Forensic attack timeline & summary generator
│   ├── data/
│   │   ├── intrusion_data.csv  # 70-row benchmark dataset
│   │   └── linux-logs-70-privOnly-log.txt
│   ├── main.py                 # Core backend FastAPI app initialization & CORS
│   └── requirements.txt
│
├── ingestion/
│   ├── db/
│   │   └── neo4j_client.py     # Ingestion service Neo4j client
│   ├── models/                 # Ingestion Pydantic schemas (events, alerts, logs)
│   ├── services/
│   │   ├── anomaly_detector.py # Live anomaly detector
│   │   ├── ip_memory.py        # Sliding window history per IP (20 events)
│   │   ├── linux_log_parser.py # Linux auth log parsing (sudo, auth failures, sessions)
│   │   ├── ml_engine.py        # ML feature extraction (9 features)
│   │   ├── ml_model.py         # Isolation Forest + LOF ensemble scorer
│   │   ├── ml_training.py      # ML training pipeline for streaming anomalies
│   │   ├── response_engine.py  # 4-tier automated mitigation actions (flag/honeypot/block)
│   │   └── risk_engine.py      # Adaptive risk calculation (fuses ML, history, logs)
│   ├── main.py                 # Ingestion FastAPI app (routes: /ingest, /ingest/logs, /dataset/upload, etc.)
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AlertFeed.jsx       # Real-time alert notifications
│   │   │   ├── AnalyticsPage.jsx   # Charts, score distributions, and metric trends
│   │   │   ├── DataLogsPage.jsx    # Raw event and parsed log viewer
│   │   │   ├── GraphPanel.jsx      # Attack chain visualizer
│   │   │   ├── HomePage.jsx        # Landing page & status overview
│   │   │   ├── HoneypotPage.jsx    # Honeypot interactions & captured commands
│   │   │   ├── LiveFeed.jsx        # Live incoming stream monitoring
│   │   │   ├── RiskCard.jsx        # Dynamic risk gauge & component breakdown
│   │   │   ├── ThreatHuntPage.jsx  # Threat investigation by IP/device/actor
│   │   │   └── ThreatStatePanel.jsx# Current blocked IPs & mitigation state
│   │   ├── App.jsx             # Top-level navigation, polling state, view routing
│   │   ├── index.css           # Tailwind CSS directives and custom glow/cyberpunk animations
│   │   └── main.jsx            # React root mount
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
│
├── build_dataset.py
├── patch_neo4j.py
├── start.sh
├── test_logs.py
├── test_upload.py
└── .env.example
```

---

## Core Detection & Scoring Mechanics

### 1. Adaptive Forensic Risk Scoring (AFRS)
The risk score (0–100) is computed from 5 weighted components:
- **ML Anomaly Score (35%)**: Isolation Forest + Local Outlier Factor ensemble output
- **Temporal Anomaly Score (25%)**: Hour-of-day access patterns, night shifts, weekend activity
- **Request Count Score (20%)**: Normalized request volume / velocity
- **Spike Deviation Score (10%)**: Deviation from per-IP rolling average (IP Memory)
- **Behavioral Trend Score (10%)**: Acceleration/surge across the IP's last 20 events

### 2. 4-Tier Automated Response Matrix
| Score Range | Threat Level | Automated Action Taken |
|---|---|---|
| **0 – 25** | `NORMAL` | Logged, no mitigation action taken |
| **25 – 40** | `SUSPICIOUS` | Flag IP in memory, increment warning counter |
| **40 – 60** | `HIGH_RISK` | Redirect traffic to Honeypot simulation environment |
| **60 – 100** | `EXTREME` | Block IP, redirect to Honeypot, record in Neo4j blocklist |

### 3. Graph Schema (Neo4j)
- **Nodes**: `(:IP)`, `(:Device)`, `(:Honeypot)`, `(:System)`
- **Relationships**:
  - `(:IP)-[:ATTACKED {risk_score, reason, timestamp, hit_count}]->(:Device)`
  - `(:IP)-[:REDIRECTED_TO {reason, timestamp}]->(:Honeypot)`
  - `(:IP)-[:BLOCKED {reason, timestamp}]->(:System)`

---

## Environment Variables Configuration

Create a `.env` file in the root or service folders based on `.env.example`:

```env
NEO4J_URI=neo4j://127.0.0.1:7687
NEO4J_USER=TraceShieldDB
NEO4J_PASSWORD=12345678
```

---

## Code Style & Development Guidelines

### Python (Backend & Ingestion)
- **Framework**: FastAPI with Pydantic schemas for request validation and response models.
- **Typing**: Use standard Python type hints (`dict[str, Any]`, `list[str]`, `Optional[int]`).
- **Error Handling**: Graceful fallback if Neo4j is unavailable (in-memory state continues working).
- **ML Models**: Keep feature preprocessing with `StandardScaler` synchronized across training and inference.
- **Concurrency**: Use `async`/`await` for non-blocking I/O where applicable.

### Frontend (React + Vite)
- **Styling**: Tailwind CSS utility classes; adhere to the dark SOC / cyberpunk aesthetic (deep slate backgrounds, neon greens `#00ff88`, warning ambers, threat reds).
- **Component Architecture**: Keep views self-contained in `src/components/` and communicate with backends via configured Axios endpoints (`localhost:8000` / `localhost:8001`).
- **State Management**: React hooks (`useState`, `useEffect`, `useCallback`) with interval-based polling for live feed updates.

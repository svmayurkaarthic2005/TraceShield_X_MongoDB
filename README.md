<p align="center">
  <img src="https://img.shields.io/badge/TraceShield-X++-00ff88?style=for-the-badge&logo=shieldsdotio&logoColor=white" alt="TraceShield X++"/>
</p>

<h1 align="center">🛡️ TraceShield X++</h1>

<p align="center">
  <strong>AI-Powered Cybersecurity Forensics & Anti-Forensics Detection Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/FastAPI-0.116+-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/Node.js-18+-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js"/>
  <img src="https://img.shields.io/badge/React-18.2-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React"/>
  <img src="https://img.shields.io/badge/Neo4j-Graph_DB-008CC1?style=flat-square&logo=neo4j&logoColor=white" alt="Neo4j"/>
  <img src="https://img.shields.io/badge/MongoDB-Reports-47A248?style=flat-square&logo=mongodb&logoColor=white" alt="MongoDB"/>
  <img src="https://img.shields.io/badge/scikit--learn-ML-F7931E?style=flat-square&logo=scikit-learn&logoColor=white" alt="scikit-learn"/>
</p>

<p align="center">
  A full-stack, real-time cybersecurity dashboard that combines <b>Machine Learning anomaly detection</b>,<br/>
  <b>rule-based threat engines</b>, <b>graph-based attack visualization</b>, and <b>automated incident response</b><br/>
  to deliver SOC-grade forensic intelligence — all running locally.
</p>

---

## 📑 Table of Contents

- [✨ Key Features](#-key-features)
- [🏗️ Architecture](#️-architecture)
- [🧠 How It Works](#-how-it-works)
- [🛠️ Tech Stack](#️-tech-stack)
- [⚡ Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [🔧 Configuration](#-configuration)
- [🔐 Authentication](#-authentication)
- [📡 API Reference](#-api-reference)
- [📂 Project Structure](#-project-structure)
- [🧪 Testing](#-testing)
- [🔒 Security](#-security)
- [🧩 Extensibility](#-extensibility)

---

## ✨ Key Features

<table>
  <tr>
    <td>🤖 <b>ML Anomaly Detection</b></td>
    <td>Isolation Forest + Local Outlier Factor ensemble trained on network intrusion patterns</td>
  </tr>
  <tr>
    <td>🔍 <b>Rule-Based Threat Engine</b></td>
    <td>Detects brute force attacks, suspicious IPs, unusual access times, and long sessions</td>
  </tr>
  <tr>
    <td>📊 <b>Adaptive Risk Scoring (AFRS)</b></td>
    <td>Weighted 5-component scoring system combining ML + temporal + behavioral signals (0–100)</td>
  </tr>
  <tr>
    <td>🕸️ <b>Attack Graph Visualization</b></td>
    <td>Neo4j-powered graph mapping IP → Device → Honeypot → System attack chains</td>
  </tr>
  <tr>
    <td>🤖 <b>Automated Response Engine</b></td>
    <td>4-tier response: flag → honeypot redirect → IP block with cooldown-based unblocking</td>
  </tr>
  <tr>
    <td>🍯 <b>Honeypot Simulation</b></td>
    <td>Simulated deception environment with fake attacker commands and interaction tracking</td>
  </tr>
  <tr>
    <td>📝 <b>Forensic Reports</b></td>
    <td>Generates analyst-style incident reports, saved to MongoDB and downloadable as standalone HTML</td>
  </tr>
  <tr>
    <td>🔐 <b>JWT-Protected Gateway</b></td>
    <td>Single-origin Express gateway in front of both Python services, gated behind a login</td>
  </tr>
  <tr>
    <td>🧠 <b>Per-IP Behavioral Memory</b></td>
    <td>Sliding window history per IP for spike detection and trend analysis</td>
  </tr>
  <tr>
    <td>📈 <b>Live SOC Dashboard</b></td>
    <td>React + Tailwind cyberpunk-themed UI with auto-refresh, animated risk scores, and glow effects</td>
  </tr>
</table>

---

## 🏗️ Architecture

TraceShield X++ runs as **two independent Python backend services**, an **Express gateway**, a **React frontend**, and two databases, each with a distinct job:

```
┌─────────────────────────────────────────────────────────────────┐
│                      FRONTEND (React + Vite)                     │
│                                                                   │
│   HomePage  │  Dashboard  │  Analytics  │  ThreatHunt  │  Logs   │
│   LiveFeed  │  GraphPanel │  Honeypot   │  RiskCard    │  Alerts │
└──────────────────────────┬────────────────────────────────────────┘
                           │ HTTP (Axios) + WebSocket — single origin
                           │ every request carries a JWT
                           ▼
          ┌────────────────────────────────────┐
          │       EXPRESS GATEWAY (:5000)       │
          │  /api/auth/login  → issues JWT      │
          │  /api/core/*      → Core Backend    │
          │  /api/ingest/*,/ws→ Ingestion       │
          │  /api/reports     → MongoDB         │
          └──────────────┬──────────┬───────────┘
              /api/core/* │          │ /api/ingest/*, /ws
              ┌────────────┴────────────────┐
              ▼                             ▼
┌──────────────────────────┐  ┌──────────────────────────────────┐
│  CORE BACKEND (:8000)    │  │  INGESTION SERVICE (:8001)       │
│                          │  │                                    │
│  ┌──────────┐ ┌────────┐│  │  ┌──────────┐  ┌──────────────┐  │
│  │ ML Model │ │ Rules  ││  │  │ ML Model │  │  IP Memory   │  │
│  │(IsoForest│ │ Engine ││  │  │(IsoForest│  │ (per-IP hist)│  │
│  │ 5 feats) │ │(4 rules││  │  │+ LOF     │  │              │  │
│  └──────────┘ └────────┘│  │  │ 9 feats) │  └──────────────┘  │
│  ┌──────────┐ ┌────────┐│  │  └──────────┘  ┌──────────────┐  │
│  │  AFRS    │ │  Graph ││  │  ┌──────────┐  │ Response Eng │  │
│  │ Scoring  │ │ Builder││  │  │  Risk    │  │ (flag/block/ │  │
│  └──────────┘ └────────┘│  │  │  Engine  │  │  honeypot)   │  │
│  ┌──────────┐ ┌────────┐│  │  └──────────┘  └──────────────┘  │
│  │ Simulate │ │Summar- ││  │  ┌──────────┐  ┌──────────────┐  │
│  │ (synth)  │ │  izer  ││  │  │ Anomaly  │  │ Log Parser   │  │
│  └──────────┘ └────────┘│  │  │ Detector │  │ (Linux logs) │  │
└────────────┬─────────────┘  └──────┬───────────────────────────┘
             │                       │
             └───────────┬───────────┘
                         ▼ Bolt Protocol
          ┌──────────────────────────────┐
          │     NEO4J GRAPH DATABASE     │
          │  (:IP)─[:ATTACKED]→(:Device) │
          │  (:IP)─[:REDIRECTED]→(:Honey)│
          │  (:IP)─[:BLOCKED]→(:System)  │
          └──────────────────────────────┘

          ┌──────────────────────────────┐
          │      MONGODB (:27017)        │
          │  Forensic reports only —     │
          │  owned by the Express        │
          │  gateway, never touched by   │
          │  Core/Ingestion              │
          └──────────────────────────────┘
```

| Service | Port | Role |
|---------|------|------|
| **Express Gateway** | `5000` | Single origin for the frontend — JWT auth, reverse proxies to Core/Ingestion, proxies `/ws`, owns the Reports API |
| **Core Backend** | `8000` | Dashboard API — ML training, risk scoring, graph building, forensic reports |
| **Ingestion Service** | `8001` | Real-time event processing — live anomaly detection, automated response |
| **Frontend** | `5173` | SOC-style dashboard — visualization, monitoring, threat hunting |
| **Neo4j** | `7687` | Graph database — attack chain storage and querying |
| **MongoDB** | `27017` | Document store for generated forensic incident reports only |

---

## 🧠 How It Works

### Data Flow — End to End

```
  Network Event                    ┌─────────────────────┐
  (IP, device,         ──────────► │   POST /ingest      │
   request_count,                  └──────────┬──────────┘
   timestamp)                                 │
                                              ▼
                               ┌──────────────────────────┐
                               │     IP Memory Service     │
                               │  • Record in sliding      │
                               │    window (last 20 events)│
                               │  • Compute avg, rate,     │
                               │    trend score             │
                               └────────────┬──────────────┘
                                            ▼
                               ┌──────────────────────────┐
                               │     ML Scoring Engine     │
                               │  • Extract 9 features     │
                               │  • StandardScaler         │
                               │  • IsolationForest +      │
                               │    Local Outlier Factor   │
                               │  • Fused score: 0–100     │
                               └────────────┬──────────────┘
                                            ▼
                               ┌──────────────────────────┐
                               │   Adaptive Risk Engine    │
                               │  35% ML + 25% temporal +  │
                               │  20% count + 10% spike +  │
                               │  10% trend → final score  │
                               │  • Spike/ML overrides     │
                               │  • Classify threat level  │
                               └────────────┬──────────────┘
                                            ▼
                               ┌──────────────────────────┐
                               │   Automated Response      │
                               │  NORMAL     → no action   │
                               │  SUSPICIOUS → flag IP     │
                               │  HIGH_RISK  → honeypot    │
                               │  EXTREME    → block IP    │
                               └────────────┬──────────────┘
                                            ▼
                               ┌──────────────────────────┐
                               │   Neo4j Graph Update      │
                               │  • MERGE nodes & edges    │
                               │  • Increment hit_count    │
                               │  • Store full metadata    │
                               └────────────┬──────────────┘
                                            ▼
                               ┌──────────────────────────┐
                               │    JSON Response           │
                               │  {status, risk_score,     │
                               │   components, response}   │
                               └──────────────────────────┘
```

A forensic report built from any of this (Dashboard simulation, a live event, or an uploaded log dataset) can be saved via the Threat Hunt page — that write goes to **MongoDB**, a completely separate path from the Neo4j graph above.

### ML Models

| Model | Service | Features | Purpose |
|-------|---------|----------|---------|
| **Isolation Forest** | Core Backend | 5 (login attempts, failed logins, session duration, IP reputation, unusual time) | Baseline anomaly detection on intrusion logs |
| **Isolation Forest + LOF** | Ingestion | 9 (request count, log-scaled count, hour, is_night, is_weekend, RPS, burst flag, deviation, historical rate) | Real-time ensemble anomaly detection on live events |

### Risk Classification

| Score Range | Level | Response Action |
|-------------|-------|-----------------|
| 0–25 | 🟢 **NORMAL** | No action |
| 25–40 | 🟡 **SUSPICIOUS** | Flag IP, increment counter |
| 40–60 | 🟠 **HIGH RISK** | Redirect to honeypot |
| 60–100 | 🔴 **EXTREME RISK** | Block IP + honeypot redirect |

---

## 🛠️ Tech Stack

### Backend (Python)
| Technology | Purpose |
|------------|---------|
| **Python 3.10+** | Core language |
| **FastAPI** | REST API framework for Core Backend & Ingestion |
| **Uvicorn** | ASGI server |
| **scikit-learn** | ML models (Isolation Forest, LOF, StandardScaler) |
| **pandas / NumPy** | Data loading and numerical operations |
| **Pydantic** | Request/response validation |

### Gateway (Node.js)
| Technology | Purpose |
|------------|---------|
| **Express** | Single origin for the frontend; reverse proxies to Core/Ingestion |
| **http-proxy-middleware** | HTTP + WebSocket reverse proxying |
| **Mongoose** | MongoDB schema/ODM for the Reports API |
| **jsonwebtoken + bcryptjs** | JWT issuing/verification and password hashing |

### Frontend
| Technology | Purpose |
|------------|---------|
| **React 18** | UI framework |
| **Vite 5** | Build tool and dev server |
| **Tailwind CSS 3.4** | Utility-first styling |
| **Axios** | HTTP client, with a JWT-attaching interceptor |

### Databases
| Technology | Purpose |
|------------|---------|
| **Neo4j** | Graph database for attack chain visualization |
| **MongoDB** | Document store for generated forensic incident reports only |
| **In-memory dicts** | Per-IP behavioral history, blocked IPs, honeypot state (Python services) |

---

## ⚡ Quick Start

```bash
git clone https://github.com/svmayurkaarthic2005/TraceShield_X_MongoDB.git
cd TraceShield_X_MongoDB

# Start everything (Linux/WSL/Git Bash)
chmod +x start.sh
./start.sh
```

Or, once each service's own dependencies are installed (see [Installation](#-installation)), start just the Node side from the repo root:

```bash
npm install
npm run dev:all   # Express gateway + frontend, via concurrently
```

Then open **http://localhost:5173** and log in (see [Authentication](#-authentication)).

---

## 📦 Installation

### Prerequisites

- **Python** 3.10 or higher
- **Node.js** 18+ and npm
- **Neo4j Desktop** ([Download](https://neo4j.com/download/)) — optional; the dashboard falls back to simulated graph data if it's unreachable
- **MongoDB Community Server** running on `127.0.0.1:27017` — optional; only needed to persist forensic reports

### 1️⃣ Core Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/macOS

pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 2️⃣ Ingestion Service

```bash
cd ingestion
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/macOS

pip install -r requirements.txt
uvicorn ingestion.main:app --reload --port 8001
```

### 3️⃣ Express Gateway

```bash
cd server
npm install
cp .env.example .env

# Set your login credentials
node scripts/hash-password.js <your-password>
# Paste the printed hash into AUTH_PASSWORD_HASH in .env, set AUTH_USERNAME,
# and set JWT_SECRET to a long random string.

npm run dev
```

> If MongoDB is unreachable, the gateway logs a warning and keeps running — `/api/reports` returns `503` until MongoDB is back; proxying to Core/Ingestion is unaffected.

### 4️⃣ Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173**. The frontend only ever talks to the Express gateway (`VITE_API_URL`, default `http://localhost:5000`) — never directly to Core or Ingestion.

### 5️⃣ Neo4j (Optional)

1. Install [Neo4j Desktop](https://neo4j.com/download/), create a local DBMS, set a password
2. Start it, then copy the root `.env.example` to `.env` and fill in your credentials

### 6️⃣ MongoDB (Optional)

Install MongoDB Community Server and make sure `mongod` is running on `127.0.0.1:27017`. No manual database setup needed — the gateway creates `traceshield.reports` on first write.

### 7️⃣ Dataset (Optional)

Drop a real intrusion CSV at `backend/data/intrusion_data.csv` with columns `login_attempts`, `failed_logins`, `session_duration`, `ip_reputation_score`, `unusual_time_access`. Without one, the system generates 5,000 synthetic training logs (80% normal, 20% attack).

---

## 🔧 Configuration

| File | Key variables |
|------|----------------|
| `.env.example` (root) | `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `MONGO_URI` |
| `server/.env.example` | `PORT`, `MONGO_URI`, `CORE_URL`, `INGEST_URL`, `JWT_SECRET`, `JWT_EXPIRES_IN`, `AUTH_USERNAME`, `AUTH_PASSWORD_HASH` |
| `frontend/.env.example` | `VITE_API_URL` (default `http://localhost:5000`) — the single origin the frontend talks to |

Copy each `.env.example` to `.env` in its own directory and fill in real values before starting that service.

---

## 🔐 Authentication

The Express gateway requires a JWT on `/api/reports`, `/api/core/*`, and `/api/ingest/*` — `/api/health` and `/api/auth/login` stay public. There's a single operator account, set in `server/.env`:

```bash
cd server
node scripts/hash-password.js <your-password>
```

Paste the output into `AUTH_PASSWORD_HASH`, and set `AUTH_USERNAME` and `JWT_SECRET`. The frontend's login page (`frontend/src/components/LoginPage.jsx`) handles the rest — it stores the JWT in `localStorage`, attaches it to every request, and drops back to the login screen on a `401`.

**Known gap:** the `/ws` WebSocket proxy is unauthenticated. Node's `'upgrade'` event bypasses Express middleware entirely, so the auth check never runs for it — securing it would need a token in the connection query string, checked before the handshake.

---

## 📡 API Reference

### Express Gateway — `:5000` (the single origin the frontend uses)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/auth/login` | — | Exchange username/password for a JWT |
| `GET` | `/api/health` | — | Aggregate status: gateway, MongoDB, Core, Ingestion, Neo4j |
| `GET/POST` | `/api/reports` | JWT | List / create forensic reports |
| `GET/DELETE` | `/api/reports/:incidentId` | JWT | Fetch / delete a single report |
| `*` | `/api/core/*` | JWT | Proxied to Core Backend, prefix stripped |
| `*` | `/api/ingest/*` | JWT | Proxied to Ingestion, prefix stripped |
| `WS` | `/ws` | none | Proxied to Ingestion's live event WebSocket |

### Core Backend — `:8000` (reached via `/api/core/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/analyze` | Analyze a random sample from the intrusion dataset |
| `POST` | `/api/simulate` | Generate and analyze simulated attack logs |
| `GET` | `/api/graph` | Fetch the full Neo4j attack graph |
| `DELETE` | `/api/graph/clear` | Clear all nodes and relationships in the graph |
| `GET` | `/api/status` | System status (model loaded, Neo4j connected, dataset size) |
| `GET` | `/api/health` | Health check (status, Neo4j, model loaded) |
| `GET` | `/api/threat-scan` | Run a full threat scan across the dataset |
| `GET` | `/api/dataset/logs` / `/api/dataset/rows` | Raw log lines / dataset rows |

### Ingestion Service — `:8001` (reached via `/api/ingest/*`, and `/ws` for the socket)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/ingest` | Ingest a real-time network event for analysis |
| `GET` | `/` | Liveness check (no dedicated `/health` route) |
| `GET` | `/blocked` | View all blocked, flagged, and honeypotted IPs |
| `DELETE` | `/blocked/{ip}` | Unblock an IP |
| `POST` | `/state/reset` | Clear all detection state |
| `POST` | `/dataset/upload` | Upload a log file for batch analysis |
| `GET` | `/graph`, `/graph/attacks`, `/graph/ip/{ip}`, `/graph/chain/{ip}`, `/graph/summary` | Attack graph reads |
| `WS` | `/ws` | Live event stream |

#### Example: Ingest an Event (direct, bypassing the gateway)

```bash
curl -X POST http://localhost:8001/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "device": "web-server-01",
    "request_count": 500,
    "timestamp": "2026-04-12T18:30:00Z"
  }'
```

```json
{
  "status": "HIGH_RISK",
  "risk_score": 52.3,
  "components": {
    "ml_score": 68.6,
    "temporal_score": 45.2,
    "count_score": 70.0,
    "spike_score": 100.0,
    "trend_score": 30.5
  },
  "response": {
    "action": "honeypot_redirect",
    "honeypot_id": "honeypot_a3f7d0"
  }
}
```

---

## 📂 Project Structure

```
TraceShield_X_MongoDB/
│
├── backend/                          # Core backend service (:8000)
│   ├── main.py                       # FastAPI app with lifespan (model training at startup)
│   ├── requirements.txt
│   ├── api/
│   │   └── routes.py                 # All REST API endpoint definitions
│   ├── core/
│   │   ├── ml_model.py               # Isolation Forest model (train + predict)
│   │   ├── detection.py              # Rule-based threat detection engine
│   │   ├── risk.py                   # Adaptive Forensic Risk Scoring (AFRS)
│   │   ├── simulation.py             # Synthetic log generator for training
│   │   ├── graph_builder.py          # Neo4j graph construction
│   │   ├── summarizer.py             # Forensic report generator
│   │   └── neo4j_db.py               # Neo4j connection manager
│   └── data/                         # Dataset directory (CSV files)
│
├── ingestion/                        # Real-time ingestion service (:8001)
│   ├── main.py                       # FastAPI app for event ingestion
│   ├── requirements.txt
│   ├── db/
│   │   ├── neo4j.py                  # Neo4j graph operations (MERGE-based)
│   │   └── neo4j_conn.py             # Neo4j connection pooling
│   ├── models/
│   │   ├── schemas.py                # Pydantic request/response schemas
│   │   ├── isolation_forest.pkl      # Pre-trained Isolation Forest model
│   │   └── scaler.pkl                # Pre-fitted StandardScaler
│   └── services/
│       ├── ml_model.py               # ML scoring (IsoForest + LOF ensemble)
│       ├── ml_engine.py              # ML engine orchestrator
│       ├── ml_training.py            # Model training pipeline
│       ├── anomaly_detector.py       # Main anomaly detection orchestrator
│       ├── risk_engine.py            # 5-component weighted risk scoring
│       ├── response_engine.py        # Automated response (flag/block/honeypot)
│       ├── ip_memory.py              # Per-IP sliding window memory
│       └── linux_log_parser.py       # Linux syslog parser
│
├── server/                           # Express gateway (:5000)
│   ├── index.js                      # App setup, auth, proxies, /api/health
│   ├── package.json
│   ├── config/
│   │   └── db.js                     # Mongoose connect, graceful degradation
│   ├── middleware/
│   │   └── auth.js                   # requireAuth — JWT verification
│   ├── models/
│   │   └── Report.js                 # Forensic report schema (unique incidentId)
│   ├── routes/
│   │   ├── auth.js                   # POST /api/auth/login
│   │   ├── reports.js                # Reports API (CRUD, MongoDB-backed, JWT-protected)
│   │   └── proxies.js                # /api/core, /api/ingest, /ws reverse proxies
│   ├── scripts/
│   │   └── hash-password.js          # Generates a bcrypt hash for AUTH_PASSWORD_HASH
│   └── test/
│       └── reports.test.js           # node:test + fetch, against traceshield_test
│
├── frontend/                         # React frontend (:5173)
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── src/
│       ├── main.jsx                  # Auth gate (LoginPage vs App) + React entry point
│       ├── App.jsx                   # Main app — routing & state management
│       ├── index.css                 # Global styles & design system
│       ├── services/
│       │   └── api.js                # Axios instance (attaches JWT, handles 401) + core()/ingest() helpers + WS_URL
│       └── components/
│           ├── HomePage.jsx          # Cyberpunk landing page
│           ├── LoginPage.jsx         # JWT login form
│           ├── RiskCard.jsx          # Animated risk score with glow effects
│           ├── AlertFeed.jsx         # Alert badges & attack timeline
│           ├── GraphPanel.jsx        # Attack graph visualization
│           ├── LiveFeed.jsx          # Real-time event stream
│           ├── AnalyticsPage.jsx     # Analytics dashboard & charts
│           ├── DataLogsPage.jsx      # Data log viewer & search
│           ├── ThreatHuntPage.jsx    # Threat hunting, forensic reports, Saved Reports panel
│           ├── HoneypotPage.jsx      # Honeypot monitoring panel
│           └── ThreatStatePanel.jsx  # Threat state overview
│
├── package.json                      # Root: `npm run dev:all` (concurrently: server + frontend)
├── start.sh                          # Quick start script (Linux/WSL/Git Bash)
├── patch_neo4j.py                    # Neo4j schema patch utility
├── build_dataset.py                  # Parses raw logs into the training CSV
├── test_logs.py                      # Log ingestion test script
├── test_upload.py                    # Upload test script
├── .env.example                      # Root environment variable template
└── EXPLANATION.md                    # Full technical deep-dive documentation
```

---

## 🧪 Testing

### Reports API (Node)

```bash
cd server
npm test        # node:test + fetch, against mongodb://127.0.0.1:27017/traceshield_test
```

### Python services

```bash
python test_logs.py       # sends auth-log-style events to :8001/ingest and /ingest/logs
python test_upload.py     # tests multipart upload to :8001/dataset/upload
cd ingestion && ./test_ingest.sh
```

### Manual health checks

```bash
curl http://localhost:5000/api/health   # aggregate: gateway, Mongo, Core, Ingestion, Neo4j
curl http://localhost:8000/api/health   # Core Backend only
curl http://localhost:8001/             # Ingestion liveness (no dedicated /health route)
```

---

## 🔒 Security

| Measure | Implementation |
|---------|---------------|
| **Authentication** | JWT-protected gateway routes, single operator account, bcrypt-hashed password (`/ws` is the one unauthenticated exception — see [Authentication](#-authentication)) |
| **Credential Management** | All `.env` files excluded from git; nothing is hardcoded |
| **CORS** | Gateway restricted to `http://localhost:5173` |
| **Input Validation** | Python endpoints validated via Pydantic models; the Reports API rejects writes missing `incidentId`/`severity`/`attackerIp` |
| **Query Safety** | All Neo4j queries use parameterized statements — no injection risk |
| **Simulated Responses** | No real network blocking or traffic manipulation — all response actions (block/honeypot) are simulated |

---

## 🧩 Extensibility

| Extension | How To |
|-----------|--------|
| 🤖 **Add a new ML model** | Replace `get_ml_score()` in `ingestion/services/ml_model.py` |
| 🔍 **Add a detection rule** | Add a new condition block in `backend/core/detection.py` |
| 🚫 **Real IP blocking** | Replace simulation in `response_engine._block_ip()` with firewall API calls (e.g., iptables, AWS WAF) |
| 🍯 **Real honeypot** | Replace `_redirect_honeypot()` with actual honeypot integration (e.g., Cowrie, T-Pot) |
| 🕸️ **New graph relationship** | Add a function in `ingestion/db/neo4j.py` following the existing MERGE pattern |
| 📄 **New report field** | Add it to `server/models/Report.js` and the shape built in `ThreatHuntPage.jsx` |
| 👥 **Multiple user accounts** | Replace the single hardcoded `AUTH_USERNAME`/`AUTH_PASSWORD_HASH` with a MongoDB `User` collection |
| 📊 **Real dataset** | Drop a CSV at `backend/data/intrusion_data.csv` — system auto-detects it |

---

## 📚 Documentation

For a comprehensive technical deep-dive covering every algorithm, model hyperparameter, scoring formula, and design decision, see **[EXPLANATION.md](./EXPLANATION.md)**.

---

<p align="center">
  Built by the TraceShield Team
</p>

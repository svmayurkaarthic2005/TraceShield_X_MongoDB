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
  <img src="https://img.shields.io/badge/React-18.2-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React"/>
  <img src="https://img.shields.io/badge/Neo4j-Graph_DB-008CC1?style=flat-square&logo=neo4j&logoColor=white" alt="Neo4j"/>
  <img src="https://img.shields.io/badge/scikit--learn-ML-F7931E?style=flat-square&logo=scikit-learn&logoColor=white" alt="scikit-learn"/>
  <img src="https://img.shields.io/badge/Vite-5.0-646CFF?style=flat-square&logo=vite&logoColor=white" alt="Vite"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/>
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
- [📡 API Reference](#-api-reference)
- [📂 Project Structure](#-project-structure)
- [🧪 Testing](#-testing)
- [🔒 Security](#-security)
- [🧩 Extensibility](#-extensibility)
- [📄 License](#-license)

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
    <td>📝 <b>Forensic Summarizer</b></td>
    <td>Generates human-readable analyst reports and step-by-step attack timelines</td>
  </tr>
  <tr>
    <td>🧠 <b>Per-IP Behavioral Memory</b></td>
    <td>Sliding window history per IP for spike detection and trend analysis</td>
  </tr>
  <tr>
    <td>📈 <b>Live SOC Dashboard</b></td>
    <td>React + Tailwind cyberpunk-themed UI with auto-refresh, animated risk scores, and glow effects</td>
  </tr>
  <tr>
    <td>📋 <b>Data Logs & Analytics</b></td>
    <td>Comprehensive data log viewer, analytics dashboards, and threat hunting interface</td>
  </tr>
</table>

---

## 🏗️ Architecture

TraceShield X++ runs as **two independent Python backend services**, an **Express gateway**, and a **React frontend**:

```
┌─────────────────────────────────────────────────────────────────┐
│                      FRONTEND (React + Vite)                     │
│                                                                   │
│   HomePage  │  Dashboard  │  Analytics  │  ThreatHunt  │  Logs   │
│   LiveFeed  │  GraphPanel │  Honeypot   │  RiskCard    │  Alerts │
└──────────────────────────┬────────────────────────────────────────┘
                           │ HTTP (Axios) + WebSocket — single origin
                           ▼
          ┌────────────────────────────────────┐
          │       EXPRESS GATEWAY (:5000)       │
          │  /api/core/*  → Core Backend proxy  │
          │  /api/ingest/*, /ws → Ingestion proxy│
          │  /api/reports → MongoDB (Mongoose)  │
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
          │                              │
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
| **Express Gateway** | `5000` | Single origin for the frontend — reverse proxies to Core/Ingestion, proxies `/ws`, owns the Reports API |
| **Core Backend** | `8000` | Dashboard API — ML training, risk scoring, graph building, forensic reports |
| **Ingestion Service** | `8001` | Real-time event processing — live anomaly detection, automated response |
| **Frontend** | `5173` | SOC-style dashboard — visualization, monitoring, threat hunting |
| **Neo4j** | `7687` | Graph database — attack chain storage and querying (unchanged) |
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

### Backend
| Technology | Purpose |
|------------|---------|
| **Python 3.10+** | Core language |
| **FastAPI** | High-performance REST API framework |
| **Uvicorn** | ASGI server |
| **scikit-learn** | ML models (Isolation Forest, LOF, StandardScaler) |
| **pandas** | Data loading and manipulation |
| **NumPy** | Numerical operations |
| **Pydantic** | Request/response validation |
| **python-dotenv** | Environment variable management |

### Frontend
| Technology | Purpose |
|------------|---------|
| **React 18** | UI framework |
| **Vite 5** | Build tool and dev server |
| **Tailwind CSS 3.4** | Utility-first styling |
| **Axios** | HTTP client for API calls |

### Database
| Technology | Purpose |
|------------|---------|
| **Neo4j** | Graph database for attack chain visualization (unchanged) |
| **MongoDB + Mongoose** | Document store for generated forensic incident reports only, owned by the Express gateway |
| **In-memory dicts** | Per-IP behavioral history, blocked IPs, honeypot state |

### Gateway
| Technology | Purpose |
|------------|---------|
| **Node.js 18+ / Express** | Single origin for the frontend; reverse proxies to Core/Ingestion |
| **http-proxy-middleware** | HTTP + WebSocket reverse proxying |
| **Mongoose** | MongoDB schema/ODM for the Reports API |

---

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/your-username/traceshield-x.git
cd traceshield-x

# Start everything (WSL/Linux)
chmod +x start.sh
./start.sh
```

Then open **http://localhost:5173** in your browser.

---

## 📦 Installation

### Prerequisites

- **Python** 3.10 or higher
- **Node.js** 18+ and npm
- **Neo4j Desktop** ([Download](https://neo4j.com/download/)) — optional but recommended
- **MongoDB Community Server** running on `127.0.0.1:27017` — optional; only needed to persist forensic reports via the Express gateway

### 1️⃣ Backend Setup

```bash
cd backend

# Create and activate virtual environment (recommended)
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the core backend server
uvicorn main:app --reload --port 8000
```

### 2️⃣ Ingestion Service Setup

```bash
cd ingestion

# Create and activate virtual environment (recommended)
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the ingestion server
uvicorn ingestion.main:app --reload --port 8001
```

### 3️⃣ Express Gateway Setup

```bash
cd server

# Install dependencies
npm install

cp .env.example .env

# Set your login credentials — generates a bcrypt hash for AUTH_PASSWORD_HASH in .env
node scripts/hash-password.js <your-password>
# Then edit .env: set AUTH_USERNAME, paste the hash into AUTH_PASSWORD_HASH,
# and set JWT_SECRET to a long random string.

# Start the gateway (proxies to Core/Ingestion, serves /api/reports)
npm run dev
```

> **Note:** If MongoDB is unreachable, the gateway logs a warning and keeps running — `/api/reports` returns `503` until MongoDB is back, everything else (proxying) is unaffected.

> **Note:** `/api/reports`, `/api/core/*` and `/api/ingest/*` require a JWT (`/api/health` and `/api/auth/login` are public). The frontend's login page handles this automatically — there's just one operator account, set above. The `/ws` WebSocket proxy is **not** authenticated (a Node implementation detail — upgrade requests bypass Express middleware).

### 4️⃣ Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start the dev server
npm run dev
```

Open **http://localhost:5173** in your browser. The frontend talks only to the Express Gateway (`VITE_API_URL`, default `http://localhost:5000`) — it never calls Core/Ingestion directly.

> From the repo root, `npm install && npm run dev:all` starts the Express Gateway and the frontend together via `concurrently`.

### 5️⃣ Neo4j Setup (Optional)

1. Download and install [Neo4j Desktop](https://neo4j.com/download/)
2. Create a new local DBMS and set a password
3. Start the database
4. Copy `.env.example` to `.env` and update with your credentials

> **Note:** If Neo4j is unavailable, the dashboard will use simulated graph data as a fallback.

### 6️⃣ MongoDB Setup (Optional)

1. Install MongoDB Community Server and make sure `mongod` is running on `127.0.0.1:27017`
2. No manual database/collection creation is needed — the gateway creates `traceshield.reports` on first write
3. `server/.env.example` already points at `mongodb://127.0.0.1:27017/traceshield` by default

> **Note:** MongoDB only stores forensic reports generated from the Threat Hunt page. It is never used by Neo4j, the ML models, or the Python services.

### 7️⃣ Dataset (Optional)

Place a real intrusion CSV at:
```
backend/data/intrusion_data.csv
```

**Required columns:**
| Column | Type | Description |
|--------|------|-------------|
| `login_attempts` | int | Total login attempts |
| `failed_logins` | int | Number of failed logins |
| `session_duration` | float | Session length in seconds |
| `ip_reputation_score` | float | IP reputation (0 = clean, 1 = malicious) |
| `unusual_time_access` | int | 1 if access occurred at unusual hours |

> If no dataset is provided, the system automatically generates 5,000 synthetic training logs (80% normal, 20% attack).

---

## 🔧 Configuration

### Environment Variables

Copy the example file and adjust values:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `neo4j://127.0.0.1:7687` | Neo4j Bolt connection URI |
| `NEO4J_USER` | `TraceShieldDB` | Neo4j username |
| `NEO4J_PASSWORD` | `12345678` | Neo4j password |
| `MONGO_URI` | `mongodb://127.0.0.1:27017/traceshield` | MongoDB connection string — reports only |

`server/.env.example` additionally defines `PORT` (gateway port, default `5000`), `CORE_URL` (`http://127.0.0.1:8000`), `INGEST_URL` (`http://127.0.0.1:8001`), and the auth settings `JWT_SECRET`, `JWT_EXPIRES_IN` (default `12h`), `AUTH_USERNAME`, and `AUTH_PASSWORD_HASH` (bcrypt — generate with `node scripts/hash-password.js <password>`). `frontend/.env.example` defines `VITE_API_URL` (default `http://localhost:5000`) — the single origin the frontend talks to.

---

## 📡 API Reference

### Core Backend — `:8000`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/api/analyze` | Analyze a random sample from the intrusion dataset |
| `POST` | `/api/simulate` | Generate and analyze simulated attack logs |
| `GET` | `/api/graph` | Fetch the full Neo4j attack graph |
| `DELETE` | `/api/graph/clear` | Clear all nodes and relationships in the graph |
| `GET` | `/api/status` | System status (model loaded, Neo4j connected, etc.) |
| `GET` | `/api/health` | Detailed health check with component statuses |

### Ingestion Service — `:8001`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/ingest` | Ingest a real-time network event for analysis |
| `GET` | `/health` | Service health check |
| `GET` | `/blocked` | View all blocked, flagged, and honeypotted IPs |
| `GET` | `/graph` | All attack relationships in the graph |
| `GET` | `/graph/attacks` | Recent attack events with full metadata |
| `GET` | `/graph/ip/{ip}` | Complete history for a specific IP address |
| `GET` | `/graph/chain/{ip}` | Full attack chain path (IP → Device → Honeypot → System) |
| `GET` | `/graph/summary` | Graph statistics (node counts, relationship counts) |

#### Example: Ingest an Event

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

#### Example Response

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
traceshield/
│
├── backend/                          # Core backend service (:8000)
│   ├── main.py                       # FastAPI app with lifespan (model training at startup)
│   ├── requirements.txt              # Python dependencies
│   ├── api/
│   │   └── routes.py                 # All REST API endpoint definitions
│   ├── core/
│   │   ├── ml_model.py               # Isolation Forest model (train + predict)
│   │   ├── detection.py              # Rule-based threat detection engine
│   │   ├── risk.py                   # Adaptive Forensic Risk Scoring (AFRS)
│   │   ├── simulation.py             # Synthetic log generator for training
│   │   ├── graph_builder.py          # Neo4j graph construction
│   │   ├── summarizer.py             # AI-style forensic report generator
│   │   └── neo4j_db.py               # Neo4j connection manager
│   └── data/                         # Dataset directory (CSV files)
│
├── ingestion/                        # Real-time ingestion service (:8001)
│   ├── main.py                       # FastAPI app for event ingestion
│   ├── requirements.txt              # Python dependencies
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
│       ├── anomaly.py                # Anomaly data structures
│       ├── risk_engine.py            # 5-component weighted risk scoring
│       ├── response_engine.py        # Automated response (flag/block/honeypot)
│       ├── ip_memory.py              # Per-IP sliding window memory
│       ├── log_parser.py             # General log parser
│       └── linux_log_parser.py       # Linux syslog parser
│
├── frontend/                         # React frontend (:5173)
│   ├── index.html                    # Entry HTML
│   ├── package.json                  # npm dependencies
│   ├── vite.config.js                # Vite configuration
│   ├── tailwind.config.js            # Tailwind CSS configuration
│   ├── postcss.config.js             # PostCSS configuration
│   └── src/
│       ├── main.jsx                  # Auth gate (LoginPage vs App) + React entry point
│       ├── App.jsx                   # Main app — routing & state management
│       ├── index.css                 # Global styles & design system
│       ├── services/
│       │   └── api.js                # Single axios instance (attaches JWT, handles 401) + core()/ingest() helpers + WS_URL
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
├── server/                            # Express gateway (:5000)
│   ├── index.js                       # App setup, auth, proxies, /api/health
│   ├── package.json                   # npm dependencies
│   ├── config/
│   │   └── db.js                      # Mongoose connect, graceful degradation
│   ├── middleware/
│   │   └── auth.js                    # requireAuth — JWT verification
│   ├── models/
│   │   └── Report.js                  # Forensic report schema (unique incidentId)
│   ├── routes/
│   │   ├── auth.js                    # POST /api/auth/login
│   │   ├── reports.js                 # Reports API (CRUD, MongoDB-backed, JWT-protected)
│   │   └── proxies.js                 # /api/core, /api/ingest, /ws reverse proxies (JWT-protected, except /ws)
│   ├── scripts/
│   │   └── hash-password.js           # Generates a bcrypt hash for AUTH_PASSWORD_HASH
│   └── test/
│       └── reports.test.js            # node:test + fetch, against traceshield_test
│
├── .env.example                      # Environment variable template (Neo4j + MongoDB)
├── .gitignore                        # Git ignore rules
├── start.sh                          # Quick start script (WSL/Linux)
├── package.json                      # Root: `npm run dev:all` (concurrently: server + frontend)
├── patch_neo4j.py                    # Neo4j schema patch utility
├── test_logs.py                      # Log testing script
├── test_upload.py                    # Upload testing script
└── EXPLANATION.md                    # Full technical deep-dive documentation
```

---

## 🧪 Testing

### Run Log Tests

```bash
python test_logs.py
```

### Run Upload Tests

```bash
python test_upload.py
```

### Test Ingestion Service Manually

```bash
cd ingestion
chmod +x test_ingest.sh
./test_ingest.sh
```

### Verify System Status

```bash
# Check core backend
curl http://localhost:8000/api/health

# Check ingestion service
curl http://localhost:8001/health
```

---

## 🔒 Security

| Measure | Implementation |
|---------|---------------|
| **Credential Management** | `.env` excluded from git; credentials loaded from environment variables only |
| **CORS** | Restricted to `localhost:5173` and `localhost:3000` |
| **Input Validation** | All endpoints validated via Pydantic models |
| **Query Safety** | All Neo4j queries use parameterized statements — no injection risk |
| **Simulated Responses** | No real network blocking or traffic manipulation — all response actions are simulated |

---

## 🧩 Extensibility

TraceShield X++ is designed as a modular platform. Here's how to extend each layer:

| Extension | How To |
|-----------|--------|
| 🤖 **Add a new ML model** | Replace `get_ml_score()` in `ingestion/services/ml_model.py` |
| 🔍 **Add a detection rule** | Add a new condition block in `backend/core/detection.py` |
| 🚫 **Real IP blocking** | Replace simulation in `response_engine._block_ip()` with firewall API calls (e.g., iptables, AWS WAF) |
| 🍯 **Real honeypot** | Replace `_redirect_honeypot()` with actual honeypot integration (e.g., Cowrie, T-Pot) |
| 🕸️ **New graph relationship** | Add a function in `ingestion/db/neo4j.py` following the existing MERGE pattern |
| 📡 **Streaming ingestion** | Replace `/ingest` POST with WebSocket or Kafka consumer |
| 📊 **Real dataset** | Drop a CSV at `backend/data/intrusion_data.csv` — system auto-detects it |
| 🐧 **Linux log parsing** | Feed auth.log or syslog files through `services/linux_log_parser.py` |

---

## 📚 Documentation

For a comprehensive technical deep-dive covering every algorithm, model hyperparameter, scoring formula, and design decision, see:

📖 **[EXPLANATION.md](./EXPLANATION.md)** — Full Technical Reference

---

## 👥 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](./LICENSE) file for details.

---

<p align="center">
  Built with 🔥 by the TraceShield Team
</p>

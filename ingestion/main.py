"""
main.py — FastAPI entry point for the TraceShield ingestion service.
Real-time anomaly detection with unified risk scoring and Neo4j storage.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from ingestion.models.schemas import IngestPayload, IngestResponse, ResponseDetail
from ingestion.services.anomaly_detector import process_event
from ingestion.services.ml_model import get_ml_score, load_model, reload_model, is_loaded
from ingestion.services.response_engine import (
    get_full_state,
    unblock as response_unblock,
    reset_state as response_reset,
)
from ingestion.services.ip_memory import reset_state as memory_reset
from ingestion.services.risk_engine import reset_state as risk_reset
from ingestion.services.log_parser import (
    parse_log_lines,
    ingest_logs_for_ip,
    get_ip_log_summary,
    reset_state as log_reset,
)
from ingestion.services.linux_log_parser import analyze_log_dataset, analyze_privilege_escalation
from ingestion.services.ml_training import (
    train as ml_train,
    evaluate as ml_evaluate,
)
from ingestion.db.neo4j import (
    get_all_relationships,
    get_recent_attacks,
    get_ip_history,
    get_graph_summary,
    get_attack_chain,
    close_driver as close_neo4j,
)
from ingestion.db.neo4j_conn import close_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Ingestion service starting...")
    loaded = load_model()
    if loaded:
        logger.info("ML model ready. Service online.")
    else:
        logger.warning(
            "Service starting WITHOUT ML model. "
            "Fallback scoring active. POST /ml/train to enable ML."
        )
    yield
    close_driver()
    close_neo4j()
    logger.info("Ingestion service shut down.")


app = FastAPI(
    title="TraceShield Ingestion API",
    description="Real-time cybersecurity event ingestion with unified risk scoring.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "online", "service": "TraceShield Ingestion API v2.0"}


@app.post("/ingest", response_model=IngestResponse)
async def ingest(payload: IngestPayload) -> IngestResponse:
    """
    Ingest a single network event and run real-time unified risk scoring.
    Broadcasts result to all connected WebSocket clients.
    """
    try:
        ts = payload.timestamp or datetime.now(timezone.utc).replace(tzinfo=None)
        result = process_event(
            ip=payload.ip,
            device=payload.device,
            request_count=payload.request_count,
            timestamp=ts,
        )
        response_obj = IngestResponse(
            status=result["status"],
            risk_score=result["risk_score"],
            message=result["message"],
            ip=payload.ip,
            device=payload.device,
            request_count=payload.request_count,
            timestamp=ts,
            graph_stored=result["graph_stored"],
            components=result["components"],
            response=result["response"],
            attack_type=result.get("attack_type", "NORMAL_ACTIVITY"),
        )
        # Broadcast to WebSocket clients (non-blocking)
        ws_payload = {
            "ip":           payload.ip,
            "device":       payload.device,
            "request_count": payload.request_count,
            "status":       result["status"],
            "risk_score":   result["risk_score"],
            "attack_type":  result.get("attack_type", "NORMAL_ACTIVITY"),
            "actions":      result["response"].get("actions_taken", []),
            "reason":       result["response"].get("reason", "N/A"),
            "log_score":    result["components"].get("log_score", 0),
            "ml_score":     result["components"].get("ml_score", 0),
            "timestamp":    ts.isoformat(),
        }
        await _ws_manager.broadcast(ws_payload)
        _store_event(ws_payload)
        return response_obj
    except Exception as exc:
        logger.error("Ingest error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


import json
from collections import deque
from typing import List as WsList

# ── In-memory event store (persists across requests, max 100 events) ──────────
_event_store: deque = deque(maxlen=100)


def _store_event(payload: dict) -> None:
    """Append event to store, newest first."""
    _event_store.appendleft(payload)

# ── WebSocket connection manager ──────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active: WsList[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active = [c for c in self.active if c != ws]

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


_ws_manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming."""
    await _ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()   # keep alive
    except WebSocketDisconnect:
        _ws_manager.disconnect(websocket)


@app.get("/events/recent")
def events_recent(limit: int = 50):
    """Return the most recent processed events (max 100)."""
    limit = min(max(limit, 1), 100)
    return {"events": list(_event_store)[:limit]}


# ── Log ingestion endpoints ───────────────────────────────────────────────────

class LogIngestRequest(BaseModel):
    ip: str
    log_lines: list[str]


@app.post("/ingest/logs")
def ingest_logs(body: LogIngestRequest):
    """
    Ingest Linux log lines for a specific IP.
    Updates per-IP log state used in hybrid risk scoring.
    Always call this BEFORE /ingest for the same IP to ensure
    log signals are available during scoring.
    """
    result = ingest_logs_for_ip(body.ip, body.log_lines)
    logger.info("LOG INGEST | ip=%s lines=%d log_score=%.2f",
                body.ip, len(body.log_lines), result["log_score"])
    return {"ip": body.ip, "lines_parsed": len(body.log_lines), **result}


@app.get("/logs/{ip_address}")
def get_log_summary(ip_address: str):
    """Return aggregated log signals for a specific IP."""
    return {"ip": ip_address, "log_summary": get_ip_log_summary(ip_address)}


# ── Dataset log analysis endpoint ─────────────────────────────────────────────

class DatasetLogsRequest(BaseModel):
    log_lines: list[str]


@app.post("/analyze/priv-esc")
async def analyze_priv_esc(body: DatasetLogsRequest):
    """
    Dedicated privilege escalation analysis endpoint.
    Accepts raw log lines (no IP required) and returns per-actor breakdown
    with exact attack lines, timestamps, and attack type classification.
    """
    try:
        if not body.log_lines:
            raise HTTPException(status_code=400, detail="log_lines must not be empty")
        result = analyze_privilege_escalation(body.log_lines)
        logger.info(
            "PRIV_ESC | lines=%d priv_esc_events=%d actors_attacked=%d",
            result["summary"]["total_lines"],
            result["summary"]["priv_esc_events"],
            result["summary"]["actors_attacked"],
        )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("analyze/priv-esc error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))



    """
    Analyze a batch of raw Linux log lines from any log format.

    All scoring flows through the unified pipeline:
      linux_log_parser → aggregate per-IP → process_event() → broadcast WS

    Input:  { "log_lines": ["<raw log line>", ...] }
    Output: { "summary": {...}, "results": [{ip, risk_score, status, ...}] }
    """
    try:
        if not body.log_lines:
            raise HTTPException(status_code=400, detail="log_lines must not be empty")

        # Step 1: parse + aggregate per-IP using linux_log_parser
        from ingestion.services.linux_log_parser import parse_lines, aggregate_by_ip, compute_request_count, build_reason
        events, total, valid = parse_lines(body.log_lines)
        by_ip = aggregate_by_ip(events)

        logger.info(
            "DATASET/LOGS | lines=%d valid=%d unique_ips=%d",
            total, valid, len(by_ip),
        )

        results = []
        anomaly_count = 0

        for raw_ip, features in by_ip.items():
            # Remap "unknown" to a meaningful synthetic identifier
            ip = "host_system" if (raw_ip == "unknown" or features.get("is_unknown")) else raw_ip

            # Seed per-IP log state BEFORE process_event — guarantees log signals
            # are available during scoring regardless of whether IP was in the line
            all_lines = [ev["raw"] for ev in events if ev.get("ip") == raw_ip]
            ingest_logs_for_ip(ip, all_lines)

            # Run through the unified pipeline (same as /ingest)
            ts = datetime.now(timezone.utc).replace(tzinfo=None)
            result = process_event(
                ip=ip,
                device="dataset_log",
                request_count=compute_request_count(features),
                timestamp=ts,
            )

            status      = result["status"]
            score       = result["risk_score"]
            response    = result["response"]
            attack_type = result.get("attack_type", "NORMAL_ACTIVITY")

            if status != "NORMAL":
                anomaly_count += 1

            # Broadcast to WebSocket clients immediately
            ws_payload = {
                "ip":            ip,
                "device":        "dataset_log",
                "request_count": features.get("total_events", 1),
                "status":        status,
                "risk_score":    score,
                "attack_type":   attack_type,
                "actions":       response.get("actions_taken", []),
                "reason":        response.get("reason", "N/A"),
                "log_score":     result["components"].get("log_score", 0),
                "ml_score":      result["components"].get("ml_score", 0),
                "timestamp":     ts.isoformat(),
                "usernames":     features.get("usernames", []),
                "log_signals":   build_reason(features),
            }
            await _ws_manager.broadcast(ws_payload)
            _store_event(ws_payload)
            await asyncio.sleep(0.075)

            results.append({
                "ip":          ip,
                "risk_score":  score,
                "status":      status,
                "attack_type": attack_type,
                "actions":     response.get("actions_taken", []),
                "reason":      response.get("reason", "N/A"),
                "features":    features,
                "components":  result["components"],
            })

        # Sort by risk_score descending
        results.sort(key=lambda r: r["risk_score"], reverse=True)

        logger.info(
            "DATASET/LOGS DONE | ips=%d anomalies=%d",
            len(by_ip), anomaly_count,
        )

        return {
            "summary": {
                "total_lines":  total,
                "valid_events": valid,
                "unique_ips":   len(by_ip),
                "anomalies":    anomaly_count,
            },
            "results": results,
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("dataset/logs error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/dataset/upload")
async def dataset_upload(file: UploadFile = File(...)):
    """
    Upload a Linux log file directly (auth.log, syslog, audit.log, etc.).
    Processes it through the same pipeline as /dataset/logs.

    Accepts: any .log, .txt, or plain text file.
    """
    try:
        content = await file.read()
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")  # fallback for non-UTF8 logs

        lines = text.splitlines()
        logger.info("DATASET/UPLOAD | file=%s lines=%d", file.filename, len(lines))

        # Reuse the same dataset/logs logic
        from ingestion.services.linux_log_parser import parse_lines, aggregate_by_ip, compute_request_count, build_reason
        events, total, valid = parse_lines(lines)
        by_ip = aggregate_by_ip(events)

        # Reset previous per-IP log and memory state so this file is evaluated independently
        from ingestion.services.log_parser import reset_state as reset_log_state
        from ingestion.services.ip_memory import reset_state as reset_ip_memory
        from ingestion.services.response_engine import reset_state as reset_response_state
        reset_log_state()
        reset_ip_memory()
        reset_response_state()

        results = []
        anomaly_count = 0

        for raw_ip, features in by_ip.items():
            # Remap "unknown" to synthetic identifier — process through full pipeline
            ip = "host_system" if (raw_ip == "unknown" or features.get("is_unknown")) else raw_ip

            # Seed per-IP log state BEFORE process_event
            all_lines = [ev["raw"] for ev in events if ev.get("ip") == raw_ip]
            ingest_logs_for_ip(ip, all_lines)

            ts = datetime.now(timezone.utc).replace(tzinfo=None)
            result = process_event(
                ip=ip,
                device=f"upload:{file.filename}",
                request_count=compute_request_count(features),
                timestamp=ts,
                skip_block_check=True,
            )

            status      = result["status"]
            score       = result["risk_score"]
            response    = result["response"]
            attack_type = result.get("attack_type", "NORMAL_ACTIVITY")

            if status != "NORMAL":
                anomaly_count += 1

            results.append({
                "ip":          ip,
                "risk_score":  score,
                "status":      status,
                "attack_type": attack_type,
                "actions":     response.get("actions_taken", []),
                "reason":      response.get("reason", "N/A"),
                "features":    features,
                "components":  result["components"],
            })

        results.sort(key=lambda r: r["risk_score"], reverse=True)

        logger.info("DATASET/UPLOAD DONE | file=%s ips=%d anomalies=%d",
                    file.filename, len(by_ip), anomaly_count)

        return {
            "filename": file.filename,
            "summary": {
                "total_lines":  total,
                "valid_events": valid,
                "unique_ips":   len(by_ip),
                "anomalies":    anomaly_count,
            },
            "results": results,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("dataset/upload error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ── ML training endpoints ─────────────────────────────────────────────────────

@app.post("/ml/train")
def ml_train_endpoint():
    """
    Train the Isolation Forest on 8 unified features and save to disk.
    Reloads model into memory immediately after training.
    """
    try:
        ml_train(csv_path=None, save=True)
        success = reload_model()
        if not success:
            raise RuntimeError("Model saved but failed to reload from disk.")
        return {
            "status":       "trained",
            "model_loaded": True,
            "features":     8,
            "feature_cols": ["request_count","requests_per_second","spike_score",
                             "trend_score","failed_logins","sudo_attempts",
                             "suspicious_commands","sensitive_file_access"],
            "message":      "Model trained on 8 unified features, saved and reloaded.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ml/status")
def ml_status():
    """Return current ML model load status."""
    return {
        "model_loaded": is_loaded(),
        "feature_count": 8,
        "feature_cols": ["request_count","requests_per_second","spike_score",
                         "trend_score","failed_logins","sudo_attempts",
                         "suspicious_commands","sensitive_file_access"],
        "message": (
            "Model loaded and ready for inference."
            if is_loaded() else
            "Model not loaded. POST /ml/train to train and load."
        ),
    }


@app.get("/ml/evaluate")
def ml_evaluate_endpoint():
    """Evaluate the trained model and return anomaly metrics."""
    try:
        result = ml_evaluate(csv_path=None)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/blocked")
def blocked_list():
    """Return full in-memory response state with timestamps and reasons."""
    return get_full_state()


@app.delete("/blocked/{ip_address}")
def unblock_ip(ip_address: str):
    """Lift a single IP's block ahead of its cooldown."""
    if not response_unblock(ip_address):
        raise HTTPException(status_code=404, detail=f"{ip_address} is not blocked")
    return {"ip": ip_address, "unblocked": True}


@app.post("/state/reset")
def reset_state():
    """
    Clear all in-memory detection state — blocks, honeypots, flags, per-IP log
    signals and behavioural history.

    Log signals and block state persist for the life of the process, so without
    this an earlier run keeps skewing later ones: a blocked IP short-circuits to
    a canned score of 100 instead of being scored on the data just submitted.
    """
    response_counts = response_reset()
    cleared = {
        **response_counts,
        "log_signal_ips": log_reset(),
        "history_ips":    memory_reset(),
        "rate_windows":   risk_reset(),
        "events":         len(_event_store),
    }
    _event_store.clear()
    logger.warning("STATE RESET | cleared=%s", cleared)
    return {"reset": True, "cleared": cleared}


@app.get("/graph")
def graph_all():
    """Fetch all Neo4j relationships for visualization."""
    return {"relationships": get_all_relationships(100)}


@app.get("/graph/attacks")
def graph_attacks():
    """Fetch recent ATTACKED relationships with metadata."""
    return {"attacks": get_recent_attacks(20)}


@app.get("/graph/ip/{ip_address}")
def graph_ip(ip_address: str):
    """Fetch all graph relationships for a specific IP."""
    return {"ip": ip_address, "history": get_ip_history(ip_address)}


@app.get("/graph/chain/{ip_address}")
def graph_chain(ip_address: str):
    """Fetch full attack chain path for an IP (IP → Device → Honeypot → System)."""
    return {"ip": ip_address, "chain": get_attack_chain(ip_address)}


@app.get("/graph/summary")
def graph_summary():
    """Return node and relationship counts."""
    return get_graph_summary()

"""
main.py — FastAPI entry point for TraceShield X++
Trains the ML model on startup and mounts all API routes.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

try:
    from backend.core.ml_model import train_model
    from backend.api.routes import router
except ImportError:
    from core.ml_model import train_model
    from api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Train ML model and store state before serving requests."""
    model, scaler, df = train_model()
    app.state.model  = model
    app.state.scaler = scaler
    app.state.df     = df
    yield


app = FastAPI(title="TraceShield X++ API", lifespan=lifespan)

import os

allowed_env = os.getenv("ALLOWED_ORIGINS", os.getenv("ALLOWED_ORIGIN", ""))
backend_origins = [
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:3000", "http://127.0.0.1:3000",
    "https://trace-shield-x.vercel.app",
]
if allowed_env:
    backend_origins.extend([o.strip() for o in allowed_env.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(set(backend_origins)),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {"status": "online", "system": "TraceShield X++"}


@app.get("/health")
def health():
    """Lightweight uptime-monitor target (e.g. cron-job.org keep-alive pings)."""
    return {"status": "ok"}

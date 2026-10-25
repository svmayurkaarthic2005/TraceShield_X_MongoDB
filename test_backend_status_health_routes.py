"""
Regression test for the /api/status vs /api/health route-shadowing fix
(backend/api/routes.py).

Background: `/status` used to be registered by TWO route handlers — the
first (line ~414) returning {neo4j, model_loaded, dataset_rows} and
occasionally raising an uncaught 500, and a second handler (originally
decorated with BOTH @router.get("/status") and @router.get("/health"))
whose graceful-degrade behavior was always unreachable for "/status"
because FastAPI/Starlette dispatch to the FIRST registered match. The fix:
removed the duplicate "/status" decorator from the second handler (it now
only serves "/health"), and made the real "/status" handler degrade
gracefully (dataset_rows: None instead of a 500) when app.state.df/model
aren't set yet, without a blanket try/except that could hide unrelated bugs.

No test framework is used elsewhere in this repo (see test_log_parser_
classification.py, test_risk_engine_weak_signal_policy.py) — this follows
the same plain-script-with-assertions convention, using fastapi.testclient
(already a transitive dependency of fastapi, itself already required by
backend/requirements.txt — nothing new installed to run this).

This machine's backend/venv is a broken Linux-created venv (bin/python is
a dangling symlink), so this was actually executed with the ingestion
service's native Windows venv (ingestion/venv_win), which already has the
same fastapi/httpx/pandas/scikit-learn/neo4j dependencies backend/requirements.txt
lists — nothing new installed. Run with:
    ingestion/venv_win/Scripts/python.exe test_backend_status_health_routes.py
"""
import sys

sys.stdout.reconfigure(encoding="utf-8")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.main import app as full_app
from backend.api.routes import router

passed = 0


def check(name, condition):
    global passed
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        raise AssertionError(name)
    passed += 1


# ── Test D: route registration — exactly one handler per path, no shadowing ──
status_routes = [r for r in router.routes if getattr(r, "path", None) == "/status"]
health_routes = [r for r in router.routes if getattr(r, "path", None) == "/health"]

check("exactly one /status route is registered (no duplicate)", len(status_routes) == 1)
check("exactly one /health route is registered", len(health_routes) == 1)
check("/status is served by the `status` handler", status_routes[0].endpoint.__name__ == "status")
check("/health is served by the `health` handler", health_routes[0].endpoint.__name__ == "health")
check(
    "/status and /health are two distinct handler functions (no shadowing)",
    status_routes[0].endpoint is not health_routes[0].endpoint,
)

# ── Test A: normal /api/status — full app with lifespan (real df/model) ──
with TestClient(full_app) as client:
    r = client.get("/api/status")
    check("GET /api/status returns 200 under normal operation", r.status_code == 200)
    body = r.json()
    check("response has neo4j/model_loaded/dataset_rows keys", set(body) == {"neo4j", "model_loaded", "dataset_rows"})
    check("neo4j is a bool", isinstance(body["neo4j"], bool))
    check("model_loaded is True once the lifespan has trained a model", body["model_loaded"] is True)
    check("dataset_rows is a positive int", isinstance(body["dataset_rows"], int) and body["dataset_rows"] > 0)

    # ── Test C (part 1): /api/health works on the same fully-started app ──
    r = client.get("/api/health")
    check("GET /api/health returns 200 on the fully-started app", r.status_code == 200)
    hbody = r.json()
    check("/api/health response has status=ok", hbody.get("status") == "ok")
    check("/api/health does not include dataset_rows (distinct contract from /status)", "dataset_rows" not in hbody)

# ── Test B: /api/status when dataset/model state is unavailable ──
# A bare app with the router mounted but no lifespan — app.state.df/model
# are never set, exercising exactly the code path that used to raise 500.
bare_app = FastAPI()
bare_app.include_router(router, prefix="/api")
with TestClient(bare_app) as client:
    r = client.get("/api/status")
    check("GET /api/status returns 200 (not 500) when df/model are unset", r.status_code == 200)
    body = r.json()
    check("dataset_rows is None when the dataset isn't loaded (graceful degrade)", body["dataset_rows"] is None)
    check("model_loaded is False when the model isn't loaded", body["model_loaded"] is False)
    check("neo4j is still a bool (test_connection() never raises)", isinstance(body["neo4j"], bool))

    # ── Test C (part 2): /api/health is independent of /status's dataset requirement ──
    r = client.get("/api/health")
    check("GET /api/health returns 200 even with no df/model set", r.status_code == 200)
    hbody = r.json()
    check("/api/health still reports status=ok with nothing loaded", hbody.get("status") == "ok")

print(f"\nAll {passed} checks passed.")

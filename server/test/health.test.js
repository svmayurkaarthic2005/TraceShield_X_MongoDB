// Focused regression test for the F3 gateway fix: GET /api/health must probe
// the ingestion service's dedicated /health route, not its root "/".
//
// Spins up a tiny mock ingestion server that returns 200 on /health and 404
// on every other path (including "/") — so if the gateway were still hitting
// "/" (the pre-fix behavior), `ingestion` would incorrectly read false here.
// CORE_URL points at an unreachable port so `core` is deterministically
// false, independent of anything this test needs to assert. MONGO_URI is
// left unset so connectMongo() short-circuits immediately (see
// server/config/db.js) instead of waiting out a real connection attempt —
// this test doesn't need MongoDB running.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GATEWAY_PORT = 5998;
const BASE = `http://127.0.0.1:${GATEWAY_PORT}`;

let mockIngestion;
let mockIngestionUrl;
let serverProcess;

before(async () => {
  mockIngestion = createServer((req, res) => {
    if (req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ detail: "Not Found" }));
    }
  });
  await new Promise((resolve) => mockIngestion.listen(0, "127.0.0.1", resolve));
  const { port } = mockIngestion.address();
  mockIngestionUrl = `http://127.0.0.1:${port}`;

  serverProcess = spawn(process.execPath, ["index.js"], {
    cwd: path.join(__dirname, ".."),
    env: {
      ...process.env,
      PORT: String(GATEWAY_PORT),
      MONGO_URI: "",
      CORE_URL: "http://127.0.0.1:19997", // deliberately unreachable
      INGEST_URL: mockIngestionUrl,
      JWT_SECRET: "test-only-secret",
    },
    stdio: "pipe",
  });

  const deadline = Date.now() + 10000;
  let up = false;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/api/health`);
      if (r.ok) { up = true; break; }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!up) throw new Error("gateway did not come up within 10s");
});

after(async () => {
  serverProcess.kill();
  mockIngestion.close();
});

test("GET /api/health reports ingestion up when its /health route (not root) responds 2xx", async () => {
  const r = await fetch(`${BASE}/api/health`);
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.ingestion, true, "gateway must have probed /health (which this mock answers), not / (which 404s)");
});

test("GET /api/health reports core down when unreachable, independent of the ingestion probe", async () => {
  const r = await fetch(`${BASE}/api/health`);
  const body = await r.json();
  assert.equal(body.core, false);
  assert.equal(body.neo4j, false, "neo4j is only checked via Core's /api/status, which is skipped when core is down");
});

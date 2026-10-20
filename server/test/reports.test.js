import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import bcrypt from "bcryptjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 5999;
const BASE = `http://127.0.0.1:${PORT}`;
const MONGO_URI = "mongodb://127.0.0.1:27017/traceshield_test";
const INCIDENT_ID = "INC-TEST-REPORTS-1";
const TEST_USERNAME = "test-user";
const TEST_PASSWORD = "test-password-123";

let serverProcess;
let authHeaders;

before(async () => {
  serverProcess = spawn(process.execPath, ["index.js"], {
    cwd: path.join(__dirname, ".."),
    env: {
      ...process.env,
      PORT: String(PORT),
      MONGO_URI,
      CORE_URL: "http://127.0.0.1:19999",
      INGEST_URL: "http://127.0.0.1:19998",
      AUTH_USERNAME: TEST_USERNAME,
      AUTH_PASSWORD_HASH: bcrypt.hashSync(TEST_PASSWORD, 10),
      JWT_SECRET: "test-only-secret",
    },
    stdio: "pipe",
  });

  const deadline = Date.now() + 15000;
  let up = false;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/api/health`);
      if (r.ok && (await r.json()).mongo) { up = true; break; }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  if (!up) throw new Error("server did not come up with MongoDB connected within 15s — is mongod running on 127.0.0.1:27017?");

  const loginRes = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: TEST_USERNAME, password: TEST_PASSWORD }),
  });
  const { token } = await loginRes.json();
  assert.ok(token, "login should return a JWT for the reports tests to use");
  authHeaders = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
});

after(async () => {
  try {
    await fetch(`${BASE}/api/reports/${INCIDENT_ID}`, { method: "DELETE", headers: authHeaders });
  } catch {}
  serverProcess.kill();
});

test("POST /api/reports requires a valid JWT", async () => {
  const r = await fetch(`${BASE}/api/reports`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ incidentId: INCIDENT_ID, severity: "HIGH", attackerIp: "10.0.0.1" }),
  });
  assert.equal(r.status, 401);
});

test("POST /api/reports upserts by incidentId", async () => {
  const payload = { incidentId: INCIDENT_ID, severity: "HIGH", attackerIp: "10.0.0.1", summary: "first" };

  const r1 = await fetch(`${BASE}/api/reports`, {
    method: "POST",
    headers: authHeaders,
    body: JSON.stringify(payload),
  });
  assert.equal(r1.status, 200);
  const d1 = await r1.json();
  assert.equal(d1.incidentId, INCIDENT_ID);
  assert.equal(d1.summary, "first");

  const r2 = await fetch(`${BASE}/api/reports`, {
    method: "POST",
    headers: authHeaders,
    body: JSON.stringify({ ...payload, summary: "updated" }),
  });
  assert.equal(r2.status, 200);
  const d2 = await r2.json();
  assert.equal(d2._id, d1._id, "re-posting the same incidentId should update the existing document, not create a new one");
  assert.equal(d2.summary, "updated");
});

test("GET /api/reports lists newest first with summary fields only", async () => {
  const r = await fetch(`${BASE}/api/reports?limit=20`, { headers: authHeaders });
  assert.equal(r.status, 200);
  const list = await r.json();
  assert.ok(Array.isArray(list));

  const found = list.find((item) => item.incidentId === INCIDENT_ID);
  assert.ok(found, "inserted report should appear in the list");
  assert.equal(found.severity, "HIGH");
  assert.equal(found.summary, undefined, "list endpoint should project summary fields only");
});

test("POST /api/reports returns 400 when required fields are missing", async () => {
  const r = await fetch(`${BASE}/api/reports`, {
    method: "POST",
    headers: authHeaders,
    body: JSON.stringify({ severity: "HIGH" }),
  });
  assert.equal(r.status, 400);
  const body = await r.json();
  assert.ok(body.error);
});

test("DELETE /api/reports/:id removes the report", async () => {
  const del = await fetch(`${BASE}/api/reports/${INCIDENT_ID}`, { method: "DELETE", headers: authHeaders });
  assert.equal(del.status, 204);

  const getAfter = await fetch(`${BASE}/api/reports/${INCIDENT_ID}`, { headers: authHeaders });
  assert.equal(getAfter.status, 404);
});

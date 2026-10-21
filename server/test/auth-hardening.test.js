import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 5998;
const BASE = `http://127.0.0.1:${PORT}`;
const MONGO_URI = "mongodb://127.0.0.1:27017/traceshield_test_auth";
const TEST_USERNAME = "test-admin";
const TEST_PASSWORD = "correct-horse-battery-staple";

let serverProcess;

before(async () => {
  // Start from a clean DB each run — a stale AuthState/LoginAudit from a
  // previous run would make the lockout/audit assertions below flaky.
  await mongoose.connect(MONGO_URI);
  await mongoose.connection.db.dropDatabase();
  await mongoose.disconnect();

  serverProcess = spawn(process.execPath, ["index.js"], {
    cwd: path.join(__dirname, ".."),
    env: {
      ...process.env,
      PORT: String(PORT),
      MONGO_URI,
      CORE_URL: "http://127.0.0.1:19997",
      INGEST_URL: "http://127.0.0.1:19996",
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
  if (!up) throw new Error("server did not come up with MongoDB connected within 15s");
});

after(async () => {
  serverProcess.kill();
  await mongoose.connect(MONGO_URI);
  await mongoose.connection.db.dropDatabase();
  await mongoose.disconnect();
});

async function login(username, password) {
  const r = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return { status: r.status, body: await r.json() };
}

test("correct credentials succeed and issue a JWT", async () => {
  const { status, body } = await login(TEST_USERNAME, TEST_PASSWORD);
  assert.equal(status, 200);
  assert.ok(body.token);
});

test("wrong password is rejected with 401, not a crash", async () => {
  const { status, body } = await login(TEST_USERNAME, "wrong-password");
  assert.equal(status, 401);
  assert.ok(body.error);
});

test("every login attempt (success and failure) is recorded in the audit log", async () => {
  const { body: loginBody } = await login(TEST_USERNAME, TEST_PASSWORD);
  const headers = { Authorization: `Bearer ${loginBody.token}` };
  const r = await fetch(`${BASE}/api/auth/audit?limit=10`, { headers });
  assert.equal(r.status, 200);
  const { entries } = await r.json();
  assert.ok(entries.length >= 2, "expects at least the success+failure attempts from earlier tests");
  assert.ok(entries.every((e) => typeof e.success === "boolean"));
  assert.ok(entries.every((e) => !("password" in e)), "audit entries must never store the attempted password");
});

test("rate limiting returns 429 before even checking credentials (separate from account lockout)", async () => {
  // A fresh server process (separate before/after block) so this isn't
  // entangled with the lockout test's account state.
  const port = 5997;
  const base = `http://127.0.0.1:${port}`;
  const uri = "mongodb://127.0.0.1:27017/traceshield_test_auth_ratelimit";
  await mongoose.connect(uri);
  await mongoose.connection.db.dropDatabase();
  await mongoose.disconnect();

  const proc = spawn(process.execPath, ["index.js"], {
    cwd: path.join(__dirname, ".."),
    env: {
      ...process.env,
      PORT: String(port),
      MONGO_URI: uri,
      CORE_URL: "http://127.0.0.1:19995",
      INGEST_URL: "http://127.0.0.1:19994",
      AUTH_USERNAME: TEST_USERNAME,
      AUTH_PASSWORD_HASH: bcrypt.hashSync(TEST_PASSWORD, 10),
      JWT_SECRET: "test-only-secret",
    },
    stdio: "pipe",
  });
  try {
    const deadline = Date.now() + 15000;
    let up = false;
    while (Date.now() < deadline) {
      try {
        const r = await fetch(`${base}/api/health`);
        if (r.ok && (await r.json()).mongo) { up = true; break; }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
    if (!up) throw new Error("rate-limit test server did not come up in time");

    const statuses = [];
    for (let i = 0; i < 12; i++) {
      const r = await fetch(`${base}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nonexistent", password: "nope" }),
      });
      statuses.push(r.status);
    }
    assert.ok(statuses.slice(0, 10).every((s) => s !== 429),
      "first 10 attempts within the window should not be rate-limited yet");
    assert.ok(statuses.slice(10).some((s) => s === 429),
      "attempts past the limit should return 429");
  } finally {
    proc.kill();
    await mongoose.connect(uri);
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
  }
});

test("change-password requires the current password and then the new one works", async () => {
  const NEW_PASSWORD = "another-strong-password-123";
  const { body: loginBody } = await login(TEST_USERNAME, TEST_PASSWORD);
  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${loginBody.token}` };

  const wrongCurrent = await fetch(`${BASE}/api/auth/change-password`, {
    method: "POST", headers,
    body: JSON.stringify({ currentPassword: "not-the-real-one", newPassword: NEW_PASSWORD }),
  });
  assert.equal(wrongCurrent.status, 401);

  const tooShort = await fetch(`${BASE}/api/auth/change-password`, {
    method: "POST", headers,
    body: JSON.stringify({ currentPassword: TEST_PASSWORD, newPassword: "short" }),
  });
  assert.equal(tooShort.status, 400);

  const ok = await fetch(`${BASE}/api/auth/change-password`, {
    method: "POST", headers,
    body: JSON.stringify({ currentPassword: TEST_PASSWORD, newPassword: NEW_PASSWORD }),
  });
  assert.equal(ok.status, 200);

  const oldStillWorks = await login(TEST_USERNAME, TEST_PASSWORD);
  assert.equal(oldStillWorks.status, 401, "old password must no longer work after a change");

  const newWorks = await login(TEST_USERNAME, NEW_PASSWORD);
  assert.equal(newWorks.status, 200);
});

test("account locks out after 5 consecutive failed attempts, and the lockout survives a correct password", async () => {
  // Own isolated server/port/db/IP-bucket — sharing BASE's server would mix
  // this test's login attempts into the same per-IP rate-limit bucket the
  // earlier tests already used (5 calls so far), tripping RATE_LIMIT_MAX
  // before the 6 calls below finish and masking the 423 behind a 429.
  // Also run last for a different reason: it leaves the account locked for
  // the full 15-minute window with no way to undo it mid-run.
  const port = 5996;
  const base = `http://127.0.0.1:${port}`;
  const uri = "mongodb://127.0.0.1:27017/traceshield_test_auth_lockout";
  const lockoutLogin = async (password) => {
    const r = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: TEST_USERNAME, password }),
    });
    return { status: r.status, body: await r.json() };
  };

  await mongoose.connect(uri);
  await mongoose.connection.db.dropDatabase();
  await mongoose.disconnect();

  const proc = spawn(process.execPath, ["index.js"], {
    cwd: path.join(__dirname, ".."),
    env: {
      ...process.env,
      PORT: String(port),
      MONGO_URI: uri,
      CORE_URL: "http://127.0.0.1:19993",
      INGEST_URL: "http://127.0.0.1:19992",
      AUTH_USERNAME: TEST_USERNAME,
      AUTH_PASSWORD_HASH: bcrypt.hashSync(TEST_PASSWORD, 10),
      JWT_SECRET: "test-only-secret",
    },
    stdio: "pipe",
  });
  try {
    const deadline = Date.now() + 15000;
    let up = false;
    while (Date.now() < deadline) {
      try {
        const r = await fetch(`${base}/api/health`);
        if (r.ok && (await r.json()).mongo) { up = true; break; }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
    if (!up) throw new Error("lockout test server did not come up in time");

    for (let i = 0; i < 5; i++) {
      const { status } = await lockoutLogin("still-wrong");
      assert.ok(status === 401 || status === 423, `attempt ${i} should be 401 or already 423`);
    }
    const { status, body } = await lockoutLogin("still-wrong");
    assert.equal(status, 423, "6th consecutive failure should be locked out");
    assert.ok(body.retryAfterSeconds > 0);

    // Locked out even with the CORRECT password — lockout is time-based, not
    // bypassable by eventually guessing right.
    const correctWhileLocked = await lockoutLogin(TEST_PASSWORD);
    assert.equal(correctWhileLocked.status, 423);
  } finally {
    proc.kill();
    await mongoose.connect(uri);
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
  }
});

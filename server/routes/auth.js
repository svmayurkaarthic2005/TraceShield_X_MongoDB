import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import AuthState from "../models/AuthState.js";
import LoginAudit from "../models/LoginAudit.js";
import { isMongoUp } from "../config/db.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

// Per-IP rate limit on /login, independent of the DB-backed account lockout
// below — this caps request VOLUME from one source regardless of which
// account it targets, and still works even when MongoDB is down (the
// lockout cannot, since it has nowhere durable to keep its counter).
// ponytail: plain in-memory fixed-window Map, no new dependency for one
// route at this traffic shape; swap for a shared store (Redis) if this ever
// runs as more than one instance, since each instance would otherwise count
// independently.
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;
const RATE_LIMIT_MAX = 10;
const rateLimitBuckets = new Map(); // ip -> { count, windowStart }

function isRateLimited(ip) {
  const now = Date.now();
  for (const [bucketIp, bucket] of rateLimitBuckets) {
    if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) rateLimitBuckets.delete(bucketIp);
  }
  const bucket = rateLimitBuckets.get(ip);
  if (!bucket) {
    rateLimitBuckets.set(ip, { count: 1, windowStart: now });
    return false;
  }
  bucket.count += 1;
  return bucket.count > RATE_LIMIT_MAX;
}

// Bootstraps the singleton AuthState doc (password hash + lockout counters)
// from env on first run. Once it exists, it — not .env — is the source of
// truth for the password, since a running process can't durably rewrite its
// own .env and Render manages env vars outside the app entirely. This is
// also why POST /change-password writes here, not to AUTH_PASSWORD_HASH.
async function getAuthState() {
  let state = await AuthState.findById("singleton");
  if (!state) {
    const bootstrapHash =
      process.env.AUTH_PASSWORD_HASH ||
      (process.env.AUTH_PASSWORD ? bcrypt.hashSync(process.env.AUTH_PASSWORD, 10) : null);
    if (!bootstrapHash) return null;
    state = await AuthState.create({ _id: "singleton", passwordHash: bootstrapHash });
  }
  return state;
}

async function audit(req, success, reason) {
  try {
    await LoginAudit.create({
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      usernameAttempted: req.body?.username,
      success,
      reason,
    });
  } catch {
    // Audit logging is best-effort — never block a login over it.
  }
}

router.post("/login", async (req, res) => {
  if (isRateLimited(req.ip)) {
    await audit(req, false, "rate_limited");
    return res.status(429).json({ error: "Too many login attempts — try again later." });
  }

  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required" });
  }
  const validUser = username === process.env.AUTH_USERNAME;

  if (!isMongoUp()) {
    // Degraded mode: no durable place to keep lockout state, so fall back to
    // the env-configured hash directly with no lockout — the same behavior
    // this app always had without MongoDB. Plaintext AUTH_PASSWORD is no
    // longer accepted anywhere, degraded mode included.
    const hash = process.env.AUTH_PASSWORD_HASH;
    const validPass = validUser && hash && (await bcrypt.compare(password, hash));
    if (!validPass) {
      await audit(req, false, "bad_credentials_degraded");
      return res.status(401).json({ error: "Invalid credentials" });
    }
    await audit(req, true, "ok_degraded");
    const token = jwt.sign({ sub: username }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || "12h",
    });
    return res.json({ token });
  }

  const state = await getAuthState();
  if (!state) {
    return res.status(500).json({ error: "Auth is not configured" });
  }

  if (state.lockedUntil && state.lockedUntil > new Date()) {
    await audit(req, false, "locked_out");
    const retryAfterSec = Math.ceil((state.lockedUntil.getTime() - Date.now()) / 1000);
    res.set("Retry-After", String(retryAfterSec));
    return res.status(423).json({
      error: "Account locked due to repeated failed attempts.",
      retryAfterSeconds: retryAfterSec,
    });
  }

  const validPass = validUser && (await bcrypt.compare(password, state.passwordHash));
  if (!validPass) {
    state.failedAttempts += 1;
    if (state.failedAttempts >= MAX_FAILED_ATTEMPTS) {
      state.lockedUntil = new Date(Date.now() + LOCKOUT_MS);
      state.failedAttempts = 0;
    }
    await state.save();
    await audit(req, false, "bad_credentials");
    return res.status(401).json({ error: "Invalid credentials" });
  }

  state.failedAttempts = 0;
  state.lockedUntil = null;
  await state.save();
  await audit(req, true, "ok");

  const token = jwt.sign({ sub: username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "12h",
  });
  res.json({ token });
});

// Requires the caller's own current password — not a self-service "forgot
// password" (no email/SMS infra exists to deliver a reset link to, and this
// is a single operator account, not a user base). An operator who has
// forgotten the password entirely still has the escape hatch this app
// always had: set a new AUTH_PASSWORD_HASH in the environment and delete the
// AuthState document (or wait for Mongo to be briefly down, which falls back
// to the env hash) to force re-bootstrap.
router.post("/change-password", requireAuth, async (req, res) => {
  if (!isMongoUp()) {
    return res.status(503).json({ error: "Password changes require MongoDB (unavailable right now)." });
  }
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: "currentPassword and newPassword are required" });
  }
  if (newPassword.length < 12) {
    return res.status(400).json({ error: "newPassword must be at least 12 characters." });
  }

  const state = await getAuthState();
  if (!state) return res.status(500).json({ error: "Auth is not configured" });

  const valid = await bcrypt.compare(currentPassword, state.passwordHash);
  if (!valid) {
    await audit(req, false, "change_password_bad_current");
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  state.passwordHash = bcrypt.hashSync(newPassword, 10);
  state.updatedAt = new Date();
  await state.save();
  await audit(req, true, "password_changed");
  res.json({ changed: true });
});

router.get("/audit", requireAuth, async (req, res) => {
  if (!isMongoUp()) return res.status(503).json({ error: "MongoDB unavailable" });
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const entries = await LoginAudit.find().sort({ timestamp: -1 }).limit(limit);
  res.json({ entries });
});

export default router;

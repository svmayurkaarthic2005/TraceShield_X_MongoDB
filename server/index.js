import "dotenv/config";
import express from "express";
import cors from "cors";
import morgan from "morgan";
import { connectMongo, isMongoUp } from "./config/db.js";
import reportsRouter from "./routes/reports.js";
import authRouter from "./routes/auth.js";
import { mountProxies } from "./routes/proxies.js";

const PORT = process.env.PORT || 5000;
const CORE_URL = process.env.CORE_URL || "http://127.0.0.1:8000";
const INGEST_URL = process.env.INGEST_URL || "http://127.0.0.1:8001";
// ALLOWED_ORIGIN can be a comma-separated list, e.g.:
//   http://localhost:5173,https://trace-shield-x.vercel.app
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || "http://localhost:5173")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

const app = express();
// Required for req.ip to reflect the real client address behind Render's
// reverse proxy (and any other platform load balancer) — without this every
// request appears to come from the proxy's own IP, making the login route's
// per-IP rate limiter useless (one shared bucket for all clients).
app.set("trust proxy", 1);
app.use(
  cors({
    origin: (origin, cb) => {
      // Allow server-to-server / curl requests (no Origin header)
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      cb(new Error(`CORS: origin '${origin}' not allowed`));
    },
    credentials: true,
  })
);
app.use(morgan("dev"));

// Public unauthenticated access for internal proxies
// (login requirement removed)

// Mounted before express.json() — http-proxy-middleware needs the raw
// request stream, which body-parsing middleware would otherwise consume.
const { wsProxy } = mountProxies(app, { coreUrl: CORE_URL, ingestUrl: INGEST_URL });

app.use(express.json({ limit: "2mb" }));

app.use("/api/auth", authRouter);

async function pingJson(url, timeoutMs = 2000) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return { up: false };
    return { up: true, body: await res.json() };
  } catch {
    return { up: false };
  }
}

app.get("/api/health", async (req, res) => {
  const [core, ingestion] = await Promise.all([
    pingJson(`${CORE_URL}/api/health`),
    // Ingestion has no dedicated /health route — its root ("/") is the
    // closest existing liveness check, and Python files aren't touched here.
    pingJson(`${INGEST_URL}/`),
  ]);
  const status = core.up ? await pingJson(`${CORE_URL}/api/status`) : { up: false };

  res.json({
    server: true,
    mongo: isMongoUp(),
    core: core.up,
    ingestion: ingestion.up,
    neo4j: status.up ? Boolean(status.body?.neo4j) : false,
  });
});

app.use("/api/reports", reportsRouter);

await connectMongo(process.env.MONGO_URI);

const server = app.listen(PORT, () => {
  console.log(`[server] listening on http://127.0.0.1:${PORT}`);
});
// NOTE: 'upgrade' events bypass the Express middleware stack entirely, so
// requireAuth does not run here — the /ws WebSocket proxy is unauthenticated.
server.on("upgrade", wsProxy.upgrade);

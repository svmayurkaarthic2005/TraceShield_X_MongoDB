import "dotenv/config";
import express from "express";
import cors from "cors";
import morgan from "morgan";
import { connectMongo, isMongoUp } from "./config/db.js";
import reportsRouter from "./routes/reports.js";
import authRouter from "./routes/auth.js";
import { mountProxies } from "./routes/proxies.js";
import { requireAuth } from "./middleware/auth.js";

const PORT = process.env.PORT || 5000;
const CORE_URL = process.env.CORE_URL || "http://127.0.0.1:8000";
const INGEST_URL = process.env.INGEST_URL || "http://127.0.0.1:8001";

const app = express();
app.use(cors({ origin: "http://localhost:5173" }));
app.use(morgan("dev"));

// requireAuth only reads headers, so it's safe to run before the proxies —
// registered here (ahead of mountProxies) so it gates both /api/core/* and
// /api/ingest/* before the request ever reaches http-proxy-middleware.
app.use("/api/core", requireAuth);
app.use("/api/ingest", requireAuth);

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

app.use("/api/reports", requireAuth, reportsRouter);

await connectMongo(process.env.MONGO_URI);

const server = app.listen(PORT, () => {
  console.log(`[server] listening on http://127.0.0.1:${PORT}`);
});
// NOTE: 'upgrade' events bypass the Express middleware stack entirely, so
// requireAuth does not run here — the /ws WebSocket proxy is unauthenticated.
server.on("upgrade", wsProxy.upgrade);

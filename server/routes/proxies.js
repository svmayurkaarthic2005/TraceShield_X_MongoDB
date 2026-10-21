import { createProxyMiddleware } from "http-proxy-middleware";

function stripUpstreamCors(proxyRes) {
  delete proxyRes.headers["access-control-allow-origin"];
  delete proxyRes.headers["access-control-allow-credentials"];
  delete proxyRes.headers["access-control-allow-methods"];
  delete proxyRes.headers["access-control-allow-headers"];
}

export function mountProxies(app, { coreUrl, ingestUrl }) {
  app.use(
    "/api/core",
    createProxyMiddleware({
      target: coreUrl,
      changeOrigin: true,
      pathRewrite: { "^/api/core": "" },
      on: {
        proxyRes: stripUpstreamCors,
      },
    })
  );

  app.use(
    "/api/ingest",
    createProxyMiddleware({
      target: ingestUrl,
      changeOrigin: true,
      pathRewrite: { "^/api/ingest": "" },
      on: {
        proxyRes: stripUpstreamCors,
      },
    })
  );

  const wsProxy = createProxyMiddleware({
    target: ingestUrl,
    ws: true,
    changeOrigin: true,
  });
  app.use("/ws", wsProxy);

  return { wsProxy };
}

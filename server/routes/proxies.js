import { createProxyMiddleware } from "http-proxy-middleware";

export function mountProxies(app, { coreUrl, ingestUrl }) {
  app.use(
    "/api/core",
    createProxyMiddleware({
      target: coreUrl,
      changeOrigin: true,
      pathRewrite: { "^/api/core": "" },
    })
  );

  app.use(
    "/api/ingest",
    createProxyMiddleware({
      target: ingestUrl,
      changeOrigin: true,
      pathRewrite: { "^/api/ingest": "" },
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

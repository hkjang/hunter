import { defineConfig, type ProxyOptions } from "vite";
import react from "@vitejs/plugin-react";
// Development only: Vite and Go listen on separate ports. Keep Go's strict
// Origin/Host CSRF verification intact by using the same target for both.
const backend: ProxyOptions = {
  target: "http://127.0.0.1:8080",
  changeOrigin: true,
  configure(proxy) {
    proxy.on("proxyReq", (request, incoming) => {
      if (incoming.headers.origin)
        request.setHeader("Origin", "http://127.0.0.1:8080");
    });
  },
};
export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", proxy: { "/api": backend, "/mcp": backend } },
  build: { chunkSizeWarningLimit: 1600 },
});

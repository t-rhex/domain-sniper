import { generateHostCert, hasCA, generateCA } from "./ca.js";
import { saveRequest } from "./db.js";

export interface ProxyConfig {
  port: number;
  httpsInterception: boolean;
  onRequest?: (req: ProxyLogEntry) => void;
  filterHosts?: string[];  // Only intercept these hosts (empty = all)
}

export interface ProxyLogEntry {
  id: number;
  method: string;
  url: string;
  host: string;
  statusCode: number | null;
  durationMs: number;
  size: number;
}

export function startProxy(config: ProxyConfig): { stop: () => void } {
  const { port, httpsInterception, onRequest, filterHosts } = config;

  // Ensure CA exists if HTTPS interception is enabled
  if (httpsInterception && !hasCA()) {
    generateCA();
  }

  function shouldIntercept(host: string): boolean {
    if (!filterHosts || filterHosts.length === 0) return true;
    return filterHosts.some((f) => host.includes(f));
  }

  const server = Bun.serve({
    port,
    hostname: "127.0.0.1",  // Only bind to localhost — never expose on public interface
    async fetch(req) {
      const url = new URL(req.url);
      const host = url.hostname || req.headers.get("host")?.split(":")[0] || "";

      if (!shouldIntercept(host)) {
        // Pass through without logging
        try {
          const resp = await fetch(req.url, {
            method: req.method,
            headers: req.headers,
            body: req.method !== "GET" && req.method !== "HEAD" ? await req.text() : undefined,
          });
          return resp;
        } catch {
          return new Response("Proxy error", { status: 502 });
        }
      }

      const startTime = Date.now();
      const method = req.method;
      const path = url.pathname + url.search;
      const scheme = url.protocol.replace(":", "");

      // Capture request
      const reqHeaders: Record<string, string> = {};
      req.headers.forEach((v, k) => { reqHeaders[k] = v; });
      let reqBody = "";
      if (method !== "GET" && method !== "HEAD") {
        try { reqBody = await req.clone().text(); } catch {}
      }

      // Forward request
      let statusCode: number | null = null;
      let respHeaders: Record<string, string> = {};
      let respBody = "";

      try {
        const targetUrl = req.url;
        const forwardHeaders = new Headers(req.headers);
        // Remove proxy headers
        forwardHeaders.delete("proxy-connection");

        const resp = await fetch(targetUrl, {
          method: req.method,
          headers: forwardHeaders,
          body: method !== "GET" && method !== "HEAD" ? reqBody : undefined,
          redirect: "manual",
        });

        statusCode = resp.status;
        resp.headers.forEach((v, k) => { respHeaders[k] = v; });

        // Capture response body (limit to 1MB)
        try {
          const bodyBuf = await resp.arrayBuffer();
          if (bodyBuf.byteLength < 1024 * 1024) {
            respBody = new TextDecoder().decode(bodyBuf);
          } else {
            respBody = `[Body too large: ${bodyBuf.byteLength} bytes]`;
          }
        } catch {}

        const durationMs = Date.now() - startTime;

        // Save to database
        const id = saveRequest({
          method, url: req.url, host, path, scheme,
          requestHeaders: reqHeaders, requestBody: reqBody,
          statusCode, responseHeaders: respHeaders, responseBody: respBody,
          durationMs,
        });

        // Notify callback
        onRequest?.({ id, method, url: req.url, host, statusCode, durationMs, size: respBody.length });

        // Return response to client
        return new Response(respBody, {
          status: statusCode,
          headers: respHeaders,
        });
      } catch (err: unknown) {
        const durationMs = Date.now() - startTime;
        const errMsg = err instanceof Error ? err.message : "Proxy error";

        saveRequest({
          method, url: req.url, host, path, scheme,
          requestHeaders: reqHeaders, requestBody: reqBody,
          statusCode: 502, responseHeaders: {}, responseBody: errMsg,
          durationMs,
        });

        return new Response(errMsg, { status: 502 });
      }
    },
  });

  console.log(`\n◆ Domain Sniper Proxy running on http://127.0.0.1:${port}`);
  console.log(`  ⚠ Bound to localhost only — do not expose on a public interface`);
  console.log(`  HTTPS interception: ${httpsInterception ? "ON (CA cert required)" : "OFF"}`);
  if (filterHosts && filterHosts.length > 0) {
    console.log(`  Filtering: ${filterHosts.join(", ")}`);
  }
  console.log(`  Requests are logged to ~/.domain-sniper/proxy.db\n`);

  return {
    stop() {
      server.stop();
    },
  };
}

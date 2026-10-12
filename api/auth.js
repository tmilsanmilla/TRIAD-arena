import { ensureAuthReady, ORIGIN, requestHeaders, relay } from "../lib/auth.js";

export default async function handler(req, res) {
  try {
    const { auth } = await ensureAuthReady();
    const url = new URL(req.url, ORIGIN), headers = requestHeaders(req);
    if (!url.pathname.startsWith("/api/auth/")) {
      const path = String(req.query?.authPath || url.searchParams.get("authPath") || "");
      if (!/^[a-z0-9/._-]+$/i.test(path) || path.includes("..")) { res.statusCode = 404; return res.end(); }
      url.pathname = `/api/auth/${path}`; url.searchParams.delete("authPath");
    }
    if (url.pathname === "/api/auth/start") {
      if (req.method !== "GET") { res.statusCode = 405; return res.end(); }
      const linking = url.searchParams.get("intent") === "link";
      const response = await auth.api.signInSocial({ headers, body: { provider: "pixel-pulse", callbackURL: `${ORIGIN}/?pixel_connected=1${linking ? "&pixel_action=link" : ""}`, errorCallbackURL: `${ORIGIN}/?pixel_error=1` }, asResponse: true });
      const result = await response.clone().json();
      if (response.ok && result.url) {
        const cookies = response.headers.getSetCookie(); if (cookies.length) res.setHeader("Set-Cookie", cookies);
        res.statusCode = 302; res.setHeader("Location", result.url); res.setHeader("Cache-Control", "no-store"); return res.end();
      }
      return relay(response, res);
    }
    let body;
    if (!["GET", "HEAD"].includes(req.method)) {
      if (typeof req.body === "string" || Buffer.isBuffer(req.body)) body = req.body;
      else if (req.body && typeof req.body === "object") body = JSON.stringify(req.body);
      else {
        const chunks = []; let bytes = 0;
        for await (const chunk of req) { bytes += chunk.length; if (bytes > 16384) { res.statusCode = 413; return res.end(); } chunks.push(chunk); }
        body = Buffer.concat(chunks);
      }
    }
    return relay(await auth.handler(new Request(url.href, { method: req.method, headers, ...(body !== undefined ? { body, duplex: "half" } : {}) })), res);
  } catch (error) {
    console.error("Triad account service error", error.code || error.name);
    res.statusCode = 503; res.setHeader("Content-Type", "application/json"); res.setHeader("Cache-Control", "no-store");
    res.end(JSON.stringify({ message: "Pixel Pulse sign-in is temporarily unavailable. You can still play as a guest." }));
  }
}

import { ensureAuthReady, ORIGIN, requestHeaders } from "../lib/auth.js";
const LEGACY_ORIGIN = "https://sfvnmmcmobnoslkmmknb.supabase.co";
const LEGACY_PUBLIC_KEY = "sb_publishable_usL3aDIJDq7j_BByuIWwlA_1ImhXLx9";
const json = (res, status, body) => { res.statusCode = status; res.setHeader("Content-Type", "application/json"); res.setHeader("Cache-Control", "no-store"); res.end(JSON.stringify(body)); };

export default async function handler(req, res) {
  if (!["GET", "POST"].includes(req.method)) return json(res, 405, { error: "Method not allowed." });
  if (req.method === "POST" && (req.headers.origin !== ORIGIN || !String(req.headers["content-type"] || "").startsWith("application/json"))) return json(res, 403, { error: "Link accounts from Triad Arena." });
  try {
    const { auth, pool } = await ensureAuthReady();
    const session = await auth.api.getSession({ headers: requestHeaders(req) });
    if (!session?.user?.id) return json(res, 401, { error: "Continue with Pixel Pulse first, then sign in to the existing Triad account." });
    if (req.method === "GET") {
      const result = await pool.query("SELECT legacy_id FROM triad_legacy_links WHERE user_id = $1", [session.user.id]);
      return json(res, 200, { linked: result.rowCount > 0 });
    }
    let body = req.body;
    if (body === undefined) {
      const chunks = []; let bytes = 0;
      for await (const chunk of req) { bytes += chunk.length; if (bytes > 16384) return json(res, 413, { error: "Request too large." }); chunks.push(chunk); }
      body = Buffer.concat(chunks).toString("utf8");
    }
    if (typeof body === "string" || Buffer.isBuffer(body)) {
      try { body = JSON.parse(body.toString()); } catch { return json(res, 400, { error: "Invalid account proof." }); }
    }
    const token = String(body?.legacyAccessToken || "");
    if (!token || token.length > 8192) return json(res, 400, { error: "Sign in to your existing Triad account to prove ownership." });
    const legacyResponse = await fetch(`${LEGACY_ORIGIN}/auth/v1/user`, {
      headers: { apikey: LEGACY_PUBLIC_KEY, Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(10000),
    });
    if (!legacyResponse.ok) return json(res, 401, { error: "The old account sign-in expired. Sign in again to link it." });
    const legacy = await legacyResponse.json();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(legacy.id || "") || typeof legacy.email !== "string" || !legacy.email.includes("@")) return json(res, 401, { error: "Could not verify the old account." });
    const rows = await pool.query(`INSERT INTO triad_legacy_links (legacy_id, user_id, legacy_email) VALUES ($1, $2, $3)
      ON CONFLICT (legacy_id) DO UPDATE SET legacy_email = EXCLUDED.legacy_email
      WHERE triad_legacy_links.user_id = EXCLUDED.user_id RETURNING legacy_id`, [legacy.id, session.user.id, legacy.email]);
    if (!rows.rowCount) return json(res, 409, { error: "That old account is already linked to another Pixel Pulse account." });
    return json(res, 200, { ok: true, username: session.user.username || session.user.name });
  } catch (error) {
    if (error.code === "23505") return json(res, 409, { error: "This Pixel Pulse account is already linked to another Triad account." });
    return json(res, 503, { error: "The old account service is unavailable. Pixel Pulse sign-in and guest play are available; retry linking when the old service returns." });
  }
}

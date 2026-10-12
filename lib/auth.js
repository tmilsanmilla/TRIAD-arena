import { Pool } from "pg";
import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";

export const ORIGIN = "https://triad-arena.vercel.app";
export const PIXEL_ISSUER = "https://pixel-pulse-websites.vercel.app/api/sso";
let service, ready;

export function getAuth() {
  if (service) return service;
  if (!process.env.DATABASE_URL || !process.env.BETTER_AUTH_SECRET || process.env.BETTER_AUTH_SECRET.length < 32) throw new Error("Account service is not configured.");
  const connectionString = new URL(process.env.DATABASE_URL);
  connectionString.searchParams.set("sslmode", "verify-full");
  const pool = new Pool({ connectionString: connectionString.href, max: 3, connectionTimeoutMillis: 10000, idleTimeoutMillis: 20000 });
  const options = {
    appName: "Triad Arena", baseURL: ORIGIN, secret: process.env.BETTER_AUTH_SECRET, database: pool,
    trustedOrigins: [ORIGIN],
    emailAndPassword: { enabled: false },
    account: { accountLinking: { enabled: false } },
    user: { additionalFields: { username: { type: "string", unique: true, input: false, required: false } } },
    databaseHooks: { user: {
      create: { before: async (user) => {
        // Credentials and other providers are disabled. This is server-owned
        // data from the verified Pixel profile, not an editable client field.
        if (!/^[a-z0-9_]{3,24}$/.test(user.name || "")) throw new Error("Invalid shared username.");
        return { data: { ...user, username: user.name } };
      } },
      update: { before: async (user) => {
        if (user.name === undefined) return { data: user };
        if (!/^[a-z0-9_]{3,24}$/.test(user.name || "")) throw new Error("Invalid shared username.");
        return { data: { ...user, username: user.name } };
      } },
    } },
    session: { expiresIn: 604800, cookieCache: { enabled: false } },
    advanced: { cookiePrefix: "triad_pixel", useSecureCookies: true, defaultCookieAttributes: { httpOnly: true, sameSite: "lax" } },
    disabledPaths: ["/sign-up/email", "/sign-in/email", "/update-user", "/change-email", "/change-password", "/set-password", "/link-social", "/unlink-account"],
    plugins: [genericOAuth({ config: [{
      providerId: "pixel-pulse", clientId: "triad-arena",
      discoveryUrl: `${PIXEL_ISSUER}/.well-known/openid-configuration`,
      requireIdTokenVerification: true, tokenEndpointAuth: { method: "none" },
      redirectURI: `${ORIGIN}/api/auth/callback/pixel-pulse`,
      scopes: ["openid", "profile", "email"], pkce: true, overrideUserInfo: true,
      disableProviderLogout: true,
      mapProfileToUser(profile) {
        const username = String(profile.preferred_username || "");
        if (!/^[a-z0-9_]{3,24}$/.test(username) || profile.name !== username || typeof profile.email_verified !== "boolean") throw new Error("Pixel Pulse returned an invalid shared identity.");
        return { name: username, username, email: profile.email, emailVerified: profile.email_verified };
      },
    }] })],
  };
  service = { auth: betterAuth(options), pool, options };
  return service;
}

export async function ensureAuthReady() {
  if (!ready) ready = (async () => {
    const { auth, pool, options } = getAuth();
    const client = await pool.connect();
    try {
      await client.query("SELECT pg_advisory_lock(753482020)");
      await (await getMigrations(options)).runMigrations();
      await client.query(`CREATE TABLE IF NOT EXISTS triad_legacy_links (
        legacy_id UUID PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES "user"(id) ON DELETE CASCADE,
        legacy_email TEXT NOT NULL, linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`);
    } finally { await client.query("SELECT pg_advisory_unlock(753482020)"); client.release(); }
    await auth.$context;
  })().catch((error) => { ready = undefined; throw error; });
  await ready;
  return getAuth();
}

export function requestHeaders(req) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers || {})) {
    if (Array.isArray(value)) headers.set(name, value.join(", "));
    else if (value !== undefined) headers.set(name, String(value));
  }
  return headers;
}

export async function relay(response, res) {
  res.statusCode = response.status;
  for (const [name, value] of response.headers) if (!["set-cookie", "content-length", "transfer-encoding"].includes(name.toLowerCase())) res.setHeader(name, value);
  const cookies = response.headers.getSetCookie();
  if (cookies.length) res.setHeader("Set-Cookie", cookies);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.end(Buffer.from(await response.arrayBuffer()));
}

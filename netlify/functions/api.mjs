import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

/* =========================================================================
 * REEL·bank API — auth + roles + shared data, all on Netlify Blobs.
 * Routes (all under /api/*):
 *   POST /api/login    { email, password }            -> { token, user }
 *   GET  /api/me                                       -> { user }
 *   GET  /api/state                                    -> { feed, bank, passed }   (any role)
 *   POST /api/state    { feed, bank, passed }          -> { ok }                    (admin)
 *   POST /api/import   { url, title }                  -> { ok, card }              (importer|admin)
 *   GET  /api/users                                    -> { users }                 (admin)
 *   POST /api/users    { email,password,role,name }    -> { ok, user }              (admin, create)
 *   POST /api/users    { action:'delete', id }         -> { ok }                    (admin)
 *   POST /api/users    { action:'role', id, role }     -> { ok }                    (admin)
 *   POST /api/users    { action:'password', id, password } -> { ok }               (admin)
 * ========================================================================= */

const STORE = "reelbank";
const ROLES = ["admin", "importer", "viewer"];
const DAY = 24 * 60 * 60 * 1000;

const SEED = {
  feed: [
    { id: "seed1", platform: "tiktok", title: "Slow-mo gym transformation reveal", author: "@peakform", desc: "Dramatic before/after with a beat drop on the reveal. Clean lighting.", img: "" },
    { id: "seed2", platform: "reels",  title: "Get-ready-with-me, one take",       author: "@maya.rl",  desc: "Handheld GRWM, natural light, subtle captions. Very authentic UGC energy.", img: "" },
    { id: "seed3", platform: "shorts", title: "Street interview: \"what's your routine?\"", author: "@askthecity", desc: "Fast cuts between strangers, bold on-screen questions.", img: "" },
    { id: "seed4", platform: "tiktok", title: "Cinematic sunrise run, drone open",  author: "@ridgeline", desc: "Moody amber grade, orchestral swell, product in frame at 0:04.", img: "" },
    { id: "seed5", platform: "reels",  title: "POV desk-setup routine ASMR",        author: "@quietdesk", desc: "No talking, ambient sound design, satisfying pacing.", img: "" }
  ],
  bank: {},
  passed: []
};

/* ------------------------------- crypto -------------------------------- */
function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, 64);
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}
function verifyPassword(password, saltHex, hashHex) {
  try {
    const hash = crypto.scryptSync(String(password), Buffer.from(saltHex, "hex"), 64);
    const expected = Buffer.from(hashHex, "hex");
    return expected.length === hash.length && crypto.timingSafeEqual(expected, hash);
  } catch { return false; }
}
function secret() { return process.env.AUTH_SECRET || "dev-only-insecure-secret"; }
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  return body + "." + sig;
}
function verifyToken(token) {
  if (!token || token.indexOf(".") < 0) return null;
  const [body, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let p; try { p = JSON.parse(Buffer.from(body, "base64url").toString()); } catch { return null; }
  if (p.exp && Date.now() > p.exp) return null;
  return p;
}
function rid() { return crypto.randomUUID(); }

/* ------------------------------- storage ------------------------------- */
async function getUsers(store) { return (await store.get("users", { type: "json" })) || {}; }
async function setUsers(store, u) { await store.setJSON("users", u); }
async function getState(store) { return (await store.get("state", { type: "json" })) || SEED; }
async function setState(store, s) { await store.setJSON("state", s); }
function publicUser(u) { return { id: u.id, email: u.email, name: u.name, role: u.role, createdAt: u.createdAt }; }

/* Seed the first admin from env vars if the user store is empty. */
async function ensureBootstrap(store) {
  const users = await getUsers(store);
  if (Object.keys(users).length) return;
  const email = (process.env.ADMIN_EMAIL || "").toLowerCase().trim();
  if (email && process.env.ADMIN_SALT && process.env.ADMIN_HASH) {
    users[email] = {
      id: rid(), email, name: process.env.ADMIN_NAME || "Admin",
      role: "admin", salt: process.env.ADMIN_SALT, hash: process.env.ADMIN_HASH, createdAt: Date.now()
    };
    await setUsers(store, users);
  }
}

/* ------------------------------- routes -------------------------------- */
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");
  const store = getStore(STORE);
  try {
    await ensureBootstrap(store);

    if (path === "/api/login") return await login(req, store);

    // everything else requires a valid token
    const auth = requireAuth(req);
    if (!auth) return json({ error: "Not signed in" }, 401);

    if (path === "/api/me") return json({ user: auth });
    if (path === "/api/state") return await stateRoute(req, store, auth);
    if (path === "/api/import") return await importRoute(req, store, auth);
    if (path === "/api/users") return await usersRoute(req, store, auth);
    return json({ error: "Not found" }, 404);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
};

export const config = { path: "/api/*" };

function requireAuth(req) {
  const h = req.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  const p = verifyToken(token);
  if (!p) return null;
  return { id: p.sub, email: p.email, role: p.role, name: p.name };
}

async function login(req, store) {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const { email, password } = await req.json().catch(() => ({}));
  const users = await getUsers(store);
  const u = users[String(email || "").toLowerCase().trim()];
  if (!u || !verifyPassword(password || "", u.salt, u.hash))
    return json({ error: "Invalid email or password" }, 401);
  const token = sign({ sub: u.id, email: u.email, name: u.name, role: u.role, iat: Date.now(), exp: Date.now() + 30 * DAY });
  return json({ token, user: publicUser(u) });
}

async function stateRoute(req, store, auth) {
  if (req.method === "GET") return json(await getState(store));
  if (req.method === "POST") {
    if (auth.role !== "admin") return json({ error: "Reviewers only" }, 403);
    const b = await req.json().catch(() => ({}));
    await setState(store, {
      feed: Array.isArray(b.feed) ? b.feed : [],
      bank: b.bank && typeof b.bank === "object" ? b.bank : {},
      passed: Array.isArray(b.passed) ? b.passed : []
    });
    return json({ ok: true });
  }
  return json({ error: "Method not allowed" }, 405);
}

async function importRoute(req, store, auth) {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  if (auth.role !== "admin" && auth.role !== "importer") return json({ error: "Not allowed" }, 403);
  const { url, title } = await req.json().catch(() => ({}));
  if (!url || !/^https?:\/\//i.test(url)) return json({ error: "A valid link is required" }, 400);
  const s = await getState(store);
  const card = {
    id: rid(), platform: detectPlatform(url), url, title: (title || "").trim() || "Imported reference",
    author: "", desc: "Submitted reference — open to preview.", img: "",
    submittedBy: auth.name || auth.email, submittedAt: Date.now()
  };
  s.feed = [card, ...(Array.isArray(s.feed) ? s.feed : [])];
  await setState(store, s);
  return json({ ok: true, card });
}

async function usersRoute(req, store, auth) {
  if (auth.role !== "admin") return json({ error: "Admins only" }, 403);
  const users = await getUsers(store);
  if (req.method === "GET") return json({ users: Object.values(users).map(publicUser).sort((a, b) => a.createdAt - b.createdAt) });
  if (req.method === "POST") {
    const b = await req.json().catch(() => ({}));
    const byId = (id) => Object.values(users).find((u) => u.id === id);

    if (b.action === "delete") {
      const t = byId(b.id);
      if (t) {
        if (t.email === auth.email) return json({ error: "You can't delete your own account" }, 400);
        delete users[t.email]; await setUsers(store, users);
      }
      return json({ ok: true });
    }
    if (b.action === "role") {
      const t = byId(b.id);
      if (!t) return json({ error: "User not found" }, 404);
      if (t.email === auth.email && b.role !== "admin") return json({ error: "You can't remove your own admin access" }, 400);
      if (!ROLES.includes(b.role)) return json({ error: "Bad role" }, 400);
      t.role = b.role; await setUsers(store, users);
      return json({ ok: true });
    }
    if (b.action === "password") {
      const t = byId(b.id);
      if (!t) return json({ error: "User not found" }, 404);
      if (String(b.password || "").length < 6) return json({ error: "Password must be at least 6 characters" }, 400);
      const { salt, hash } = hashPassword(b.password); t.salt = salt; t.hash = hash;
      await setUsers(store, users);
      return json({ ok: true });
    }
    // create
    const email = String(b.email || "").toLowerCase().trim();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "Enter a valid email" }, 400);
    if (users[email]) return json({ error: "That email already has an account" }, 409);
    if (String(b.password || "").length < 6) return json({ error: "Password must be at least 6 characters" }, 400);
    const role = ROLES.includes(b.role) ? b.role : "viewer";
    const { salt, hash } = hashPassword(b.password);
    users[email] = { id: rid(), email, name: (b.name || "").trim() || email.split("@")[0], role, salt, hash, createdAt: Date.now() };
    await setUsers(store, users);
    return json({ ok: true, user: publicUser(users[email]) });
  }
  return json({ error: "Method not allowed" }, 405);
}

/* ------------------------------- helpers ------------------------------- */
function detectPlatform(url) {
  const u = String(url).toLowerCase();
  if (u.includes("tiktok")) return "tiktok";
  if (u.includes("instagram") || u.includes("/reel")) return "reels";
  if (u.includes("youtu")) return "shorts";
  return "tiktok";
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" }
  });
}

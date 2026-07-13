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
const FORMATS = ["Hair transformations", "High-effort UGC", "IRL", "UGC shoots", "Yaps"];
const DAY = 24 * 60 * 60 * 1000;

const SEED = { feed: [], bank: {}, passed: [], archive: {}, recommended: [] };

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

/* ------------------------------- storage -------------------------------
 * Each user is stored under its own key `user:<email>` so concurrent
 * account creation never clobbers another (no read-modify-write on a shared
 * collection). App data (feed/bank/passed) lives in a single `state` blob. */
const uKey = (email) => "user:" + String(email).toLowerCase().trim();
async function getUser(store, email) { return await store.get(uKey(email), { type: "json" }); }
async function putUser(store, u) { await store.setJSON(uKey(u.email), u); }
async function deleteUser(store, email) { await store.delete(uKey(email)); }
async function listUsers(store) {
  const { blobs } = await store.list({ prefix: "user:" });
  const out = [];
  for (const b of blobs) { const u = await store.get(b.key, { type: "json" }); if (u) out.push(u); }
  return out;
}
async function getState(store) {
  const s = (await store.get("state", { type: "json" })) || SEED;
  if (!s.archive || typeof s.archive !== "object") s.archive = {};
  if (!Array.isArray(s.recommended)) s.recommended = [];
  return s;
}
async function setState(store, s) { await store.setJSON("state", s); }
function publicUser(u) { return { id: u.id, email: u.email, name: u.name, role: u.role, createdAt: u.createdAt }; }

/* Access requests (self-serve) and invites — per-key blobs, like users. */
const rKey = (email) => "req:" + String(email).toLowerCase().trim();
async function getRequest(store, email) { return await store.get(rKey(email), { type: "json" }); }
async function putRequest(store, r) { await store.setJSON(rKey(r.email), r); }
async function deleteRequest(store, email) { await store.delete(rKey(email)); }
async function listRequests(store) {
  const { blobs } = await store.list({ prefix: "req:" });
  const out = []; for (const b of blobs) { const r = await store.get(b.key, { type: "json" }); if (r) out.push(r); }
  return out;
}
const iKey = (t) => "invite:" + t;
async function getInvite(store, t) { return await store.get(iKey(t), { type: "json" }); }
async function putInvite(store, i) { await store.setJSON(iKey(i.token), i); }
async function deleteInvite(store, t) { await store.delete(iKey(t)); }
const emailOk = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);

/* Per-user leaderboard stats (per-key blob to avoid write races). */
const sKey = (email) => "stat:" + String(email).toLowerCase().trim();
async function incStat(store, email, name, field, by) {
  const k = sKey(email);
  const cur = (await store.get(k, { type: "json" })) || { email: String(email).toLowerCase().trim(), name: name || "", imports: 0, sorts: 0 };
  cur[field] = (cur[field] || 0) + by;
  if (name) cur.name = name;
  await store.setJSON(k, cur);
}
async function listStats(store) {
  const { blobs } = await store.list({ prefix: "stat:" });
  const out = []; for (const b of blobs) { const s = await store.get(b.key, { type: "json" }); if (s) out.push(s); }
  return out;
}

/* Seed the first admin from env vars if it doesn't exist yet (idempotent). */
async function ensureBootstrap(store) {
  const email = (process.env.ADMIN_EMAIL || "").toLowerCase().trim();
  if (!email || !process.env.ADMIN_SALT || !process.env.ADMIN_HASH) return;
  if (await getUser(store, email)) return;
  await putUser(store, {
    id: rid(), email, name: process.env.ADMIN_NAME || "Admin",
    role: "admin", salt: process.env.ADMIN_SALT, hash: process.env.ADMIN_HASH, createdAt: Date.now()
  });
}

/* ------------------------------- routes -------------------------------- */
/* Platform-agnostic handler: takes a Web `Request` and a Blobs `store`.
   Netlify and Vercel each construct the store their own way and call this. */
export async function handleRequest(req, store) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");
  try {
    await ensureBootstrap(store);

    if (path === "/api/login") return await login(req, store);
    // public self-serve access flows
    if (path === "/api/request-access") return await requestAccess(req, store);
    if (path === "/api/invite") return await inviteInfo(req, store);
    if (path === "/api/invite-accept") return await inviteAccept(req, store);

    // everything else requires a valid token
    const auth = requireAuth(req);
    if (!auth) return json({ error: "Not signed in" }, 401);

    if (path === "/api/me") return json({ user: auth });
    if (path === "/api/state") return await stateRoute(req, store, auth);
    if (path === "/api/import") return await importRoute(req, store, auth);
    if (path === "/api/users") return await usersRoute(req, store, auth);
    if (path === "/api/requests") return await requestsRoute(req, store, auth);
    if (path === "/api/sorted") return await sortedRoute(req, store, auth);
    if (path === "/api/leaderboard") return await leaderboardRoute(req, store, auth);
    return json({ error: "Not found" }, 404);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
}

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
  let u = await getUser(store, email || "");
  // Cold-start fallback: if the admin seed blob hasn't materialized yet but the
  // credentials match the admin env seed, authenticate and persist on the spot.
  if (!u) {
    const adminEmail = (process.env.ADMIN_EMAIL || "").toLowerCase().trim();
    if (adminEmail && String(email || "").toLowerCase().trim() === adminEmail &&
        process.env.ADMIN_SALT && process.env.ADMIN_HASH &&
        verifyPassword(password || "", process.env.ADMIN_SALT, process.env.ADMIN_HASH)) {
      u = { id: rid(), email: adminEmail, name: process.env.ADMIN_NAME || "Admin", role: "admin",
            salt: process.env.ADMIN_SALT, hash: process.env.ADMIN_HASH, createdAt: Date.now() };
      await putUser(store, u);
    }
  }
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
    const incoming = {
      feed: Array.isArray(b.feed) ? b.feed : [],
      bank: b.bank && typeof b.bank === "object" ? b.bank : {},
      passed: Array.isArray(b.passed) ? b.passed : [],
      archive: b.archive && typeof b.archive === "object" ? b.archive : {},
      recommended: Array.isArray(b.recommended) ? b.recommended : []
    };
    // Non-destructive save: rescue any submissions that landed on the server
    // after this admin loaded — cards they haven't decided on yet (not in their
    // feed/bank/passed/archive). Prevents an admin's save from wiping a
    // teammate's fresh submission under last-write-wins.
    const known = new Set();
    incoming.feed.forEach((c) => c && known.add(c.id));
    incoming.passed.forEach((c) => c && known.add(c.id));
    incoming.recommended.forEach((c) => c && known.add(c.id));
    Object.values(incoming.bank).forEach((a) => Array.isArray(a) && a.forEach((c) => c && known.add(c.id)));
    Object.values(incoming.archive).forEach((a) => Array.isArray(a) && a.forEach((c) => c && known.add(c.id)));
    const current = await getState(store);
    const rescuedFeed = (current.feed || []).filter((c) => c && c.id && !known.has(c.id));
    const rescuedRec = (current.recommended || []).filter((c) => c && c.id && !known.has(c.id));
    if (rescuedFeed.length) incoming.feed = [...rescuedFeed, ...incoming.feed];
    if (rescuedRec.length) incoming.recommended = [...rescuedRec, ...incoming.recommended];
    await setState(store, incoming);
    return json({ ok: true, rescued: rescuedFeed.length + rescuedRec.length });
  }
  return json({ error: "Method not allowed" }, 405);
}

async function importRoute(req, store, auth) {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  if (auth.role !== "admin" && auth.role !== "importer") return json({ error: "Not allowed" }, 403);
  const { url, title, format, urgent, target } = await req.json().catch(() => ({}));
  if (!url || !/^https?:\/\//i.test(url)) return json({ error: "A valid link is required" }, 400);
  const toRecommended = target === "recommended";
  // review submissions must be categorized; recommended-pool items don't need a format
  if (!toRecommended && !FORMATS.includes(format)) return json({ error: "Pick a format" }, 400);
  const resolved = await resolveUrl(url);
  const s = await getState(store);
  const card = {
    id: rid(), platform: detectPlatform(resolved), url: resolved,
    originalUrl: resolved !== url ? url : undefined,
    format: FORMATS.includes(format) ? format : undefined, urgent: !!urgent,
    title: (title || "").trim() || (toRecommended ? "Recommended clip" : "Imported reference"),
    author: "", desc: toRecommended ? "Recommended — open to preview." : "Submitted reference — open to preview.", img: "",
    submittedBy: auth.name || auth.email, submittedAt: Date.now()
  };
  if (toRecommended) {
    s.recommended = [card, ...(Array.isArray(s.recommended) ? s.recommended : [])];
  } else {
    s.feed = [card, ...(Array.isArray(s.feed) ? s.feed : [])];
  }
  await setState(store, s);
  if (!toRecommended) await incStat(store, auth.email, auth.name || auth.email, "imports", 1);
  return json({ ok: true, card });
}

async function usersRoute(req, store, auth) {
  if (auth.role !== "admin") return json({ error: "Admins only" }, 403);
  if (req.method === "GET") {
    const users = await listUsers(store);
    return json({ users: users.map(publicUser).sort((a, b) => a.createdAt - b.createdAt) });
  }
  if (req.method === "POST") {
    const b = await req.json().catch(() => ({}));
    // Address the target by email (strongly consistent); fall back to an id
    // scan only if no email was supplied. list() is eventually consistent, so
    // mutations must not depend on it.
    const target = async () => b.email ? await getUser(store, b.email)
      : (await listUsers(store)).find((u) => u.id === b.id);

    if (b.action === "delete") {
      const email = b.email ? String(b.email).toLowerCase().trim() : (await target())?.email;
      if (email) {
        if (email === auth.email) return json({ error: "You can't delete your own account" }, 400);
        await deleteUser(store, email); // delete by key directly — no dependency on a prior read
      }
      return json({ ok: true });
    }
    if (b.action === "role") {
      const t = await target();
      if (!t) return json({ error: "User not found" }, 404);
      if (t.email === auth.email && b.role !== "admin") return json({ error: "You can't remove your own admin access" }, 400);
      if (!ROLES.includes(b.role)) return json({ error: "Bad role" }, 400);
      t.role = b.role; await putUser(store, t);
      return json({ ok: true });
    }
    if (b.action === "password") {
      const t = await target();
      if (!t) return json({ error: "User not found" }, 404);
      if (String(b.password || "").length < 6) return json({ error: "Password must be at least 6 characters" }, 400);
      const { salt, hash } = hashPassword(b.password); t.salt = salt; t.hash = hash;
      await putUser(store, t);
      return json({ ok: true });
    }
    // create
    const email = String(b.email || "").toLowerCase().trim();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "Enter a valid email" }, 400);
    if (await getUser(store, email)) return json({ error: "That email already has an account" }, 409);
    if (String(b.password || "").length < 6) return json({ error: "Password must be at least 6 characters" }, 400);
    const role = ROLES.includes(b.role) ? b.role : "viewer";
    const { salt, hash } = hashPassword(b.password);
    const u = { id: rid(), email, name: (b.name || "").trim() || email.split("@")[0], role, salt, hash, createdAt: Date.now() };
    await putUser(store, u);
    return json({ ok: true, user: publicUser(u) });
  }
  return json({ error: "Method not allowed" }, 405);
}

/* --- public: someone requests access from the login screen --- */
async function requestAccess(req, store) {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const { email, name, note } = await req.json().catch(() => ({}));
  const e = String(email || "").toLowerCase().trim();
  if (!emailOk(e)) return json({ error: "Enter a valid email" }, 400);
  if (await getUser(store, e)) return json({ ok: true, already: true }); // already has access
  const existing = await getRequest(store, e);
  await putRequest(store, {
    email: e, name: String(name || "").trim().slice(0, 80), note: String(note || "").trim().slice(0, 300),
    createdAt: existing ? existing.createdAt : Date.now(), status: "pending"
  });
  return json({ ok: true });
}

/* --- public: read an invite (to render the "set your password" screen) --- */
async function inviteInfo(req, store) {
  const t = new URL(req.url).searchParams.get("token");
  const i = t ? await getInvite(store, t) : null;
  if (!i) return json({ valid: false }, 404);
  return json({ valid: true, email: i.email, role: i.role, name: i.name || "" });
}

/* --- public: redeem an invite by setting a password --- */
async function inviteAccept(req, store) {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const { token, password, name } = await req.json().catch(() => ({}));
  const i = token ? await getInvite(store, token) : null;
  if (!i) return json({ error: "This invite is invalid or has already been used" }, 400);
  if (String(password || "").length < 6) return json({ error: "Password must be at least 6 characters" }, 400);
  if (await getUser(store, i.email)) { await deleteInvite(store, token); return json({ error: "An account already exists for this email — try signing in" }, 409); }
  const { salt, hash } = hashPassword(password);
  const u = { id: rid(), email: i.email, name: String(name || i.name || "").trim() || i.email.split("@")[0], role: ROLES.includes(i.role) ? i.role : "viewer", salt, hash, createdAt: Date.now() };
  await putUser(store, u);
  await deleteInvite(store, token);
  await deleteRequest(store, i.email);
  const sess = sign({ sub: u.id, email: u.email, name: u.name, role: u.role, iat: Date.now(), exp: Date.now() + 30 * DAY });
  return json({ token: sess, user: publicUser(u) });
}

/* --- admin: list requests, approve/deny, or invite an email directly --- */
async function requestsRoute(req, store, auth) {
  if (auth.role !== "admin") return json({ error: "Admins only" }, 403);
  if (req.method === "GET") {
    const rs = await listRequests(store);
    return json({ requests: rs.sort((a, b) => a.createdAt - b.createdAt) });
  }
  if (req.method === "POST") {
    const b = await req.json().catch(() => ({}));
    const e = String(b.email || "").toLowerCase().trim();
    if (b.action === "deny") { if (e) await deleteRequest(store, e); return json({ ok: true }); }
    if (b.action === "approve" || b.action === "invite") {
      if (!emailOk(e)) return json({ error: "Valid email required" }, 400);
      if (await getUser(store, e)) return json({ error: "That email already has an account" }, 409);
      const role = ROLES.includes(b.role) ? b.role : "viewer";
      const token = rid() + rid().replace(/-/g, "").slice(0, 10);
      await putInvite(store, { token, email: e, role, name: String(b.name || "").trim(), createdBy: auth.email, createdAt: Date.now() });
      if (b.action === "approve") await deleteRequest(store, e);
      return json({ ok: true, token, email: e, role });
    }
    return json({ error: "Unknown action" }, 400);
  }
  return json({ error: "Method not allowed" }, 405);
}

/* Follow redirects on short/share links (vm.tiktok.com, tiktok.com/t/, etc.)
   to the canonical URL that contains the video id, so it can be embedded. */
async function resolveUrl(url) {
  const isShort = /(vm\.tiktok\.com|vt\.tiktok\.com|tiktok\.com\/t\/|\/share\/|instagr\.am)/i.test(url);
  const tiktokNoId = /tiktok\.com/i.test(url) && !/\/video\/\d+/.test(url);
  if (!isShort && !tiktokNoId) return url;
  try {
    const r = await fetch(url, {
      redirect: "follow",
      signal: AbortSignal.timeout(7000),
      headers: { "user-agent": "Mozilla/5.0 (compatible; SiftBot/1.0)" }
    });
    return r.url || url;
  } catch { return url; }
}

/* --- record that this user sorted (kept/passed) N videos --- */
async function sortedRoute(req, store, auth) {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const b = await req.json().catch(() => ({}));
  const n = Math.max(0, Math.min(1000, parseInt(b.count, 10) || 0));
  if (n > 0) await incStat(store, auth.email, auth.name || auth.email, "sorts", n);
  return json({ ok: true });
}

/* --- leaderboard (any signed-in user can view) --- */
async function leaderboardRoute(req, store) {
  const stats = await listStats(store);
  return json({ leaders: stats.map((s) => ({ email: s.email, name: s.name || s.email.split("@")[0], imports: s.imports || 0, sorts: s.sorts || 0 })) });
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

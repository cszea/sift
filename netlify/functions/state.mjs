import { getStore } from "@netlify/blobs";

/* First-run seed. Once anything is saved, the stored state wins. */
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

const KEY = "state";

export default async (req) => {
  const store = getStore("reelbank");
  try {
    if (req.method === "GET") {
      const state = await store.get(KEY, { type: "json" });
      return json(state ?? SEED);
    }
    if (req.method === "POST") {
      const body = await req.json();
      const clean = {
        feed: Array.isArray(body.feed) ? body.feed : [],
        bank: body.bank && typeof body.bank === "object" ? body.bank : {},
        passed: Array.isArray(body.passed) ? body.passed : []
      };
      await store.setJSON(KEY, clean);
      return json({ ok: true, savedAt: Date.now() });
    }
    return new Response("Method Not Allowed", { status: 405 });
  } catch (e) {
    return json({ error: String(e && e.message || e) }, 500);
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" }
  });
}

export const config = { path: "/api/state" };

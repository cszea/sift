# REEL·bank — video reference swipe app

Tinder-style triage for short-form video references (TikTok / Reels / Shorts). Swipe right to file a reference into a categorized bank, swipe left to pass with an optional reason. Data is stored in a **shared Netlify Blobs database**, so the bank is the same for every reviewer on every device.

## Stack
- `index.html` — the whole frontend (no build step).
- `netlify/functions/state.mjs` — one serverless function exposing `GET/POST /api/state`, backed by Netlify Blobs.
- `netlify.toml` — Netlify config (publish dir, functions dir, Node 20).
- `package.json` — declares `@netlify/blobs` (installed automatically by Netlify on deploy).

If opened as a plain file with no backend, it degrades gracefully to an offline/local cache so it still runs.

## Deploy (Git-connected — recommended, no local tooling needed)
1. Push this folder to a GitHub repo.
2. In Netlify: **Add new site → Import an existing project → GitHub → pick the repo.**
3. Leave build settings at defaults (publish = `.`, functions auto-detected). Click **Deploy**.
4. Netlify installs `@netlify/blobs`, deploys the function, and Blobs is enabled automatically. Done.

Every future `git push` redeploys automatically.

## Deploy (Netlify CLI — needs Node.js installed locally)
```bash
npm i -g netlify-cli
netlify login            # opens the browser to authorize
netlify deploy --build --prod
```

## The API
- `GET /api/state` → `{ feed, bank, passed }` (returns a seed set on first ever run)
- `POST /api/state` with the same JSON body → persists it

The whole app state is stored as a single JSON blob under the key `state` in the `reelbank` store. For a 2-reviewer internal tool this is plenty; if you ever need conflict-free concurrent editing, split it into per-item operations.

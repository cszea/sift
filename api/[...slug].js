import { getStore } from "@netlify/blobs";
import { handleRequest } from "../lib/app.mjs";

// Vercel: reach the same Netlify Blobs store over the network via a token.
export default async function handler(req, res) {
  const store = getStore({
    name: "reelbank",
    consistency: "strong",
    siteID: process.env.BLOBS_SITE_ID,
    token: process.env.BLOBS_TOKEN,
  });

  // Adapt Vercel's Node req/res into a Web Request the shared handler expects.
  const proto = req.headers["x-forwarded-proto"] || "https";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const fullUrl = `${proto}://${host}${req.url}`;

  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v != null) headers.set(k, Array.isArray(v) ? v.join(", ") : String(v));
  }

  let body;
  if (req.method !== "GET" && req.method !== "HEAD") {
    if (typeof req.body === "string") body = req.body;
    else if (Buffer.isBuffer(req.body)) body = req.body.toString("utf8");
    else if (req.body && typeof req.body === "object" && Object.keys(req.body).length) body = JSON.stringify(req.body);
  }

  const request = new Request(fullUrl, { method: req.method, headers, body });
  const response = await handleRequest(request, store);

  res.statusCode = response.status;
  response.headers.forEach((val, key) => {
    if (key.toLowerCase() === "content-encoding" || key.toLowerCase() === "content-length") return;
    res.setHeader(key, val);
  });
  res.end(await response.text());
}

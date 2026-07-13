import { getStore } from "@netlify/blobs";
import { handleRequest } from "../../lib/app.mjs";

// Netlify: Blobs is auto-configured from the function's site context.
export default async (req) =>
  handleRequest(req, getStore({ name: "reelbank", consistency: "strong" }));

export const config = { path: "/api/*" };

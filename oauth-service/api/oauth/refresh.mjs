import {
  exchangeRefreshToken,
  json,
  normalizeRegion,
  readJson,
  tokenResult,
} from "../_lib/oauth.mjs";

export default async function handler(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed." });
  try {
    const body = await readJson(req);
    const refreshToken = typeof body.refreshToken === "string" ? body.refreshToken.trim() : "";
    if (!refreshToken) return json(res, 400, { error: "Refresh token is required." });
    const tokens = await exchangeRefreshToken(refreshToken, normalizeRegion(body.region));
    return json(res, 200, { tokens: tokenResult(tokens) });
  } catch (error) {
    console.error("OAuth refresh failed.", error);
    return json(res, 401, { error: "Smartsheet authorization has expired. Please reconnect." });
  }
}

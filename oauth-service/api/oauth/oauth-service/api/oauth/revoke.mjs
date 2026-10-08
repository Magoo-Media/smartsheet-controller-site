import {
  json,
  normalizeRegion,
  readJson,
  revokeAccessToken,
} from "../_lib/oauth.mjs";

export default async function handler(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed." });
  try {
    const body = await readJson(req);
    const accessToken = typeof body.accessToken === "string" ? body.accessToken.trim() : "";
    if (!accessToken) return json(res, 400, { error: "Access token is required." });

    await revokeAccessToken(accessToken, normalizeRegion(body.region));
    return json(res, 200, { revoked: true });
  } catch (error) {
    console.error("OAuth revoke failed.", error);
    return json(res, 502, { error: "Smartsheet authorization could not be revoked." });
  }
}

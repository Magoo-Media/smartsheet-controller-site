import {
  buildAuthorizeUrl,
  hash,
  json,
  makeState,
  normalizeRegion,
  randomId,
  readJson,
  setSession,
} from "../_lib/oauth.mjs";

export default async function handler(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed." });
  try {
    const body = await readJson(req);
    const pollToken = typeof body.pollToken === "string" ? body.pollToken.trim() : "";
    if (pollToken.length < 32) return json(res, 400, { error: "Invalid OAuth transaction request." });

    const sessionId = randomId(24);
    const state = makeState(sessionId, randomId(24));
    await setSession(sessionId, {
      status: "pending",
      pollTokenHash: hash(pollToken),
      region: normalizeRegion(body.region),
      createdAt: Date.now(),
    });

    return json(res, 200, { sessionId, authorizeUrl: buildAuthorizeUrl(state) });
  } catch (error) {
    console.error("OAuth start failed.", error);
    return json(res, 500, { error: "OAuth setup is temporarily unavailable." });
  }
}

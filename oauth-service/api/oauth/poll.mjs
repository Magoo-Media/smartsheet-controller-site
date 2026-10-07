import {
  assertPollToken,
  deleteSession,
  getSession,
  json,
  readJson,
} from "../_lib/oauth.mjs";

export default async function handler(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed." });
  try {
    const body = await readJson(req);
    const sessionId = typeof body.sessionId === "string" ? body.sessionId.trim() : "";
    const pollToken = typeof body.pollToken === "string" ? body.pollToken.trim() : "";
    const session = await getSession(sessionId);
    assertPollToken(session, pollToken);

    if (session.status === "pending") return json(res, 200, { status: "pending" });
    await deleteSession(sessionId);
    if (session.status === "error") return json(res, 200, { status: "error", error: session.error });
    return json(res, 200, { status: "complete", tokens: session.tokens });
  } catch (error) {
    if (error instanceof SyntaxError) return json(res, 400, { error: "Invalid request." });
    return json(res, 400, { error: "Invalid or expired OAuth transaction." });
  }
}

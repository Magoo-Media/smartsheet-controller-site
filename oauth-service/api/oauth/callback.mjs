import {
  exchangeAuthorizationCode,
  getSession,
  html,
  json,
  parseState,
  setSession,
  successPage,
  tokenResult,
} from "../_lib/oauth.mjs";

export default async function handler(req, res) {
  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed." });
  try {
    const url = new URL(req.url, "https://oauth.invalid");
    const state = url.searchParams.get("state") ?? "";
    const { sessionId } = parseState(state);
    const session = await getSession(sessionId);
    if (!session) return html(res, 400, successPage("This authorization request has expired. Please try again from Stream Deck."));

    const oauthError = url.searchParams.get("error");
    if (oauthError) {
      await setSession(sessionId, { ...session, status: "error", error: "Smartsheet authorization was not completed." });
      return html(res, 400, successPage("Smartsheet authorization was not completed. You may close this window."));
    }

    const code = url.searchParams.get("code") ?? "";
    if (!code) return html(res, 400, successPage("Smartsheet did not return an authorization code."));

    const tokens = await exchangeAuthorizationCode(code, session.region);
    await setSession(sessionId, { ...session, status: "complete", tokens: tokenResult(tokens) });
    return html(res, 200, successPage());
  } catch (error) {
    console.error("OAuth callback failed.", error);
    return html(res, 500, successPage("The connection could not be completed. Return to Stream Deck and try again."));
  }
}

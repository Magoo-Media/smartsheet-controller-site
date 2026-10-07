import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const SESSION_TTL_SECONDS = 10 * 60;
const ALLOWED_REGIONS = new Set(["us", "eu", "au", "gov"]);
const API_BASE_URLS = {
  us: "https://api.smartsheet.com/2.0",
  eu: "https://api.smartsheet.eu/2.0",
  au: "https://api.smartsheet.au/2.0",
  gov: "https://api.smartsheetgov.com/2.0",
};

export function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

export function html(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(body);
}

export async function readJson(req) {
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 16 * 1024) throw new Error("Request body is too large.");
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export function requireEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}

export function requireEnvAny(names) {
  for (const name of names) {
    const value = process.env[name]?.trim();
    if (value) return value;
  }
  throw new Error(`Missing server configuration: ${names.join(" or ")}`);
}

export function normalizeRegion(value) {
  return ALLOWED_REGIONS.has(value) ? value : "us";
}

export function randomId(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function hash(value) {
  return createHmac("sha256", requireEnv("OAUTH_STATE_SECRET")).update(value).digest("hex");
}

export function makeState(sessionId, nonce) {
  const payload = `${sessionId}.${nonce}`;
  const signature = hash(payload);
  return Buffer.from(`${payload}.${signature}`, "utf8").toString("base64url");
}

export function parseState(state) {
  const decoded = Buffer.from(state, "base64url").toString("utf8");
  const parts = decoded.split(".");
  if (parts.length !== 3) throw new Error("Invalid OAuth state.");
  const [sessionId, nonce, signature] = parts;
  const expected = hash(`${sessionId}.${nonce}`);
  const actualBytes = Buffer.from(signature, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (actualBytes.length !== expectedBytes.length || !timingSafeEqual(actualBytes, expectedBytes)) {
    throw new Error("Invalid OAuth state signature.");
  }
  return { sessionId, nonce };
}

async function redis(command, ...args) {
  const url = requireEnvAny(["UPSTASH_REDIS_REST_URL", "KV_REST_API_URL"]).replace(/\/$/, "");
  const token = requireEnvAny(["UPSTASH_REDIS_REST_TOKEN", "KV_REST_API_TOKEN"]);
  const response = await fetch(`${url}/${command}/${args.map(encodeURIComponent).join("/")}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error(`Session storage returned HTTP ${response.status}.`);
  const body = await response.json();
  if (body.error) throw new Error("Session storage request failed.");
  return body.result;
}

export async function setSession(sessionId, value) {
  await redis("set", `smartsheet-oauth:${sessionId}`, JSON.stringify(value), "EX", SESSION_TTL_SECONDS);
}

export async function getSession(sessionId) {
  const value = await redis("get", `smartsheet-oauth:${sessionId}`);
  return value ? JSON.parse(value) : undefined;
}

export async function deleteSession(sessionId) {
  await redis("del", `smartsheet-oauth:${sessionId}`);
}

export function assertPollToken(session, pollToken) {
  if (!session?.pollTokenHash || !pollToken) throw new Error("Invalid OAuth transaction.");
  const actual = Buffer.from(hash(pollToken), "utf8");
  const expected = Buffer.from(session.pollTokenHash, "utf8");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new Error("Invalid OAuth transaction.");
  }
}

export function apiBase(region) {
  return API_BASE_URLS[normalizeRegion(region)];
}

export function buildAuthorizeUrl(state) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: requireEnv("SMARTSHEET_CLIENT_ID"),
    scope: "READ_SHEETS WRITE_SHEETS",
    state,
  });
  return `https://app.smartsheet.com/b/authorize?${params.toString()}`;
}

export async function exchangeAuthorizationCode(code, region) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: requireEnv("SMARTSHEET_CLIENT_ID"),
    client_secret: requireEnv("SMARTSHEET_CLIENT_SECRET"),
  });
  return tokenRequest(apiBase(region), body);
}

export async function exchangeRefreshToken(refreshToken, region) {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: requireEnv("SMARTSHEET_CLIENT_ID"),
    client_secret: requireEnv("SMARTSHEET_CLIENT_SECRET"),
  });
  return tokenRequest(apiBase(region), body);
}

async function tokenRequest(baseUrl, body) {
  const response = await fetch(`${baseUrl}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.access_token) {
    throw new Error("Smartsheet token exchange failed.");
  }
  return payload;
}

export function tokenResult(payload) {
  const expiresIn = Number(payload.expires_in);
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    expiresAt: Number.isFinite(expiresIn) && expiresIn > 0
      ? Date.now() + expiresIn * 1000
      : undefined,
  };
}

export function successPage(message = "Smartsheet is connected. You may close this window.") {
  return `<!doctype html><meta charset="utf-8"><title>Smartsheet Controller</title><style>body{font:16px system-ui,sans-serif;max-width:38rem;margin:4rem auto;padding:0 1rem;color:#222}h1{font-size:1.4rem}</style><h1>Smartsheet Controller</h1><p>${message}</p>`;
}

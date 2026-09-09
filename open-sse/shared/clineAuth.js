import crypto from "crypto";

export function getClineAccessToken(token) {
  if (typeof token !== "string") return "";
  let trimmed = token.trim();
  if (!trimmed) return "";
  if (trimmed.startsWith("Bearer ")) {
    trimmed = trimmed.slice(7).trim();
  }
  return trimmed.startsWith("workos:") ? trimmed : `workos:${trimmed}`;
}

export function getClineAuthorizationHeader(token) {
  const accessToken = getClineAccessToken(token);
  return accessToken ? `Bearer ${accessToken}` : "";
}

export function buildClineHeaders(token, extraHeaders = {}) {
  const authorization = getClineAuthorizationHeader(token);
  const headers = {
    "Content-Type": "application/json",
    "User-Agent": "Cline/3.0.47",
    "HTTP-Referer": "https://cline.bot",
    "X-Title": "Cline",
    "X-IS-MULTIROOT": "false",
    "X-CLIENT-TYPE": "cline-sdk",
    "X-CLIENT-VERSION": "3.0.47",
    "X-PLATFORM": "terminal",
    "X-PLATFORM-VERSION": "3.0.47",
    "X-CORE-VERSION": "0.0.66",
    "X-Task-ID": crypto.randomUUID(),
    ...extraHeaders,
  };

  if (authorization) {
    headers.Authorization = authorization;
  }

  return headers;
}


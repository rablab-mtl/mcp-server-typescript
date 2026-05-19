/**
 * Google OAuth handler for the DataForSEO MCP worker.
 *
 * Implements the OAuth 2.0 authorization code flow with Google as the identity
 * provider. Validates the authenticated user against an email allowlist before
 * completing the upstream OAuth flow back to the MCP client (Claude).
 *
 * Routes:
 *   GET /authorize  - entry point, redirects user to Google login
 *   GET /callback   - Google redirects here after user consent
 *   GET /health     - public health check (no auth)
 *   GET /           - public info page
 */

import { Hono } from "hono";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";

type Env = {
  OAUTH_PROVIDER: OAuthHelpers;
  OAUTH_KV: KVNamespace;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  ALLOWED_EMAILS?: string;
  ALLOWED_DOMAINS?: string;
};

const app = new Hono<{ Bindings: Env }>();

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function isEmailAllowed(email: string, env: Env): boolean {
  const normalized = email.trim().toLowerCase();

  const allowedEmails = (env.ALLOWED_EMAILS || "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);

  if (allowedEmails.includes(normalized)) return true;

  const allowedDomains = (env.ALLOWED_DOMAINS || "")
    .split(",")
    .map((d) => d.trim().toLowerCase().replace(/^@/, ""))
    .filter(Boolean);

  return allowedDomains.some((d) => normalized.endsWith(`@${d}`));
}

function callbackUrl(requestUrl: string): string {
  const u = new URL(requestUrl);
  return `${u.protocol}//${u.host}/callback`;
}

function renderDeniedPage(email: string): string {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Acces refuse</title>
  <style>
    body{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f5;
         color:#26372b;display:flex;align-items:center;justify-content:center;
         min-height:100vh;margin:0;padding:1rem}
    .card{background:#fff;padding:2rem 2.5rem;border-radius:12px;
          box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:480px;text-align:center}
    h1{color:#ec662a;margin:0 0 1rem;font-size:1.5rem}
    p{line-height:1.6;color:#26372b}
    code{background:#f5f5f5;padding:.15rem .4rem;border-radius:4px;
         font-size:.9em;color:#26372b}
  </style>
</head>
<body>
  <div class="card">
    <h1>Acces refuse</h1>
    <p>Le compte <code>${escapeHtml(email)}</code> n'est pas autorise a utiliser ce serveur MCP.</p>
    <p>Contacte l'administrateur de Rablab si tu penses que c'est une erreur.</p>
  </div>
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* -------------------------------------------------------------------------- */
/* Public routes                                                              */
/* -------------------------------------------------------------------------- */

app.get("/", (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8" />
<title>DataForSEO MCP (Rablab)</title>
<style>body{font-family:system-ui;color:#26372b;max-width:680px;margin:3rem auto;padding:0 1.5rem;line-height:1.6}
h1{color:#ec662a}code{background:#f5f5f5;padding:.15rem .4rem;border-radius:4px}</style>
</head><body>
<h1>DataForSEO MCP (Rablab)</h1>
<p>Serveur Model Context Protocol pour DataForSEO. Acces restreint via Google OAuth.</p>
<p>Endpoint MCP : <code>/mcp</code> (auth requise)</p>
<p>Health : <code>/health</code></p>
</body></html>`);
});

app.get("/health", (c) => {
  return c.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
  });
});

/* -------------------------------------------------------------------------- */
/* OAuth flow                                                                 */
/* -------------------------------------------------------------------------- */

// Step 1: client (Claude) hits /authorize. We parse the OAuth request and
// redirect the user's browser to Google for sign-in.
app.get("/authorize", async (c) => {
  let oauthReqInfo: AuthRequest;
  try {
    oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
  } catch (err) {
    return c.text(`Invalid OAuth request: ${(err as Error).message}`, 400);
  }

  if (!oauthReqInfo.clientId) {
    return c.text("Missing client_id", 400);
  }

  // Encode the original OAuth request inside the Google state param so we can
  // resume it after Google redirects back to /callback.
  const state = btoa(JSON.stringify(oauthReqInfo));

  const googleAuthUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  googleAuthUrl.searchParams.set("client_id", c.env.GOOGLE_CLIENT_ID);
  googleAuthUrl.searchParams.set("redirect_uri", callbackUrl(c.req.url));
  googleAuthUrl.searchParams.set("response_type", "code");
  googleAuthUrl.searchParams.set("scope", "openid email profile");
  googleAuthUrl.searchParams.set("state", state);
  googleAuthUrl.searchParams.set("access_type", "online");
  googleAuthUrl.searchParams.set("prompt", "select_account");

  return c.redirect(googleAuthUrl.toString());
});

// Step 2: Google redirects here after user authentication. We exchange the
// auth code for a Google access token, fetch the user's email, check it against
// the allowlist, then hand control back to the OAuth provider so it can issue
// our own access token to the MCP client.
app.get("/callback", async (c) => {
  const code = c.req.query("code");
  const stateRaw = c.req.query("state");
  const errorParam = c.req.query("error");

  if (errorParam) {
    return c.text(`Google OAuth error: ${errorParam}`, 400);
  }
  if (!code || !stateRaw) {
    return c.text("Missing code or state parameter", 400);
  }

  let oauthReqInfo: AuthRequest;
  try {
    oauthReqInfo = JSON.parse(atob(stateRaw)) as AuthRequest;
  } catch {
    return c.text("Invalid state parameter", 400);
  }

  // Exchange Google authorization code for an access token
  const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: c.env.GOOGLE_CLIENT_ID,
      client_secret: c.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: callbackUrl(c.req.url),
      grant_type: "authorization_code",
    }),
  });

  if (!tokenResp.ok) {
    const errText = await tokenResp.text();
    return c.text(`Token exchange failed: ${errText}`, 500);
  }

  const tokenData = (await tokenResp.json()) as { access_token?: string };
  if (!tokenData.access_token) {
    return c.text("No access token in Google response", 500);
  }

  // Fetch user profile
  const userResp = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });
  if (!userResp.ok) {
    return c.text("Failed to fetch user info from Google", 500);
  }

  const user = (await userResp.json()) as {
    email: string;
    email_verified?: boolean;
    name?: string;
    sub: string;
  };

  if (!user.email_verified) {
    return c.html(renderDeniedPage(user.email + " (non verifie)"), 403);
  }

  if (!isEmailAllowed(user.email, c.env)) {
    return c.html(renderDeniedPage(user.email), 403);
  }

  // Email passes the allowlist - complete the OAuth flow back to the MCP client
  const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthReqInfo,
    userId: user.sub,
    metadata: {
      label: user.name || user.email,
    },
    scope: oauthReqInfo.scope,
    props: {
      email: user.email,
      name: user.name || "",
      sub: user.sub,
    },
  });

  return c.redirect(redirectTo);
});

export { app as GoogleHandler };

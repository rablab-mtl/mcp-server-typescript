/**
 * OAuth-protected entry point for the DataForSEO MCP worker.
 *
 * Wraps the existing DataForSEOMcpAgent with @cloudflare/workers-oauth-provider
 * so the /mcp and /sse endpoints require a valid OAuth access token. Tokens are
 * issued only after a successful Google sign-in by a user whose email matches
 * the configured allowlist (see google-handler.ts).
 */

import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { DataForSEOMcpAgent } from "./index-worker.js";
import { GoogleHandler } from "./google-handler.js";

// The Durable Object class must be re-exported so wrangler can bind it.
export { DataForSEOMcpAgent };

export default new OAuthProvider({
  apiHandlers: {
    "/mcp": DataForSEOMcpAgent.serve("/mcp") as never,
    "/sse": DataForSEOMcpAgent.serveSSE("/sse") as never,
  },
  defaultHandler: GoogleHandler as never,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
});

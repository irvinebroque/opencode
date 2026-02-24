/**
 * OAuth flow executor for webfetch authentication.
 *
 * Supports:
 * - Authorization Code + PKCE / RFC 7636 (interactive, opens browser)
 * - Device Authorization Grant / RFC 8628 (headless/SSH)
 * - Dynamic Client Registration / RFC 7591
 *
 * PKCE implementation adapted from the audited irvinebroque/http-rfc-utils
 * (src/auth/pkce.ts) which validates per RFC 7636 §4.1-§4.6.
 *
 * Key RFC compliance points:
 * - RFC 7636 §4.1: code_verifier uses unreserved chars, 43-128 characters
 * - RFC 7636 §4.2: S256 challenge = BASE64URL(SHA256(verifier))
 * - RFC 8628 §3.5: slow_down MUST increase interval by 5 seconds
 * - RFC 7591 §2: client registration request format
 * - RFC 6749 §5.2: error response format for token endpoint
 *
 * @see https://www.rfc-editor.org/rfc/rfc7636.html
 * @see https://www.rfc-editor.org/rfc/rfc8628.html
 * @see https://www.rfc-editor.org/rfc/rfc7591.html
 */

import { Log } from "../util/log"
import type { ASMetadata, ResourceMetadata } from "./discovery"
import * as WebFetchAuth from "./webfetch-auth"

const log = Log.create({ service: "webfetch.flow" })

const CALLBACK_PORT = 19877
const CALLBACK_PATH = "/webfetch/oauth/callback"
const CALLBACK_TIMEOUT = 5 * 60 * 1000 // 5 minutes

// ---------------------------------------------------------------------------
// PKCE — adapted from irvinebroque/http-rfc-utils src/auth/pkce.ts
// RFC 7636 §4.1-§4.2
// ---------------------------------------------------------------------------

/**
 * RFC 7636 §4.1: code_verifier character set validation.
 * code-verifier = 43*128unreserved
 * unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
 */
const PKCE_RE = /^[A-Za-z0-9\-._~]{43,128}$/

function base64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  const binary = String.fromCharCode(...bytes)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/**
 * Generate PKCE code_verifier and code_challenge per RFC 7636 §4.1-§4.2.
 *
 * The verifier is 32 cryptographically random bytes encoded as base64url,
 * producing a 43-character string (minimum per RFC 7636 §4.1).
 * The challenge is BASE64URL(SHA256(ASCII(verifier))) per Appendix A.
 */
export async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer)
  if (!PKCE_RE.test(verifier)) throw new Error("PKCE verifier generation produced invalid value")
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))
  const challenge = base64url(hash)
  return { verifier, challenge }
}

/** Generate a cryptographically random state parameter (32 bytes, base64url). */
export function state(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer)
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration — RFC 7591
// ---------------------------------------------------------------------------

export type ClientInfo = {
  client_id: string
  client_secret?: string
}

/**
 * Register a client dynamically per RFC 7591 §2.
 *
 * Sends a registration request to the AS's registration_endpoint with
 * metadata about the client (redirect URIs, name, grant types).
 * Uses token_endpoint_auth_method "none" (public client).
 *
 * @see https://www.rfc-editor.org/rfc/rfc7591.html#section-2
 */
export async function register(
  metadata: ASMetadata,
  redirectUri: string,
): Promise<ClientInfo | undefined> {
  if (!metadata.registration_endpoint) return undefined

  log.info("attempting dynamic client registration", { endpoint: metadata.registration_endpoint })

  const response = await fetch(metadata.registration_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      redirect_uris: [redirectUri],
      client_name: "OpenCode",
      client_uri: "https://opencode.ai",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  }).catch(() => undefined)

  if (!response || !response.ok) {
    log.info("dynamic registration failed", { status: response?.status })
    return undefined
  }

  const body = (await response.json().catch(() => undefined)) as
    | { client_id: string; client_secret?: string }
    | undefined
  if (!body || !body.client_id) return undefined

  log.info("dynamic registration succeeded", { client_id: body.client_id })
  return { client_id: body.client_id, client_secret: body.client_secret }
}

// ---------------------------------------------------------------------------
// HTML pages for callback server
// ---------------------------------------------------------------------------

/**
 * Escape HTML special characters to prevent XSS injection.
 * Error messages from authorization servers are untrusted input and
 * MUST be escaped before interpolation into HTML.
 */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

const HTML_SUCCESS = `<!DOCTYPE html>
<html>
<head>
  <title>OpenCode - Authorization Successful</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #1a1a2e; color: #eee; }
    .container { text-align: center; padding: 2rem; }
    h1 { color: #4ade80; margin-bottom: 1rem; }
    p { color: #aaa; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Authorization Successful</h1>
    <p>You can close this window and return to OpenCode.</p>
  </div>
  <script>setTimeout(() => window.close(), 2000);</script>
</body>
</html>`

function htmlError(error: string): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>OpenCode - Authorization Failed</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #1a1a2e; color: #eee; }
    .container { text-align: center; padding: 2rem; }
    h1 { color: #f87171; margin-bottom: 1rem; }
    p { color: #aaa; }
    .error { color: #fca5a5; font-family: monospace; margin-top: 1rem; padding: 1rem; background: rgba(248,113,113,0.1); border-radius: 0.5rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Authorization Failed</h1>
    <p>An error occurred during authorization.</p>
    <div class="error">${escapeHtml(error)}</div>
  </div>
</body>
</html>`
}

// ---------------------------------------------------------------------------
// Token response type — RFC 6749 §5.1-§5.2
// ---------------------------------------------------------------------------

type TokenResponse = {
  access_token?: string
  refresh_token?: string
  expires_in?: number
  scope?: string
  error?: string
  error_description?: string
  error_uri?: string
}

// ---------------------------------------------------------------------------
// Authorization Code + PKCE — RFC 6749 §4.1, RFC 7636
// ---------------------------------------------------------------------------

/**
 * Execute the Authorization Code + PKCE flow.
 *
 * 1. Start a local callback server on an available port
 * 2. Build the authorization URL with PKCE challenge and state
 * 3. Open the browser for user authorization
 * 4. Wait for the callback with the authorization code
 * 5. Exchange the code for tokens at the token endpoint
 *
 * The redirect_uri is built AFTER the server starts to ensure the port
 * matches the actual listening port (fixes port mismatch bug when
 * CALLBACK_PORT is already in use).
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1
 * @see https://www.rfc-editor.org/rfc/rfc7636.html
 * @see https://www.rfc-editor.org/rfc/rfc8707.html (resource parameter)
 */
export async function authorizationCode(
  resource: string,
  resourceMeta: ResourceMetadata,
  asMeta: ASMetadata,
  client: ClientInfo,
  scopes?: string[],
): Promise<WebFetchAuth.Credential | undefined> {
  if (!asMeta.authorization_endpoint || !asMeta.token_endpoint) {
    log.error("AS missing required endpoints", { issuer: asMeta.issuer })
    return undefined
  }

  const codes = await pkce()
  const st = state()
  const scope = scopes?.join(" ") ?? resourceMeta.scopes_supported?.join(" ") ?? ""

  // Start callback server FIRST to get the actual port
  const result = await callbackServer(st, (port) => {
    const redirectUri = `http://127.0.0.1:${port}${CALLBACK_PATH}`
    const params = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: redirectUri,
      state: st,
      code_challenge: codes.challenge,
      code_challenge_method: "S256",
    })
    if (scope) params.set("scope", scope)
    // RFC 8707: request audience-restricted tokens
    params.set("resource", resourceMeta.resource)
    return `${asMeta.authorization_endpoint}?${params.toString()}`
  })
  if (!result) return undefined

  const redirectUri = `http://127.0.0.1:${result.port}${CALLBACK_PATH}`

  // Exchange code for tokens — RFC 6749 §4.1.3
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: result.code,
    redirect_uri: redirectUri,
    client_id: client.client_id,
    code_verifier: codes.verifier,
  })
  if (client.client_secret) body.set("client_secret", client.client_secret)

  const response = await fetch(asMeta.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  }).catch(() => undefined)

  if (!response) {
    log.error("token exchange network error")
    return undefined
  }

  // RFC 6749 §5.2: parse error response
  const tokens = (await response.json().catch(() => ({}))) as TokenResponse

  if (!response.ok || !tokens.access_token) {
    log.error("token exchange failed", {
      status: response.status,
      error: tokens.error,
      description: tokens.error_description,
    })
    return undefined
  }

  const cred: WebFetchAuth.Credential = {
    resource: resourceMeta.resource,
    scheme: "bearer",
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: tokens.expires_in ? Date.now() / 1000 + tokens.expires_in : undefined,
    scope: tokens.scope ?? scope,
    oauth_client_id: client.client_id,
    oauth_client_secret: client.client_secret,
    issuer: asMeta.issuer,
  }

  await WebFetchAuth.set(resourceMeta.resource, cred)
  return cred
}

// ---------------------------------------------------------------------------
// Device Authorization Grant — RFC 8628
// ---------------------------------------------------------------------------

export type DeviceInfo = {
  verification_uri: string
  user_code: string
}

/**
 * Initiate the Device Authorization Grant per RFC 8628 §3.1-§3.2.
 *
 * Returns device info for the user to visit a URL and enter a code,
 * plus a poll() function that polls the token endpoint.
 *
 * Key compliance point — RFC 8628 §3.5:
 * When the server returns "slow_down", the client MUST increase the
 * polling interval by 5 seconds for ALL subsequent requests.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8628.html
 */
export async function deviceCode(
  resource: string,
  resourceMeta: ResourceMetadata,
  asMeta: ASMetadata,
  client: ClientInfo,
  scopes?: string[],
): Promise<{ info: DeviceInfo; poll: () => Promise<WebFetchAuth.Credential | undefined> } | undefined> {
  if (!asMeta.device_authorization_endpoint || !asMeta.token_endpoint) {
    log.info("AS does not support device code flow", { issuer: asMeta.issuer })
    return undefined
  }

  const scope = scopes?.join(" ") ?? resourceMeta.scopes_supported?.join(" ") ?? ""
  const body = new URLSearchParams({ client_id: client.client_id })
  if (scope) body.set("scope", scope)
  // RFC 8707: audience-restricted tokens
  body.set("resource", resourceMeta.resource)

  const response = await fetch(asMeta.device_authorization_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  }).catch(() => undefined)

  if (!response || !response.ok) {
    log.error("device authorization failed", { status: response?.status })
    return undefined
  }

  const data = (await response.json().catch(() => undefined)) as {
    device_code: string
    user_code: string
    verification_uri: string
    verification_uri_complete?: string
    expires_in?: number
    interval?: number
  } | undefined

  if (!data || !data.device_code || !data.user_code || !data.verification_uri) return undefined

  // RFC 8628 §3.2: default polling interval is 5 seconds
  let interval = (data.interval ?? 5) * 1000
  const deadline = Date.now() + (data.expires_in ?? 300) * 1000

  const info: DeviceInfo = {
    verification_uri: data.verification_uri_complete ?? data.verification_uri,
    user_code: data.user_code,
  }

  async function poll(): Promise<WebFetchAuth.Credential | undefined> {
    while (Date.now() < deadline) {
      await Bun.sleep(interval)

      const body = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: data!.device_code,
        client_id: client.client_id,
      })

      const response = await fetch(asMeta.token_endpoint!, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }).catch(() => undefined)

      if (!response) continue

      const json = (await response.json().catch(() => ({}))) as TokenResponse

      if (response.ok && json.access_token) {
        const cred: WebFetchAuth.Credential = {
          resource: resourceMeta.resource,
          scheme: "bearer",
          access_token: json.access_token,
          refresh_token: json.refresh_token,
          expires_at: json.expires_in ? Date.now() / 1000 + json.expires_in : undefined,
          scope: json.scope ?? scope,
          oauth_client_id: client.client_id,
          oauth_client_secret: client.client_secret,
          issuer: asMeta.issuer,
        }
        await WebFetchAuth.set(resourceMeta.resource, cred)
        return cred
      }

      // RFC 8628 §3.5: "slow_down" — MUST increase interval by 5 seconds
      if (json.error === "slow_down") {
        interval += 5000
        continue
      }
      if (json.error === "authorization_pending") continue

      // RFC 8628 §3.5: any other error is a terminal failure
      log.error("device code poll failed", {
        error: json.error,
        description: json.error_description,
        status: response.status,
      })
      return undefined
    }

    log.error("device code flow timed out")
    return undefined
  }

  return { info, poll }
}

// ---------------------------------------------------------------------------
// Local callback server for authorization code flow
// ---------------------------------------------------------------------------

let server: ReturnType<typeof Bun.serve> | undefined

type CallbackResult = { code: string; port: number }

/**
 * Start a local HTTP callback server, open the browser, and wait for the
 * authorization code callback.
 *
 * The buildAuthUrl callback receives the actual port the server is listening
 * on, ensuring the redirect_uri always matches. This prevents the port mismatch
 * bug where the URL encodes port 19877 but the server is on 19878+.
 *
 * @param expected - Expected state parameter for CSRF validation
 * @param buildAuthUrl - Callback that receives actual port, returns the authorization URL
 */
async function callbackServer(
  expected: string,
  buildAuthUrl: (port: number) => string,
): Promise<CallbackResult | undefined> {
  return new Promise((resolve) => {
    let timeout: ReturnType<typeof setTimeout>
    let port = CALLBACK_PORT

    function cleanup() {
      clearTimeout(timeout)
      if (server) {
        server.stop()
        server = undefined
      }
    }

    // Try to start server, handling port conflicts
    for (let i = 0; i < 10; i++) {
      try {
        server = Bun.serve({
          port,
          fetch(req) {
            const url = new URL(req.url)
            if (url.pathname !== CALLBACK_PATH) {
              return new Response("Not found", { status: 404 })
            }

            const code = url.searchParams.get("code")
            const st = url.searchParams.get("state")
            const error = url.searchParams.get("error")
            const desc = url.searchParams.get("error_description")

            // CSRF check — state must match
            if (!st || st !== expected) {
              return new Response(htmlError("Invalid state parameter"), {
                status: 400,
                headers: { "Content-Type": "text/html" },
              })
            }

            if (error) {
              cleanup()
              resolve(undefined)
              return new Response(htmlError(desc ?? error), {
                headers: { "Content-Type": "text/html" },
              })
            }

            if (!code) {
              cleanup()
              resolve(undefined)
              return new Response(htmlError("No authorization code"), {
                status: 400,
                headers: { "Content-Type": "text/html" },
              })
            }

            cleanup()
            resolve({ code, port })
            return new Response(HTML_SUCCESS, {
              headers: { "Content-Type": "text/html" },
            })
          },
        })
        break
      } catch {
        port++
        if (i === 9) {
          log.error("could not find open port for callback server")
          resolve(undefined)
          return
        }
      }
    }

    // Build auth URL with the actual port the server is on
    const authUrl = buildAuthUrl(port)

    // Open browser
    const open =
      process.platform === "darwin"
        ? "open"
        : process.platform === "win32"
          ? "start"
          : "xdg-open"
    Bun.spawn([open, authUrl], { stdout: "ignore", stderr: "ignore" })

    log.info("opened browser for authorization", { url: authUrl, port })

    timeout = setTimeout(() => {
      log.error("authorization callback timed out")
      cleanup()
      resolve(undefined)
    }, CALLBACK_TIMEOUT)
  })
}

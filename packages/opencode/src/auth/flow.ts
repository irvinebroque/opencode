/**
 * OAuth flow executor for webfetch authentication.
 *
 * Supports:
 * - Authorization Code + PKCE (interactive, opens browser)
 * - Device Authorization Grant / RFC 8628 (headless/SSH)
 * - Dynamic Client Registration / RFC 7591
 *
 * Reuses proven patterns from mcp/oauth-callback.ts and plugin/codex.ts.
 */

import { Log } from "../util/log"
import type { ASMetadata, ResourceMetadata } from "./discovery"
import { type Credential, set as storeCredential } from "./webfetch-auth"

const log = Log.create({ service: "webfetch.flow" })

const CALLBACK_PORT = 19877
const CALLBACK_PATH = "/webfetch/oauth/callback"
const CALLBACK_TIMEOUT = 5 * 60 * 1000 // 5 minutes
const DEVICE_POLL_INTERVAL = 5000

// PKCE generation per RFC 7636

function base64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  const binary = String.fromCharCode(...bytes)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  // RFC 7636 Section 4.1: verifier uses unreserved chars [A-Z / a-z / 0-9 / "-" / "." / "_" / "~"]
  // 43-128 chars, minimum 32 bytes entropy. base64url of 32 random bytes = 43 chars, unbiased.
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer)
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))
  return { verifier, challenge: base64url(hash) }
}

function state(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer)
}

// Dynamic Client Registration (RFC 7591)

type ClientInfo = {
  client_id: string
  client_secret?: string
}

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

  const body = (await response.json()) as { client_id: string; client_secret?: string }
  if (!body.client_id) return undefined

  log.info("dynamic registration succeeded", { client_id: body.client_id })
  return { client_id: body.client_id, client_secret: body.client_secret }
}

// HTML pages for callback server

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

const HTML_ERROR = (error: string) => `<!DOCTYPE html>
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
    <div class="error">${error}</div>
  </div>
</body>
</html>`

// Authorization Code + PKCE flow

type AuthResult = {
  access_token: string
  refresh_token?: string
  expires_in?: number
  scope?: string
}

export async function authorizationCode(
  resource: string,
  resourceMeta: ResourceMetadata,
  asMeta: ASMetadata,
  client: ClientInfo,
  scopes?: string[],
): Promise<Credential | undefined> {
  if (!asMeta.authorization_endpoint || !asMeta.token_endpoint) {
    log.error("AS missing required endpoints", { issuer: asMeta.issuer })
    return undefined
  }

  const codes = await pkce()
  const st = state()
  const redirectUri = `http://127.0.0.1:${CALLBACK_PORT}${CALLBACK_PATH}`
  const scope = scopes?.join(" ") ?? resourceMeta.scopes_supported?.join(" ") ?? ""

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

  const authUrl = `${asMeta.authorization_endpoint}?${params.toString()}`

  // Start callback server and wait for code
  const code = await callbackServer(st, authUrl)
  if (!code) return undefined

  // Exchange code for tokens
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: client.client_id,
    code_verifier: codes.verifier,
  })
  if (client.client_secret) body.set("client_secret", client.client_secret)

  const response = await fetch(asMeta.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  })

  if (!response.ok) {
    log.error("token exchange failed", { status: response.status })
    return undefined
  }

  const tokens = (await response.json()) as AuthResult
  const cred: Credential = {
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

  await storeCredential(resourceMeta.resource, cred)
  return cred
}

// Device Authorization Grant (RFC 8628)

export type DeviceInfo = {
  verification_uri: string
  user_code: string
}

export async function deviceCode(
  resource: string,
  resourceMeta: ResourceMetadata,
  asMeta: ASMetadata,
  client: ClientInfo,
  scopes?: string[],
): Promise<{ info: DeviceInfo; poll: () => Promise<Credential | undefined> } | undefined> {
  if (!asMeta.device_authorization_endpoint || !asMeta.token_endpoint) {
    log.info("AS does not support device code flow", { issuer: asMeta.issuer })
    return undefined
  }

  const scope = scopes?.join(" ") ?? resourceMeta.scopes_supported?.join(" ") ?? ""
  const body = new URLSearchParams({ client_id: client.client_id })
  if (scope) body.set("scope", scope)
  body.set("resource", resourceMeta.resource)

  const response = await fetch(asMeta.device_authorization_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  })

  if (!response.ok) {
    log.error("device authorization failed", { status: response.status })
    return undefined
  }

  const data = (await response.json()) as {
    device_code: string
    user_code: string
    verification_uri: string
    verification_uri_complete?: string
    expires_in?: number
    interval?: number
  }

  const interval = (data.interval ?? 5) * 1000
  const deadline = Date.now() + (data.expires_in ?? 300) * 1000

  const info: DeviceInfo = {
    verification_uri: data.verification_uri_complete ?? data.verification_uri,
    user_code: data.user_code,
  }

  async function poll(): Promise<Credential | undefined> {
    while (Date.now() < deadline) {
      await Bun.sleep(interval)

      const body = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: data.device_code,
        client_id: client.client_id,
      })

      const response = await fetch(asMeta.token_endpoint!, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      })

      const json = (await response.json().catch(() => ({}))) as AuthResult & { error?: string }

      if (response.ok && json.access_token) {
        const cred: Credential = {
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
        await storeCredential(resourceMeta.resource, cred)
        return cred
      }

      // Check for "authorization_pending" or "slow_down"
      if (json.error === "slow_down") {
        await Bun.sleep(interval) // extra wait
        continue
      }
      if (json.error === "authorization_pending") continue

      // Any other error means failure
      log.error("device code poll failed", { error: json.error, status: response.status })
      return undefined
    }

    log.error("device code flow timed out")
    return undefined
  }

  return { info, poll }
}

// Local callback server for authorization code flow

let server: ReturnType<typeof Bun.serve> | undefined

async function callbackServer(expected: string, authUrl: string): Promise<string | undefined> {
  return new Promise((resolve) => {
    let timeout: ReturnType<typeof setTimeout>

    function cleanup() {
      clearTimeout(timeout)
      if (server) {
        server.stop()
        server = undefined
      }
    }

    // Try to start server, handling port conflicts
    let port = CALLBACK_PORT
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

            if (!st || st !== expected) {
              return new Response(HTML_ERROR("Invalid state parameter"), {
                status: 400,
                headers: { "Content-Type": "text/html" },
              })
            }

            if (error) {
              cleanup()
              resolve(undefined)
              return new Response(HTML_ERROR(desc ?? error), {
                headers: { "Content-Type": "text/html" },
              })
            }

            if (!code) {
              cleanup()
              resolve(undefined)
              return new Response(HTML_ERROR("No authorization code"), {
                status: 400,
                headers: { "Content-Type": "text/html" },
              })
            }

            cleanup()
            resolve(code)
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

    // Open browser
    const open = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open"
    Bun.spawn([open, authUrl], { stdout: "ignore", stderr: "ignore" })

    log.info("opened browser for authorization", { url: authUrl, port })

    timeout = setTimeout(() => {
      log.error("authorization callback timed out")
      cleanup()
      resolve(undefined)
    }, CALLBACK_TIMEOUT)
  })
}

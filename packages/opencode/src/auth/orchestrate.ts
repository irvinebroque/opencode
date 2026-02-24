/**
 * Auth orchestration for webfetch.
 *
 * Handles the full OAuth flow when webfetch encounters a 401/403:
 *
 * Flow: 401/403 -> parse WWW-Authenticate (RFC 9110 §11.6.1)
 *       -> discover resource metadata (RFC 9728)
 *       -> discover AS metadata (RFC 8414)
 *       -> dynamic client registration (RFC 7591) or use stored client
 *       -> OAuth authorization code + PKCE (RFC 7636) or device code (RFC 8628)
 *       -> retry request with credentials
 *
 * @see https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1
 * @see https://www.rfc-editor.org/rfc/rfc9728.html
 */

import { Log } from "../util/log"
import * as WebFetchAuth from "./webfetch-auth"
import * as WwwAuthenticate from "./www-authenticate"
import * as Discovery from "./discovery"
import * as Flow from "./flow"

const log = Log.create({ service: "webfetch.auth" })

export type AskFn = (opts: {
  permission: string
  patterns: string[]
  always: string[]
  metadata: Record<string, string>
}) => Promise<void>

function credential(resource: string, tokens: Flow.TokenResult, issuer: string): WebFetchAuth.Credential {
  return {
    resource,
    scheme: "bearer",
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: tokens.expires_in ? Date.now() / 1000 + tokens.expires_in : undefined,
    scope: tokens.scope,
    oauth_client_id: tokens.client.client_id,
    oauth_client_secret: tokens.client.client_secret,
    issuer,
  }
}

export async function handleAuth(
  response: Response,
  url: string,
  base: Record<string, string>,
  signal: AbortSignal,
  ask: AskFn,
): Promise<Response | undefined> {
  log.info("auth required", { url, status: response.status })

  // 1. Parse WWW-Authenticate challenges — RFC 9110 §11.6.1
  //    Extract resource_metadata URL from Bearer challenge — RFC 9728 §5.1
  const challenges = WwwAuthenticate.all(response)
  const metaUrl = WwwAuthenticate.resourceMetadataUrl(challenges)

  // 2. Discovery — RFC 9728 §4 (resource metadata) + RFC 8414 §3 (AS metadata)
  const result = await Discovery.discover(url, metaUrl ?? undefined, signal)

  if (!result.resource || !result.servers.length) {
    // Basic auth challenge without discovery — RFC 7617
    const basic = challenges.find((c) => c.scheme.toLowerCase() === "basic")
    if (basic) {
      log.info("basic auth challenge detected", { realm: basic.params["realm"] })
      throw new Error(
        `This URL requires Basic authentication (realm: ${basic.params["realm"] ?? "unknown"}). ` +
          `Configure credentials for this origin in the webfetch auth store.`,
      )
    }

    log.info("no auth discovery available", { url, challenges: challenges.length })
    return undefined
  }

  const server = result.servers[0]!

  // 3. Client resolution — RFC 7591 §2 (dynamic registration) or stored credentials.
  //    Registration is NOT done here for auth code flow — it is deferred to
  //    authorizationCode() which registers after the callback server binds,
  //    ensuring the redirect_uri port matches the actual listening port.
  let client: Flow.ClientInfo | undefined

  const existing = await WebFetchAuth.get(url).catch(() => undefined)
  if (existing?.oauth_client_id) {
    client = { client_id: existing.oauth_client_id, client_secret: existing.oauth_client_secret }
  }

  // 4. Prompt user for consent
  await ask({
    permission: "webfetch",
    patterns: [url],
    always: [new URL(url).origin + "/*"],
    metadata: {
      url,
      action: "authenticate",
      server: server.issuer,
      scopes: (result.resource.scopes_supported?.join(", ") ?? "default") + " (server-reported, unverified)",
    },
  })

  // 5. Execute OAuth flow — RFC 6749 §4.1 (auth code) + RFC 7636 (PKCE)
  const supports = server.grant_types_supported ?? ["authorization_code"]
  let cred: WebFetchAuth.Credential | undefined

  if (supports.includes("authorization_code") && server.authorization_endpoint) {
    const tokens = await Flow.authorizationCode(
      url,
      result.resource,
      server,
      client,
      result.resource.scopes_supported,
    )
    if (tokens) {
      cred = credential(result.resource.resource, tokens, server.issuer)
      await WebFetchAuth.set(result.resource.resource, cred)
    }
  }

  // Fallback: Device Authorization Grant — RFC 8628 §3.1
  if (
    !cred &&
    supports.includes("urn:ietf:params:oauth:grant-type:device_code") &&
    server.device_authorization_endpoint
  ) {
    // Register for device code if no client yet (device code doesn't use redirect_uri
    // in the flow itself, so the hardcoded port is acceptable for registration metadata)
    if (!client && server.registration_endpoint) {
      client = (await Flow.register(server, "http://127.0.0.1:19877/webfetch/oauth/callback")) ?? undefined
    }
    if (client) {
      const device = await Flow.deviceCode(url, result.resource, server, client, result.resource.scopes_supported)
      if (device) {
        log.info("device code flow", {
          uri: device.info.verification_uri,
          code: device.info.user_code,
        })
        const tokens = await device.poll()
        if (tokens) {
          cred = credential(result.resource.resource, tokens, server.issuer)
          await WebFetchAuth.set(result.resource.resource, cred)
        }
      }
    }
  }

  if (!cred) {
    if (!client) {
      const docs = server.service_documentation ?? server.issuer
      throw new Error(
        `This URL requires OAuth authentication via ${server.issuer}, ` +
          `but no client_id is configured and dynamic registration is not available. ` +
          `Register a client at ${docs} and configure it in opencode.json.`,
      )
    }
    throw new Error(`OAuth authentication failed for ${url}. Please try again.`)
  }

  // 6. Retry with credentials — RFC 6750 §2.1 (Bearer in Authorization header)
  const auth = WebFetchAuth.headers(cred)
  const retry = await fetch(url, { signal, headers: { ...base, ...auth } })

  if (retry.ok) return retry

  // Remove stale credentials on retry failure so the user isn't stuck
  // with a bad token on subsequent requests. Use the canonical resource
  // identifier (same key used by set()) — not the original request URL.
  log.error("auth retry failed, removing stale credential", { url, status: retry.status })
  await WebFetchAuth.remove(result.resource.resource).catch(() => {})
  return undefined
}

/**
 * Per-origin credential store and auth orchestration for webfetch.
 * Stores bearer tokens and basic auth credentials.
 * File: $XDG_DATA_HOME/opencode/webfetch-auth.json (mode 0o600)
 */

import path from "path"
import { Global } from "../global"
import { Filesystem } from "../util/filesystem"
import { Log } from "../util/log"
import type { ASMetadata } from "./discovery"
import { fetchASMetadata, discover } from "./discovery"
import { all as allChallenges, resourceMetadataUrl as challengeMetadataUrl } from "./www-authenticate"
import { register, authorizationCode, deviceCode } from "./flow"

const log = Log.create({ service: "webfetch.auth" })
const filepath = path.join(Global.Path.data, "webfetch-auth.json")

export type Credential = {
  resource: string
  scheme: "bearer" | "basic"
  access_token?: string
  refresh_token?: string
  expires_at?: number
  scope?: string
  username?: string
  password?: string
  oauth_client_id?: string
  oauth_client_secret?: string
  issuer?: string
}

type Store = Record<string, Credential>

async function load(): Promise<Store> {
  return Filesystem.readJson<Store>(filepath).catch(() => ({}))
}

async function save(store: Store) {
  await Filesystem.writeJson(filepath, store, 0o600)
}

export async function get(resource: string): Promise<Credential | undefined> {
  const store = await load()
  const origin = new URL(resource).origin

  // Exact match first
  if (store[resource]) return store[resource]

  // Origin match
  if (store[origin]) return store[origin]

  // Longest prefix match
  let best: Credential | undefined
  let len = 0
  for (const [key, cred] of Object.entries(store)) {
    if (resource.startsWith(key) && key.length > len) {
      best = cred
      len = key.length
    }
  }
  return best
}

export async function set(resource: string, cred: Credential) {
  const store = await load()
  store[resource] = cred
  await save(store)
  log.info("stored credential", { resource, scheme: cred.scheme })
}

export async function remove(resource: string) {
  const store = await load()
  delete store[resource]
  await save(store)
  log.info("removed credential", { resource })
}

export function expired(cred: Credential): boolean {
  if (!cred.expires_at) return false
  // Consider expired 30s before actual expiry to avoid edge cases
  return Date.now() / 1000 > cred.expires_at - 30
}

export async function refresh(cred: Credential, metadata: ASMetadata): Promise<Credential | undefined> {
  if (!cred.refresh_token || !metadata.token_endpoint) return undefined

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: cred.refresh_token,
  })
  if (cred.oauth_client_id) body.set("client_id", cred.oauth_client_id)
  if (cred.oauth_client_secret) body.set("client_secret", cred.oauth_client_secret)

  log.info("refreshing token", { resource: cred.resource, issuer: cred.issuer })

  const response = await fetch(metadata.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  })

  if (!response.ok) {
    log.error("token refresh failed", { status: response.status, resource: cred.resource })
    return undefined
  }

  const tokens = (await response.json()) as {
    access_token: string
    refresh_token?: string
    expires_in?: number
    scope?: string
  }

  const updated: Credential = {
    ...cred,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token ?? cred.refresh_token,
    expires_at: tokens.expires_in ? Date.now() / 1000 + tokens.expires_in : undefined,
    scope: tokens.scope ?? cred.scope,
  }

  await set(cred.resource, updated)
  return updated
}

export function headers(cred: Credential): Record<string, string> {
  if (cred.scheme === "bearer" && cred.access_token)
    return { Authorization: `Bearer ${cred.access_token}` }

  if (cred.scheme === "basic" && cred.username !== undefined && cred.password !== undefined) {
    const encoded = btoa(`${cred.username}:${cred.password}`)
    return { Authorization: `Basic ${encoded}` }
  }

  return {}
}

/**
 * Look up stored credentials for a URL and return auth headers.
 * Automatically refreshes expired tokens when possible.
 */
export async function resolve(url: string): Promise<Record<string, string>> {
  const cred = await get(url).catch(() => undefined)
  if (!cred) return {}

  if (expired(cred) && cred.refresh_token && cred.issuer) {
    const as = await fetchASMetadata(cred.issuer)
    if (as) {
      const refreshed = await refresh(cred, as)
      if (refreshed) return headers(refreshed)
    }
  }

  if (!expired(cred)) return headers(cred)
  return {}
}

/**
 * Handle a 401/403 response by discovering the auth server and running
 * an OAuth flow. Returns auth headers on success, undefined on failure.
 *
 * The consent callback is invoked before starting the OAuth flow so the
 * caller can prompt the user for approval.
 */
export async function negotiate(
  response: Response,
  url: string,
  consent: (info: { server: string; scopes: string }) => Promise<void>,
): Promise<Record<string, string> | undefined> {
  log.info("auth required", { url, status: response.status })

  // 1. Parse WWW-Authenticate challenges
  const challenges = allChallenges(response)
  const metaUrl = challengeMetadataUrl(challenges)

  // 2. RFC 9728 / RFC 8414 discovery
  const result = await discover(url, metaUrl ?? undefined)

  if (!result.resource || !result.servers.length) {
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

  const resource = result.resource
  const server = result.servers[0]

  // 3. Resolve client credentials
  let client: { client_id: string; client_secret?: string } | undefined

  const existing = await get(url).catch(() => undefined)
  if (existing?.oauth_client_id) {
    client = { client_id: existing.oauth_client_id, client_secret: existing.oauth_client_secret }
  }

  if (!client && server.registration_endpoint) {
    const redirectUri = `http://127.0.0.1:19877/webfetch/oauth/callback`
    client = await register(server, redirectUri) ?? undefined
  }

  if (!client) {
    const docs = server.service_documentation ?? server.issuer
    throw new Error(
      `This URL requires OAuth authentication via ${server.issuer}, ` +
        `but no client_id is configured and dynamic registration is not available. ` +
        `Register a client at ${docs} and configure it in opencode.json.`,
    )
  }

  // 4. Prompt caller for consent
  await consent({
    server: server.issuer,
    scopes: resource.scopes_supported?.join(", ") ?? "default",
  })

  // 5. Execute OAuth flow (prefer auth code + PKCE)
  const supports = server.grant_types_supported ?? ["authorization_code"]
  let cred: Credential | undefined

  if (supports.includes("authorization_code") && server.authorization_endpoint) {
    cred = await authorizationCode(
      url,
      resource,
      server,
      client,
      resource.scopes_supported,
    )
  }

  if (!cred && supports.includes("urn:ietf:params:oauth:grant-type:device_code") && server.device_authorization_endpoint) {
    const device = await deviceCode(
      url,
      resource,
      server,
      client,
      resource.scopes_supported,
    )
    if (device) {
      log.info("device code flow", {
        uri: device.info.verification_uri,
        code: device.info.user_code,
      })
      cred = await device.poll()
    }
  }

  if (!cred) {
    throw new Error(`OAuth authentication failed for ${url}. Please try again.`)
  }

  return headers(cred)
}

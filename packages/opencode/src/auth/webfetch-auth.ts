/**
 * Per-origin credential store for webfetch authentication.
 *
 * Stores bearer tokens and basic auth credentials in a JSON file
 * at $XDG_DATA_HOME/opencode/webfetch-auth.json with mode 0o600.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6750.html (Bearer tokens)
 * @see https://www.rfc-editor.org/rfc/rfc7617.html (Basic auth)
 */

import path from "path"
import { mkdir } from "fs/promises"
import { Global } from "../global"
import { Filesystem } from "../util/filesystem"
import { Log } from "../util/log"
import { requireHttps, fetchASMetadata, type ASMetadata } from "./discovery"

const log = Log.create({ service: "webfetch.auth" })
const filepath = path.join(Global.Path.data, "webfetch-auth.json")

// In-memory mutex to serialize load/modify/save operations and prevent
// TOCTOU races when concurrent token refreshes or OAuth flows run.
let lock = Promise.resolve()

function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const prev = lock
  let release!: () => void
  lock = new Promise<void>((r) => {
    release = r
  })
  return prev.then(fn).finally(release)
}

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
  // Ensure parent directory exists with 0o700 so other users cannot list
  // the directory contents, even though the file itself is 0o600.
  await mkdir(path.dirname(filepath), { recursive: true, mode: 0o700 })
  await Filesystem.writeJson(filepath, store, 0o600)
}

/**
 * Look up a stored credential for a resource URL.
 *
 * Matching priority:
 * 1. Exact URL match
 * 2. Origin match
 * 3. Longest prefix match
 *
 * @see https://www.rfc-editor.org/rfc/rfc6750.html#section-3 (scope of protection)
 */
export async function get(resource: string): Promise<Credential | undefined> {
  const store = await load()
  const origin = new URL(resource).origin

  // Exact match first
  if (store[resource]) return store[resource]

  // Origin match
  if (store[origin]) return store[origin]

  // Longest prefix match — origin-aware and path-segment-boundary-aware.
  // 1. Origins must match (prevents https://a.com matching https://a.com.evil.com)
  // 2. Key must end at a path boundary (prevents /v1 matching /v1extra)
  let best: Credential | undefined
  let len = 0
  for (const [key, cred] of Object.entries(store)) {
    if (key.length <= len || !resource.startsWith(key)) continue
    if (!URL.canParse(key) || new URL(key).origin !== origin) continue
    const next = resource[key.length]
    if (!next || next === "/" || next === "?" || next === "#") {
      best = cred
      len = key.length
    }
  }
  return best
}

/**
 * Store a credential for a resource URL.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6750.html (Bearer Token Usage)
 */
export function set(resource: string, cred: Credential) {
  return serialized(async () => {
    const store = await load()
    store[resource] = cred
    await save(store)
    log.info("stored credential", { resource, scheme: cred.scheme })
  })
}

/**
 * Remove a stored credential for a resource URL.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6750.html (Bearer Token Usage)
 */
export function remove(resource: string) {
  return serialized(async () => {
    const store = await load()
    delete store[resource]
    await save(store)
    log.info("removed credential", { resource })
  })
}

/**
 * Check if a credential's access token has expired.
 * Uses a 30-second buffer before actual expiry to avoid edge cases
 * with clock skew and in-flight requests.
 */
export function expired(cred: Credential): boolean {
  if (!cred.expires_at) return false
  return Date.now() / 1000 > cred.expires_at - 30
}

/**
 * Refresh an expired OAuth token using the refresh_token grant.
 *
 * Per RFC 6749 §6, the refresh request includes:
 * - grant_type=refresh_token
 * - refresh_token (REQUIRED)
 * - client_id (if the client is not authenticating via other means)
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749.html#section-6
 */
export async function refresh(cred: Credential, metadata: ASMetadata): Promise<Credential | undefined> {
  if (!cred.refresh_token || !metadata.token_endpoint) return undefined
  if (!requireHttps(metadata.token_endpoint)) return undefined

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
  }).catch(() => undefined)

  if (!response || !response.ok) {
    log.error("token refresh failed", { status: response?.status, resource: cred.resource })
    return undefined
  }

  const tokens = (await response.json().catch(() => undefined)) as {
    access_token: string
    refresh_token?: string
    expires_in?: number
    scope?: string
  } | undefined

  if (!tokens || !tokens.access_token) return undefined

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

/**
 * Build Authorization header value from a credential.
 *
 * RFC 6750 §2.1: Bearer token in Authorization header
 * RFC 7617 §2: Basic credentials as base64(user-id ":" password)
 *
 * Uses Buffer.from() for Basic auth to properly handle UTF-8 encoding
 * per RFC 7617 §2.1, unlike btoa() which throws on non-ASCII.
 */
export function headers(cred: Credential): Record<string, string> {
  if (cred.scheme === "bearer" && cred.access_token)
    return { Authorization: `Bearer ${cred.access_token}` }

  if (cred.scheme === "basic" && cred.username !== undefined && cred.password !== undefined) {
    // RFC 7617 §2: user-id MUST NOT contain ":" — it is used as the
    // separator and would corrupt the credential on the server side.
    if (cred.username.includes(":")) {
      log.error("basic auth username must not contain ':'", { resource: cred.resource })
      return {}
    }
    // RFC 7617 §2: credentials = user-id ":" password, encoded as base64
    // Use Buffer for proper UTF-8 support (btoa throws on non-ASCII)
    const encoded = Buffer.from(`${cred.username}:${cred.password}`, "utf-8").toString("base64")
    return { Authorization: `Basic ${encoded}` }
  }

  return {}
}

/**
 * Look up stored credentials for a URL and return auth headers.
 * Automatically refreshes expired tokens when a refresh_token is available.
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

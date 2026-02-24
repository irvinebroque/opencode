/**
 * Per-origin credential store for webfetch.
 * Stores bearer tokens and basic auth credentials.
 * File: $XDG_DATA_HOME/opencode/webfetch-auth.json (mode 0o600)
 */

import path from "path"
import { Global } from "../global"
import { Filesystem } from "../util/filesystem"
import { Log } from "../util/log"
import type { ASMetadata } from "./discovery"

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

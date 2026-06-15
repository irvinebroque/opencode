export * as WebFetchAuth from "./webfetch-auth"

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http"
import { promises as dns } from "node:dns"
import path from "node:path"
import { Effect } from "effect"
import { FSUtil } from "../fs-util"
import { Global } from "../global"

export const AUTH_TIMEOUT_SECONDS = 10 * 60

export interface Logger {
  readonly info: (message: string, fields?: Record<string, unknown>) => void
  readonly warn: (message: string, fields?: Record<string, unknown>) => void
  readonly error: (message: string, fields?: Record<string, unknown>) => void
}

export const noopLogger: Logger = {
  info: () => {},
  warn: () => {},
  error: () => {},
}

export type Challenge = {
  readonly scheme: string
  readonly params: Record<string, string>
  readonly token68?: string
}

export type ResourceMetadata = {
  resource: string
  authorization_servers?: string[]
  scopes_supported?: string[]
  bearer_methods_supported?: string[]
  resource_signing_alg_values_supported?: string[]
  resource_name?: string
  resource_documentation?: string
  resource_policy_uri?: string
  resource_tos_uri?: string
  tls_client_certificate_bound_access_tokens?: boolean
  dpop_signing_alg_values_supported?: string[]
  dpop_bound_access_tokens_required?: boolean
  jwks_uri?: string
  signed_metadata?: string
}

export type ASMetadata = {
  issuer: string
  authorization_endpoint?: string
  token_endpoint?: string
  registration_endpoint?: string
  scopes_supported?: string[]
  response_types_supported: string[]
  grant_types_supported?: string[]
  code_challenge_methods_supported?: string[]
  token_endpoint_auth_methods_supported?: string[]
  device_authorization_endpoint?: string
  service_documentation?: string
  jwks_uri?: string
  signed_metadata?: string
}

export type Credential = {
  readonly resource: string
  readonly scheme: "bearer" | "basic"
  readonly access_token?: string
  readonly refresh_token?: string
  readonly expires_at?: number
  readonly scope?: string
  readonly username?: string
  readonly password?: string
  readonly oauth_client_id?: string
  readonly oauth_client_secret?: string
  readonly issuer?: string
}

export interface CredentialStore {
  readonly get: (resource: string) => Promise<Credential | undefined>
  readonly set: (resource: string, credential: Credential) => Promise<void>
  readonly remove: (resource: string) => Promise<void>
  readonly all: () => Promise<Record<string, Credential>>
}

export interface Interaction {
  readonly askConsent: (info: {
    readonly resource: string
    readonly server: string
    readonly scopes?: string[]
  }) => Promise<void>
  readonly openUrl: (url: string) => Promise<void>
  readonly showDeviceCode: (info: DeviceInfo) => Promise<void>
}

export interface CallbackServer {
  readonly start: () => Promise<{ readonly redirectUri: string }>
  readonly waitForCode: (expectedState: string) => Promise<string>
  readonly stop: () => Promise<void>
}

export interface ClientRegistration {
  readonly name: string
  readonly uri?: string
  readonly clientId?: string
  readonly clientSecret?: string
}

export type ClientInfo = {
  readonly client_id: string
  readonly client_secret?: string
}

export type TokenResult = {
  readonly access_token: string
  readonly refresh_token?: string
  readonly expires_in?: number
  readonly scope?: string
  readonly client: ClientInfo
}

export type DeviceInfo = {
  readonly verification_uri: string
  readonly user_code: string
}

type TokenResponse = {
  readonly access_token?: string
  readonly token_type?: string
  readonly refresh_token?: string
  readonly expires_in?: number
  readonly scope?: string
  readonly error?: string
  readonly error_description?: string
  readonly error_uri?: string
}

const tokenRe = /^[!#$%&'*+\-.^_`|~A-Za-z0-9]+$/
const token68Re = /^[A-Za-z0-9\-._~+/]+=*$/
const pkceRe = /^[A-Za-z0-9\-._~]{43,128}$/
const loopback = new Set(["127.0.0.1", "[::1]", "::1"])
const maxMetadataBytes = 1_048_576
const maxAuthorizationServers = 5
const maxDeviceCodeLifetime = 600

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function skipOWS(input: string, index: number) {
  let current = index
  while (current < input.length && (input[current] === " " || input[current] === "\t")) current++
  return current
}

function parseToken(input: string, index: number) {
  let current = index
  while (current < input.length && tokenRe.test(input[current])) current++
  if (current === index) return
  return { value: input.slice(index, current), end: current }
}

function quotedPairChar(input: string) {
  const code = input.charCodeAt(0)
  return code === 0x09 || (code >= 0x20 && code !== 0x7f)
}

function parseQuotedString(input: string, index: number) {
  if (input[index] !== '"') return
  let current = index + 1
  let start = current
  const parts: string[] = []
  while (current < input.length) {
    const char = input[current]
    if (char === '"') {
      if (current > start) parts.push(input.slice(start, current))
      return { value: parts.join(""), end: current + 1 }
    }
    if (char === "\\" && current + 1 < input.length) {
      const escaped = input[current + 1]
      if (!quotedPairChar(escaped)) return
      if (current > start) parts.push(input.slice(start, current))
      parts.push(escaped)
      current += 2
      start = current
      continue
    }
    current++
  }
}

function parseTokenOrQuoted(input: string, index: number) {
  if (input[index] === '"') return parseQuotedString(input, index)
  return parseToken(input, index)
}

function parseToken68(input: string, index: number) {
  let current = index
  while (current < input.length && input[current] !== " " && input[current] !== "\t" && input[current] !== ",")
    current++
  const candidate = input.slice(index, current)
  if (!candidate || !token68Re.test(candidate)) return
  return { value: candidate, end: current }
}

function nextParam(input: string, index: number) {
  const token = parseToken(input, skipOWS(input, index))
  if (!token) return false
  const afterToken = skipOWS(input, token.end)
  if (input[afterToken] !== "=") return false
  const afterEquals = skipOWS(input, afterToken + 1)
  if (afterEquals >= input.length) return false
  if (input[afterEquals] === '"') return true
  return parseToken(input, afterEquals) !== undefined
}

export function parseWWWAuthenticate(header: string): Challenge[] {
  const challenges: Challenge[] = []
  let position = 0

  while (position < header.length) {
    position = skipOWS(header, position)
    while (position < header.length && header[position] === ",") position = skipOWS(header, position + 1)
    if (position >= header.length) break

    const scheme = parseToken(header, position)
    if (!scheme) {
      position++
      continue
    }
    position = skipOWS(header, scheme.end)

    if (position >= header.length || header[position] === ",") {
      challenges.push({ scheme: scheme.value, params: {} })
      if (position < header.length && header[position] === ",") position++
      continue
    }

    const token68 = parseToken68(header, position)
    if (token68) {
      const afterToken68 = skipOWS(header, token68.end)
      if (afterToken68 >= header.length || header[afterToken68] === ",") {
        challenges.push({ scheme: scheme.value, params: {}, token68: token68.value })
        position = afterToken68
        if (position < header.length && header[position] === ",") position++
        continue
      }
    }

    const params: Record<string, string> = {}
    let duplicate = false
    while (position < header.length) {
      position = skipOWS(header, position)
      const name = parseToken(header, position)
      if (!name) break

      position = skipOWS(header, name.end)
      if (position >= header.length || header[position] !== "=") {
        position = name.end - name.value.length
        break
      }
      position = skipOWS(header, position + 1)

      const value = parseTokenOrQuoted(header, position)
      if (!value) {
        if (position < header.length && header[position] === '"') position = header.length
        break
      }

      const key = name.value.toLowerCase()
      if (key in params) duplicate = true
      params[key] = value.value
      position = skipOWS(header, value.end)

      if (position < header.length && header[position] === ",") {
        const comma = position
        position++
        if (nextParam(header, position)) continue
        position = comma + 1
        break
      }
      break
    }

    if (!duplicate) challenges.push({ scheme: scheme.value, params })
    position = skipOWS(header, position)
    if (position < header.length && header[position] === ",") position++
  }

  return challenges
}

export function challenges(headers: Headers | Record<string, string | undefined>): Challenge[] {
  if (headers instanceof Headers)
    return [...headers.entries()].flatMap(([key, value]) =>
      key.toLowerCase() === "www-authenticate" ? parseWWWAuthenticate(value) : [],
    )
  const value = Object.entries(headers).find(([key]) => key.toLowerCase() === "www-authenticate")?.[1]
  return value ? parseWWWAuthenticate(value) : []
}

export function resourceMetadataFromChallenges(items: Challenge[]) {
  for (const item of items) {
    const value = item.params.resource_metadata
    if (!value) continue
    const url = requireHttps(value)
    if (url) return url.toString()
  }
}

export function isLoopback(hostname: string) {
  return loopback.has(hostname)
}

export function requireHttps(raw: string) {
  if (!URL.canParse(raw)) return
  const url = new URL(raw)
  if (url.protocol === "https:") return url
  if (url.protocol === "http:" && isLoopback(url.hostname)) return url
}

function parseV4(host: string) {
  const parts = host.split(".")
  if (parts.length !== 4) return
  const bytes = parts.map((part) => (/^(?:0|[1-9]\d{0,2})$/.test(part) ? Number.parseInt(part, 10) : NaN))
  if (bytes.some((byte) => Number.isNaN(byte) || byte > 255)) return
  return bytes
}

function matchCIDR(parts: number[], network: number[], bits: number, partSize: number) {
  let index = 0
  let remaining = bits
  while (remaining > 0) {
    const shift = Math.max(partSize - remaining, 0)
    if (parts[index] >> shift !== network[index] >> shift) return false
    remaining -= partSize
    index++
  }
  return true
}

const v4Private: ReadonlyArray<readonly [number[], number]> = [
  [[0, 0, 0, 0], 8],
  [[10, 0, 0, 0], 8],
  [[100, 64, 0, 0], 10],
  [[127, 0, 0, 0], 8],
  [[169, 254, 0, 0], 16],
  [[172, 16, 0, 0], 12],
  [[192, 168, 0, 0], 16],
]

function isPrivateV4(parts: number[]) {
  return v4Private.some(([network, bits]) => matchCIDR(parts, network, bits, 8))
}

function expandV6(raw: string): number[] | undefined {
  const addr = raw.includes("%") ? raw.slice(0, raw.indexOf("%")) : raw
  const last = addr.lastIndexOf(":")
  const tail = addr.slice(last + 1)
  if (tail.includes(".")) {
    const v4 = parseV4(tail)
    if (!v4) return
    return expandV6(
      `${addr.slice(0, last + 1)}${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`,
    )
  }
  const halves = addr.split("::")
  if (halves.length > 2) return
  const left = halves[0] ? halves[0].split(":").map((part) => Number.parseInt(part, 16)) : []
  const right = halves.length === 2 && halves[1] ? halves[1].split(":").map((part) => Number.parseInt(part, 16)) : []
  if (left.some(Number.isNaN) || right.some(Number.isNaN)) return
  const pad = 8 - left.length - right.length
  if (pad < 0 || (halves.length === 1 && pad !== 0)) return
  return [...left, ...new Array(pad).fill(0), ...right]
}

const v6Private: ReadonlyArray<readonly [number[], number]> = [
  [[0, 0, 0, 0, 0, 0, 0, 1], 128],
  [[0, 0, 0, 0, 0, 0, 0, 0], 128],
  [[0xfc00, 0, 0, 0, 0, 0, 0, 0], 7],
  [[0xfe80, 0, 0, 0, 0, 0, 0, 0], 10],
  [[0xfec0, 0, 0, 0, 0, 0, 0, 0], 10],
  [[0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32],
]

function v4From(hi: number, lo: number) {
  return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff]
}

function embeddedV4(groups: number[]) {
  if (matchCIDR(groups, [0, 0, 0, 0, 0, 0xffff, 0, 0], 96, 16)) return v4From(groups[6], groups[7])
  if (matchCIDR(groups, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16, 16)) return v4From(groups[1], groups[2])
  if (matchCIDR(groups, [0x2001, 0, 0, 0, 0, 0, 0, 0], 32, 16)) return v4From(groups[6] ^ 0xffff, groups[7] ^ 0xffff)
  if (matchCIDR(groups, [0x0064, 0xff9b, 0, 0, 0, 0, 0, 0], 96, 16)) return v4From(groups[6], groups[7])
}

function isPrivateIP(hostname: string) {
  const host = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname
  const v4 = parseV4(host)
  if (v4) return isPrivateV4(v4)
  const groups = expandV6(host.toLowerCase())
  if (!groups || groups.length !== 8) return false
  if (v6Private.some(([network, bits]) => matchCIDR(groups, network, bits, 16))) return true
  const embedded = embeddedV4(groups)
  return embedded ? isPrivateV4(embedded) : false
}

export async function isPrivateNetwork(hostname: string) {
  if (isPrivateIP(hostname)) return true
  const lower = hostname.toLowerCase()
  if (lower === "localhost" || lower.endsWith(".localhost")) return true
  if (lower.endsWith(".local") || lower.endsWith(".internal")) return true
  const v4 = await dns.resolve4(hostname).catch(() => [])
  if (v4.some(isPrivateIP)) return true
  const v6 = await dns.resolve6(hostname).catch(() => [])
  return v6.some(isPrivateIP)
}

function validResource(resource: string) {
  const url = requireHttps(resource)
  return !!url && !url.hash
}

function validIssuer(issuer: string) {
  const url = requireHttps(issuer)
  return !!url && !url.search && !url.hash
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string" && item.length > 0)
}

function validateResourceFields(input: Record<string, unknown>) {
  for (const field of [
    "resource",
    "jwks_uri",
    "resource_name",
    "resource_documentation",
    "resource_policy_uri",
    "resource_tos_uri",
    "signed_metadata",
  ] as const) {
    if (input[field] !== undefined && typeof input[field] !== "string") return false
  }
  for (const field of [
    "authorization_servers",
    "scopes_supported",
    "bearer_methods_supported",
    "resource_signing_alg_values_supported",
    "dpop_signing_alg_values_supported",
    "authorization_details_types_supported",
  ] as const) {
    if (input[field] !== undefined && !stringArray(input[field])) return false
  }
  for (const field of ["tls_client_certificate_bound_access_tokens", "dpop_bound_access_tokens_required"] as const) {
    if (input[field] !== undefined && typeof input[field] !== "boolean") return false
  }
  return true
}

function validateASFields(input: Record<string, unknown>) {
  for (const field of [
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "service_documentation",
    "device_authorization_endpoint",
    "signed_metadata",
  ] as const) {
    if (input[field] !== undefined && typeof input[field] !== "string") return false
  }
  for (const field of [
    "scopes_supported",
    "response_types_supported",
    "grant_types_supported",
    "code_challenge_methods_supported",
    "token_endpoint_auth_methods_supported",
    "response_modes_supported",
  ] as const) {
    if (input[field] !== undefined && !stringArray(input[field])) return false
  }
  return true
}

export function resourceMetadataUrl(resource: string) {
  const url = new URL(resource)
  const suffix = url.pathname === "/" ? "" : url.pathname
  return `${url.origin}/.well-known/oauth-protected-resource${suffix}${url.search}`
}

export function asMetadataUrl(issuer: string) {
  const url = new URL(issuer)
  const suffix = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "")
  return `${url.origin}/.well-known/oauth-authorization-server${suffix}`
}

function oidcMetadataUrl(issuer: string) {
  const url = new URL(issuer)
  const base = url.pathname.replace(/\/$/, "")
  return `${url.origin}${base}/.well-known/openid-configuration`
}

async function readJsonLimited(response: Response, limit: number) {
  const contentLength = response.headers.get("content-length")
  if (contentLength && Number.parseInt(contentLength, 10) > limit) return
  const reader = response.body?.getReader()
  if (!reader) return
  const chunks: Uint8Array[] = []
  let total = 0
  while (true) {
    const next = await reader.read()
    if (next.done) break
    total += next.value.byteLength
    if (total > limit) {
      await reader.cancel()
      return
    }
    chunks.push(next.value)
  }
  return JSON.parse(new TextDecoder().decode(Buffer.concat(chunks, total))) as unknown
}

function applicationJson(response: Response) {
  return response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() === "application/json"
}

export async function fetchResourceMetadata(
  url: string,
  resource: string,
  signal?: AbortSignal,
  options?: { readonly allowPrivate?: boolean; readonly logger?: Logger },
) {
  const logger = options?.logger ?? noopLogger
  if (!requireHttps(url)) {
    logger.error("resource metadata URL must be HTTPS", { url })
    return
  }
  const host = new URL(url).hostname
  if (!options?.allowPrivate && !isLoopback(host) && (await isPrivateNetwork(host))) {
    logger.error("resource metadata URL must not target private network", { url })
    return
  }
  const response = await fetch(url, { headers: { Accept: "application/json" }, redirect: "error", signal }).catch(
    () => undefined,
  )
  if (!response?.ok || !applicationJson(response)) return
  const body = await readJsonLimited(response, maxMetadataBytes).catch(() => undefined)
  if (!isRecord(body) || !validateResourceFields(body) || typeof body.resource !== "string") return
  const metadata = body as ResourceMetadata
  if (!validResource(metadata.resource)) return
  if (metadata.resource_signing_alg_values_supported?.includes("none")) return
  if (metadata.jwks_uri && !requireHttps(metadata.jwks_uri)) return
  if (metadata.authorization_servers?.some((issuer) => !validIssuer(issuer))) return
  if (metadata.resource !== resource) {
    logger.error("resource metadata mismatch", { expected: resource, got: metadata.resource })
    return
  }
  return metadata
}

export async function fetchASMetadata(
  issuer: string,
  signal?: AbortSignal,
  options?: { readonly allowPrivate?: boolean; readonly logger?: Logger },
) {
  const logger = options?.logger ?? noopLogger
  if (!validIssuer(issuer)) return
  const issuerHost = new URL(issuer).hostname
  if (!options?.allowPrivate && !isLoopback(issuerHost) && (await isPrivateNetwork(issuerHost))) return
  const request = { headers: { Accept: "application/json" }, redirect: "error" as const, signal }
  const discovered = await fetch(asMetadataUrl(issuer), request).catch(() => undefined)
  const response = discovered?.ok ? discovered : await fetch(oidcMetadataUrl(issuer), request).catch(() => undefined)
  if (!response?.ok || !applicationJson(response)) return
  const body = await readJsonLimited(response, maxMetadataBytes).catch(() => undefined)
  if (!isRecord(body) || !validateASFields(body) || typeof body.issuer !== "string") return
  const metadata = body as ASMetadata
  if (metadata.issuer !== issuer) return
  if (!metadata.response_types_supported.length) return
  if (metadata.jwks_uri && !requireHttps(metadata.jwks_uri)) return
  const signingAlgorithms = body.token_endpoint_auth_signing_alg_values_supported
  if (Array.isArray(signingAlgorithms) && signingAlgorithms.includes("none")) return
  for (const field of [
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "device_authorization_endpoint",
  ] as const) {
    const value = metadata[field]
    if (!value) continue
    if (!requireHttps(value)) return
    const host = new URL(value).hostname
    if (!options?.allowPrivate && !isLoopback(host) && (await isPrivateNetwork(host))) return
  }
  metadata.grant_types_supported ??= ["authorization_code", "implicit"]
  const metadataRecord = metadata as Record<string, unknown>
  metadataRecord.response_modes_supported ??= ["query", "fragment"]
  metadataRecord.token_endpoint_auth_methods_supported ??= ["client_secret_basic"]
  const grants = new Set(metadata.grant_types_supported)
  if ((grants.has("authorization_code") || grants.has("implicit")) && !metadata.authorization_endpoint) return
  if (!(grants.size === 1 && grants.has("implicit")) && !metadata.token_endpoint) return
  logger.info("AS metadata fetched", { issuer })
  return metadata
}

export async function discover(resource: string, metadataUrl?: string, signal?: AbortSignal, logger = noopLogger) {
  const resourceHost = new URL(resource).hostname
  const local = await isPrivateNetwork(resourceHost)
  if (metadataUrl) {
    const host = new URL(metadataUrl).hostname
    if ((await isPrivateNetwork(host)) && !local) return { servers: [] as ASMetadata[] }
  }
  const metadata = await fetchResourceMetadata(metadataUrl ?? resourceMetadataUrl(resource), resource, signal, {
    allowPrivate: local,
    logger,
  })
  if (!metadata?.authorization_servers?.length) return { resource: metadata, servers: [] as ASMetadata[] }
  const servers = (
    await Promise.all(
      metadata.authorization_servers.slice(0, maxAuthorizationServers).map(async (issuer) => {
        const host = new URL(issuer).hostname
        if ((await isPrivateNetwork(host)) && !local) return
        return fetchASMetadata(issuer, signal, { allowPrivate: local, logger })
      }),
    )
  ).filter((server): server is ASMetadata => !!server)
  return { resource: metadata, servers }
}

function base64url(buffer: ArrayBuffer) {
  return Buffer.from(buffer).toString("base64url")
}

export async function pkce() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)).buffer)
  if (!pkceRe.test(verifier)) throw new Error("PKCE verifier generation produced invalid value")
  return { verifier, challenge: base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))) }
}

export function state() {
  return base64url(crypto.getRandomValues(new Uint8Array(32)).buffer)
}

function sleep(ms: number, signal?: AbortSignal) {
  if (!signal) return new Promise<void>((resolve) => setTimeout(resolve, ms))
  if (signal.aborted) return Promise.reject(signal.reason)
  return new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal.removeEventListener("abort", abort)
      resolve()
    }, ms)
    const abort = () => {
      clearTimeout(timeout)
      signal.removeEventListener("abort", abort)
      reject(signal.reason)
    }
    signal.addEventListener("abort", abort, { once: true })
  })
}

function escapeHtml(input: string) {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

const successHtml = `<!DOCTYPE html><html><head><title>OpenCode - Authorization Successful</title></head><body><h1>Authorization Successful</h1><p>You can close this window and return to OpenCode.</p><script>setTimeout(() => window.close(), 2000);</script></body></html>`

function errorHtml(message: string) {
  return `<!DOCTYPE html><html><head><title>OpenCode - Authorization Failed</title></head><body><h1>Authorization Failed</h1><p>${escapeHtml(message)}</p></body></html>`
}

export class LocalCallbackServer implements CallbackServer {
  private server?: Server
  private port: number
  constructor(
    private readonly options: {
      readonly port?: number
      readonly hostname?: string
      readonly path?: string
      readonly timeout?: number
      readonly portRetries?: number
    } = {},
  ) {
    this.port = options.port ?? 19877
  }

  async start() {
    const hostname = this.options.hostname ?? "127.0.0.1"
    for (const offset of Array.from({ length: this.options.portRetries ?? 10 }, (_, index) => index)) {
      const port = this.port + offset
      const ok = await new Promise<boolean>((resolve) => {
        const server = createServer()
        server.once("error", () => resolve(false))
        server.listen(port, hostname, () => {
          this.server = server
          this.port = port
          resolve(true)
        })
      })
      if (ok) return { redirectUri: `http://${hostname}:${port}${this.options.path ?? "/oauth/callback"}` }
    }
    throw new Error("could not find open port for callback server")
  }

  waitForCode(expectedState: string) {
    return new Promise<string>((resolve, reject) => {
      const server = this.server
      if (!server) {
        reject(new Error("callback server is not running"))
        return
      }
      let done = false
      const finish = (run: () => void, close: boolean) => {
        if (done) return
        done = true
        clearTimeout(timer)
        server.off("request", request)
        if (close) setTimeout(() => void this.stop(), 500)
        run()
      }
      const timer = setTimeout(
        () => finish(() => reject(new Error("authorization callback timed out")), true),
        this.options.timeout ?? 300_000,
      )
      const request = (req: IncomingMessage, res: ServerResponse) => {
        const url = new URL(req.url ?? "/", `http://${this.options.hostname ?? "127.0.0.1"}:${this.port}`)
        if (url.pathname !== (this.options.path ?? "/oauth/callback")) {
          res.writeHead(404)
          res.end("Not found")
          return
        }
        const callbackState = url.searchParams.get("state")
        if (!callbackState || callbackState !== expectedState) {
          res.writeHead(400, { "Content-Type": "text/html" })
          res.end(errorHtml("Invalid state parameter"))
          return
        }
        const error = url.searchParams.get("error")
        if (error) {
          const description = url.searchParams.get("error_description") ?? error
          res.writeHead(200, { "Content-Type": "text/html" })
          res.end(errorHtml(description))
          finish(() => reject(new Error(`Authorization error: ${description}`)), true)
          return
        }
        const code = url.searchParams.get("code")
        if (!code) {
          res.writeHead(400, { "Content-Type": "text/html" })
          res.end(errorHtml("No authorization code"))
          finish(() => reject(new Error("No authorization code in callback")), true)
          return
        }
        res.writeHead(200, { "Content-Type": "text/html" })
        res.end(successHtml)
        finish(() => resolve(code), true)
      }
      server.on("request", request)
    })
  }

  async stop() {
    if (!this.server) return
    const server = this.server
    this.server = undefined
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
}

export function tokenEndpointHeaders(
  metadata: Pick<ASMetadata, "token_endpoint_auth_methods_supported">,
  client: ClientInfo,
  body: URLSearchParams,
  logger: Logger = noopLogger,
) {
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" }
  if (!client.client_secret) {
    body.set("client_id", client.client_id)
    return headers
  }
  const methods = metadata.token_endpoint_auth_methods_supported ?? ["client_secret_basic"]
  if (methods.includes("client_secret_basic")) {
    headers.Authorization = `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`, "utf-8").toString("base64")}`
    return headers
  }
  if (methods.includes("client_secret_post")) {
    body.set("client_id", client.client_id)
    body.set("client_secret", client.client_secret)
    return headers
  }
  logger.error("token endpoint auth method unsupported", { methods })
}

export async function register(
  metadata: ASMetadata,
  redirectUri: string,
  registration: ClientRegistration,
  logger: Logger = noopLogger,
  signal?: AbortSignal,
) {
  if (!metadata.registration_endpoint || !requireHttps(metadata.registration_endpoint)) return
  const grants = new Set(metadata.grant_types_supported ?? ["authorization_code", "implicit"])
  const supportsAuthorizationCode = grants.has("authorization_code")
  const supportsDevice = grants.has("urn:ietf:params:oauth:grant-type:device_code")
  const grantTypes = [
    ...(supportsAuthorizationCode ? ["authorization_code", "refresh_token"] : []),
    ...(supportsDevice ? ["urn:ietf:params:oauth:grant-type:device_code"] : []),
  ]
  const response = await fetch(metadata.registration_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    redirect: "error",
    signal,
    body: JSON.stringify({
      redirect_uris: [redirectUri],
      client_name: registration.name,
      ...(registration.uri ? { client_uri: registration.uri } : {}),
      grant_types: grantTypes,
      ...(supportsAuthorizationCode ? { response_types: ["code"] } : {}),
      token_endpoint_auth_method: "none",
    }),
  }).catch(() => undefined)
  if (!response?.ok) return
  const body = await response.json().catch(() => undefined)
  if (!isRecord(body) || typeof body.client_id !== "string") return
  if (typeof body.client_secret_expires_at === "number" && body.client_secret_expires_at > 0) return
  return {
    client_id: body.client_id,
    client_secret: typeof body.client_secret === "string" ? body.client_secret : undefined,
  }
}

export async function authorizationCode(
  resource: string,
  resourceMeta: ResourceMetadata,
  asMeta: ASMetadata,
  client: ClientInfo | undefined,
  scopes: string[] | undefined,
  options: {
    readonly server: CallbackServer
    readonly interaction: Interaction
    readonly registration: ClientRegistration
    readonly logger?: Logger
    readonly signal?: AbortSignal
  },
) {
  const logger = options.logger ?? noopLogger
  if (!asMeta.authorization_endpoint || !asMeta.token_endpoint) return
  if (!requireHttps(asMeta.authorization_endpoint) || !requireHttps(asMeta.token_endpoint)) return
  if (asMeta.code_challenge_methods_supported && !asMeta.code_challenge_methods_supported.includes("S256")) return
  const codes = await pkce()
  const oauthState = state()
  const scope = scopes?.join(" ") ?? resourceMeta.scopes_supported?.join(" ") ?? ""
  const started = await options.server.start().catch(() => undefined)
  if (!started) return
  const resolved =
    client ??
    (asMeta.registration_endpoint
      ? await register(asMeta, started.redirectUri, options.registration, logger, options.signal)
      : undefined)
  if (!resolved) {
    await options.server.stop()
    return
  }
  const params = new URLSearchParams({
    response_type: "code",
    client_id: resolved.client_id,
    redirect_uri: started.redirectUri,
    state: oauthState,
    code_challenge: codes.challenge,
    code_challenge_method: "S256",
    resource: resourceMeta.resource,
  })
  if (scope) params.set("scope", scope)
  const url = `${asMeta.authorization_endpoint}?${params.toString()}`
  const authorizationUrl = requireHttps(url)
  if (!authorizationUrl) {
    await options.server.stop()
    return
  }
  await options.interaction.openUrl(authorizationUrl.toString()).catch(async (error) => {
    await options.server.stop()
    throw error
  })
  const code = await options.server.waitForCode(oauthState).catch(() => undefined)
  if (!code) return
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: started.redirectUri,
    code_verifier: codes.verifier,
    resource: resourceMeta.resource,
  })
  const headers = tokenEndpointHeaders(asMeta, resolved, body, logger)
  if (!headers) return
  const response = await fetch(asMeta.token_endpoint, {
    method: "POST",
    headers,
    redirect: "error",
    signal: options.signal,
    body: body.toString(),
  }).catch(() => undefined)
  const tokens = (await response?.json().catch(() => undefined)) as TokenResponse | undefined
  if (!response?.ok || !tokens?.access_token || tokens.token_type?.toLowerCase() !== "bearer") return
  return {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_in: tokens.expires_in,
    scope: tokens.scope ?? scope,
    client: resolved,
  } satisfies TokenResult
}

export async function deviceCode(
  resource: string,
  resourceMeta: ResourceMetadata,
  asMeta: ASMetadata,
  client: ClientInfo,
  scopes?: string[],
  logger: Logger = noopLogger,
  signal?: AbortSignal,
) {
  if (!asMeta.device_authorization_endpoint || !asMeta.token_endpoint) return
  if (!requireHttps(asMeta.device_authorization_endpoint) || !requireHttps(asMeta.token_endpoint)) return
  const scope = scopes?.join(" ") ?? resourceMeta.scopes_supported?.join(" ") ?? ""
  const startBody = new URLSearchParams({ client_id: client.client_id, resource: resourceMeta.resource })
  if (scope) startBody.set("scope", scope)
  const response = await fetch(asMeta.device_authorization_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    redirect: "error",
    signal,
    body: startBody.toString(),
  }).catch(() => undefined)
  if (!response?.ok) return
  const data = await response.json().catch(() => undefined)
  if (
    !isRecord(data) ||
    typeof data.device_code !== "string" ||
    typeof data.user_code !== "string" ||
    typeof data.verification_uri !== "string" ||
    typeof data.expires_in !== "number"
  )
    return
  const deviceCodeValue = data.device_code
  const userCode = data.user_code
  const verificationUri = data.verification_uri
  let interval = Math.max(typeof data.interval === "number" ? data.interval : 5, 1) * 1000
  const lifetime = Math.min(Math.max(data.expires_in, 0), maxDeviceCodeLifetime)
  const deadline = Date.now() + lifetime * 1000
  const verification =
    typeof data.verification_uri_complete === "string" &&
    requireHttps(data.verification_uri_complete)?.origin === requireHttps(verificationUri)?.origin
      ? data.verification_uri_complete
      : verificationUri
  const info = { verification_uri: verification, user_code: userCode }

  return {
    info,
    poll: async () => {
      while (Date.now() < deadline) {
        await sleep(interval, signal).catch(() => undefined)
        if (signal?.aborted) return
        const body = new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: deviceCodeValue,
        })
        const headers = tokenEndpointHeaders(asMeta, client, body, logger)
        if (!headers) return
        const response = await fetch(asMeta.token_endpoint!, {
          method: "POST",
          headers,
          redirect: "error",
          signal,
          body: body.toString(),
        }).catch(() => undefined)
        if (!response) {
          interval = Math.min(interval * 2, 60_000)
          continue
        }
        const json = (await response.json().catch(() => ({}))) as TokenResponse
        if (response.ok && json.access_token) {
          if (json.token_type?.toLowerCase() !== "bearer") return
          return {
            access_token: json.access_token,
            refresh_token: json.refresh_token,
            expires_in: json.expires_in,
            scope: json.scope ?? scope,
            client,
          } satisfies TokenResult
        }
        if (json.error === "slow_down") {
          interval += 5000
          continue
        }
        if (json.error === "authorization_pending") continue
        return
      }
    },
  }
}

export function expired(credential: Credential) {
  if (!credential.expires_at) return false
  return Date.now() / 1000 > credential.expires_at - 30
}

export function authHeaders(credential: Credential, logger: Logger = noopLogger): Record<string, string> {
  if (credential.scheme === "bearer" && credential.access_token) {
    if (/[\r\n]/.test(credential.access_token)) return {}
    return { Authorization: `Bearer ${credential.access_token}` }
  }
  if (credential.scheme === "basic" && credential.username !== undefined && credential.password !== undefined) {
    if (credential.username.includes(":")) {
      logger.error("basic auth username must not contain ':'", { resource: credential.resource })
      return {}
    }
    return {
      Authorization: `Basic ${Buffer.from(`${credential.username}:${credential.password}`, "utf-8").toString("base64")}`,
    }
  }
  return {}
}

export async function lookup(resource: string, store: CredentialStore) {
  const all = await store.all()
  const origin = new URL(resource).origin
  if (all[resource]) return all[resource]
  const match = Object.entries(all)
    .filter(([key]) => {
      if (!URL.canParse(key) || new URL(key).origin !== origin || !resource.startsWith(key)) return false
      const next = resource[key.length]
      return !next || next === "/" || next === "?" || next === "#"
    })
    .toSorted((a, b) => b[0].length - a[0].length)[0]
  return match?.[1] ?? all[origin]
}

export async function refresh(
  credential: Credential,
  metadata: ASMetadata,
  store: CredentialStore,
  logger: Logger = noopLogger,
  signal?: AbortSignal,
) {
  if (!credential.refresh_token || !metadata.token_endpoint || !requireHttps(metadata.token_endpoint)) return
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: credential.refresh_token,
    resource: credential.resource,
  })
  const headers = credential.oauth_client_id
    ? tokenEndpointHeaders(
        metadata,
        { client_id: credential.oauth_client_id, client_secret: credential.oauth_client_secret },
        body,
        logger,
      )
    : { "Content-Type": "application/x-www-form-urlencoded" }
  if (!headers) return
  const response = await fetch(metadata.token_endpoint, {
    method: "POST",
    headers,
    redirect: "error",
    signal,
    body: body.toString(),
  }).catch(() => undefined)
  if (!response?.ok) return
  const tokens = (await response.json().catch(() => undefined)) as TokenResponse | undefined
  if (!tokens?.access_token || tokens.token_type?.toLowerCase() !== "bearer") return
  const updated = {
    ...credential,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token ?? credential.refresh_token,
    expires_at: tokens.expires_in ? Date.now() / 1000 + tokens.expires_in : undefined,
    scope: tokens.scope ?? credential.scope,
  }
  await store.set(credential.resource, updated)
  return updated
}

export async function resolveCredentials(
  url: string,
  store: CredentialStore,
  logger: Logger = noopLogger,
  signal?: AbortSignal,
) {
  const credential = await lookup(url, store).catch(() => undefined)
  if (!credential) return {}
  if (expired(credential) && credential.refresh_token && credential.issuer) {
    const issuer = requireHttps(credential.issuer)
    if (!issuer) return {}
    if (!isLoopback(issuer.hostname) && (await isPrivateNetwork(issuer.hostname))) return {}
    const metadata = await fetchASMetadata(credential.issuer, signal, { logger })
    const refreshed = metadata ? await refresh(credential, metadata, store, logger, signal) : undefined
    if (refreshed) return authHeaders(refreshed, logger)
  }
  return expired(credential) ? {} : authHeaders(credential, logger)
}

export function fileStore(fs: FSUtil.Interface, global: Global.Interface): CredentialStore {
  const filepath = path.join(global.data, "webfetch-auth.json")
  const load = async () => {
    const data = await Effect.runPromise(fs.readJson(filepath).pipe(Effect.catch(() => Effect.succeed({}))))
    if (!isRecord(data)) return {}
    return Object.fromEntries(
      Object.entries(data).filter(
        (entry): entry is [string, Credential] =>
          isRecord(entry[1]) &&
          typeof entry[1].resource === "string" &&
          (entry[1].scheme === "bearer" || entry[1].scheme === "basic"),
      ),
    )
  }
  return {
    async get(resource) {
      return (await load())[resource]
    },
    async set(resource, credential) {
      await Effect.runPromise(
        fs
          .ensureDir(global.data)
          .pipe(Effect.andThen(fs.writeJson(filepath, { ...(await load()), [resource]: credential }, 0o600))),
      )
    },
    async remove(resource) {
      const data = await load()
      delete data[resource]
      await Effect.runPromise(fs.ensureDir(global.data).pipe(Effect.andThen(fs.writeJson(filepath, data, 0o600))))
    },
    all: load,
  }
}

function credential(resource: string, tokens: TokenResult, issuer: string): Credential {
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

export async function handleAuthChallenge(options: {
  readonly headers: Headers | Record<string, string | undefined>
  readonly url: string
  readonly baseHeaders: Record<string, string>
  readonly signal?: AbortSignal
  readonly store: CredentialStore
  readonly interaction: Interaction
  readonly callbackServer?: CallbackServer
  readonly client?: ClientRegistration
  readonly logger?: Logger
  readonly preferDevice?: boolean
}) {
  const logger = options.logger ?? noopLogger
  const parsed = challenges(options.headers)
  const metadataUrl = resourceMetadataFromChallenges(parsed)
  const result = await discover(new URL(options.url).toString(), metadataUrl, options.signal, logger)
  if (!result.resource || !result.servers.length) {
    const basic = parsed.find((challenge) => challenge.scheme.toLowerCase() === "basic")
    if (basic)
      throw new Error(
        `This URL requires Basic authentication (realm: ${basic.params.realm ?? "unknown"}). Configure credentials for this origin in the credential store.`,
      )
    return
  }
  const registration = options.client ?? { name: "OpenCode", uri: "https://opencode.ai" }
  let last: Error | undefined

  for (const server of result.servers) {
    const existing = await lookup(options.url, options.store).catch(() => undefined)
    const resolved = options.client?.clientId
      ? { client_id: options.client.clientId, client_secret: options.client.clientSecret }
      : existing?.oauth_client_id && (!existing.issuer || existing.issuer === server.issuer)
        ? { client_id: existing.oauth_client_id, client_secret: existing.oauth_client_secret }
        : undefined
    await options.interaction.askConsent({
      resource: options.url,
      server: server.issuer,
      scopes: result.resource.scopes_supported,
    })

    const grants = server.grant_types_supported ?? ["authorization_code", "implicit"]
    const supportsDevice =
      grants.includes("urn:ietf:params:oauth:grant-type:device_code") && !!server.device_authorization_endpoint
    let stored: Credential | undefined
    let authError: Error | undefined

    if (options.preferDevice && !supportsDevice) {
      last = new Error(
        `This URL requires browser-based OAuth via ${server.issuer}, but this environment only supports device authorization.`,
      )
      continue
    }

    if (
      !options.preferDevice &&
      grants.includes("authorization_code") &&
      server.authorization_endpoint &&
      options.callbackServer
    ) {
      const tokens = await authorizationCode(
        options.url,
        result.resource,
        server,
        resolved,
        result.resource.scopes_supported,
        {
          server: options.callbackServer,
          interaction: options.interaction,
          registration,
          logger,
          signal: options.signal,
        },
      ).catch((error) => {
        authError = error instanceof Error ? error : new Error(String(error))
        return undefined
      })
      if (tokens) {
        stored = credential(result.resource.resource, tokens, server.issuer)
        await options.store.set(result.resource.resource, stored)
      }
    }

    if (!stored && supportsDevice) {
      const client =
        resolved ??
        (server.registration_endpoint && options.callbackServer
          ? await register(
              server,
              (await options.callbackServer.start().catch(() => undefined))?.redirectUri ??
                "http://127.0.0.1:19877/oauth/callback",
              registration,
              logger,
              options.signal,
            )
          : undefined)
      await options.callbackServer?.stop().catch(() => {})
      const device = client
        ? await deviceCode(
            options.url,
            result.resource,
            server,
            client,
            result.resource.scopes_supported,
            logger,
            options.signal,
          )
        : undefined
      if (device) {
        await options.interaction.showDeviceCode(device.info)
        const tokens = await device.poll()
        if (tokens) {
          stored = credential(result.resource.resource, tokens, server.issuer)
          await options.store.set(result.resource.resource, stored)
        }
      }
    }

    if (!stored) {
      if (authError) {
        last = authError
        continue
      }
      if (!resolved && !server.registration_endpoint) {
        last = new Error(
          `This URL requires OAuth authentication via ${server.issuer}, but no client_id is configured and dynamic registration is not available.`,
        )
        continue
      }
      last = new Error(`OAuth authentication failed for ${options.url} via ${server.issuer}.`)
      continue
    }

    const response = await fetch(options.url, {
      headers: { ...options.baseHeaders, ...authHeaders(stored, logger) },
      redirect: "error",
      signal: options.signal,
    }).catch(() => undefined)
    if (response?.ok) return response
    await options.store.remove(result.resource.resource).catch(() => {})
    last = new Error(`OAuth authentication succeeded but retry failed for ${options.url} via ${server.issuer}.`)
  }

  if (last) throw last
}

export async function openAuthorizationUrl(url: string) {
  const command =
    process.platform === "darwin"
      ? ["open", url]
      : process.platform === "win32"
        ? ["cmd", "/c", "start", "", url]
        : ["xdg-open", url]
  const proc = Bun.spawn(command, { stdout: "ignore", stderr: "ignore" })
  const code = await proc.exited
  if (code !== 0) throw new Error("Could not open browser")
}

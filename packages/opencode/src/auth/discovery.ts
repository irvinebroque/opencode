/**
 * RFC 9728 (Protected Resource Metadata) and RFC 8414 (AS Metadata) discovery.
 *
 * Key RFC compliance points:
 * - RFC 9728 §2: resource identifier MUST be HTTPS, absolute URI, no fragment
 * - RFC 9728 §3.1: well-known URL insertion algorithm
 * - RFC 9728 §3.2: metadata response MUST be application/json
 * - RFC 9728 §3.3: resource value MUST exactly match the resource identifier
 * - RFC 8414 §2: issuer MUST be HTTPS, no query/fragment
 * - RFC 8414 §2: response_types_supported is REQUIRED
 * - RFC 8414 §2: default grant_types_supported is ["authorization_code", "implicit"]
 * - RFC 8414 §3.1: well-known URL insertion algorithm (trailing slash normalization)
 * - RFC 8414 §3.3: issuer value MUST exactly match
 *
 * @see https://www.rfc-editor.org/rfc/rfc9728.html
 * @see https://www.rfc-editor.org/rfc/rfc8414.html
 */

import { Log } from "../util/log"

const log = Log.create({ service: "webfetch.discovery" })

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
  device_authorization_endpoint?: string
  service_documentation?: string
  jwks_uri?: string
  signed_metadata?: string
}

// ---------------------------------------------------------------------------
// URL validation helpers
// ---------------------------------------------------------------------------

/**
 * Validate that a URL uses HTTPS and is an absolute URI.
 * Returns the parsed URL or undefined if invalid.
 *
 * HTTP is permitted for loopback addresses (127.0.0.1 / [::1] / localhost)
 * per RFC 8252 §7.3 which allows HTTP for the loopback interface redirect.
 * This also enables testing with local mock servers.
 */
export function requireHttps(raw: string): URL | undefined {
  if (!URL.canParse(raw)) return undefined
  const url = new URL(raw)
  if (url.protocol === "https:") return url
  if (url.protocol === "http:" && isLoopback(url.hostname)) return url
  return undefined
}

// Only IP literals — "localhost" is excluded because it is DNS-resolvable
// and could map to a non-loopback address via /etc/hosts or DNS poisoning.
const LOOPBACK = new Set(["127.0.0.1", "[::1]", "::1"])

export function isLoopback(hostname: string): boolean {
  return LOOPBACK.has(hostname)
}

// ---------------------------------------------------------------------------
// Private network detection — SSRF protection
// ---------------------------------------------------------------------------

/** Parse an IPv4 address string into 4 octets, or undefined if invalid. */
function parseV4(host: string): number[] | undefined {
  const parts = host.split(".")
  if (parts.length !== 4) return undefined
  const bytes = parts.map(Number)
  if (bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) return undefined
  return bytes
}

/** Check if IPv4 octets belong to a private, loopback, or link-local range. */
function privateV4(o: number[]): boolean {
  if (o[0] === 0) return true                                   // 0.0.0.0/8
  if (o[0] === 10) return true                                  // 10.0.0.0/8
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true   // 100.64.0.0/10 (RFC 6598)
  if (o[0] === 127) return true                                 // 127.0.0.0/8
  if (o[0] === 169 && o[1] === 254) return true                 // 169.254.0.0/16 (link-local / cloud metadata)
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true    // 172.16.0.0/12
  if (o[0] === 192 && o[1] === 168) return true                 // 192.168.0.0/16
  return false
}

/** Expand an IPv6 address string to 8 groups of 16-bit values. */
function expandV6(raw: string): number[] | undefined {
  // Strip zone ID (e.g. %eth0 or %25eth0)
  const addr = raw.includes("%") ? raw.slice(0, raw.indexOf("%")) : raw

  // Handle IPv4-mapped suffix (::ffff:1.2.3.4)
  const last = addr.lastIndexOf(":")
  const tail = addr.slice(last + 1)
  if (tail.includes(".")) {
    const v4 = parseV4(tail)
    if (!v4) return undefined
    const hex =
      ((v4[0] << 8) | v4[1]).toString(16) +
      ":" +
      ((v4[2] << 8) | v4[3]).toString(16)
    return expandV6(addr.slice(0, last + 1) + hex)
  }

  const halves = addr.split("::")
  if (halves.length > 2) return undefined

  const parse = (s: string) =>
    s === "" ? [] : s.split(":").map((g) => parseInt(g, 16))
  const left = parse(halves[0])
  const right = halves.length === 2 ? parse(halves[1]) : []
  if (left.some(isNaN) || right.some(isNaN)) return undefined

  const pad = 8 - left.length - right.length
  if (pad < 0 || (halves.length === 1 && pad !== 0)) return undefined

  return [...left, ...new Array(pad).fill(0), ...right]
}

/**
 * Check whether an IP literal is a private, loopback, or link-local address.
 *
 * This is the synchronous core that only inspects IP address literals.
 * Callers that need hostname-safe SSRF checks should use {@link isPrivateNetwork}
 * which also resolves DNS names and checks well-known private hostnames.
 */
function isPrivateIP(hostname: string): boolean {
  const host = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname

  // IPv4
  const v4 = parseV4(host)
  if (v4) return privateV4(v4)

  // IPv6
  const groups = expandV6(host.toLowerCase())
  if (!groups || groups.length !== 8) return false

  // ::1 loopback
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0 &&
    groups[6] === 0 &&
    groups[7] === 1
  )
    return true

  // :: unspecified
  if (groups.every((g) => g === 0)) return true

  // fc00::/7 unique local
  if ((groups[0] & 0xfe00) === 0xfc00) return true

  // fe80::/10 link-local
  if ((groups[0] & 0xffc0) === 0xfe80) return true

  // ::ffff:0:0/96 IPv4-mapped — check the embedded IPv4
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    return privateV4([
      (groups[6] >> 8) & 0xff,
      groups[6] & 0xff,
      (groups[7] >> 8) & 0xff,
      groups[7] & 0xff,
    ])
  }

  return false
}

/**
 * Check whether a hostname refers to a private, loopback, or link-local address.
 *
 * Used for SSRF protection to block requests targeting internal networks.
 * Covers:
 * - IP literals: RFC 1918, RFC 6598, loopback, link-local, IPv6 equivalents
 * - Known private hostname patterns: localhost, .localhost, .local, .internal
 * - DNS resolution: resolves hostnames and checks all resulting IPs
 *
 * DNS resolution guards against rebinding attacks where a public-looking
 * hostname (e.g. evil.com) resolves to a private IP (e.g. 169.254.169.254).
 */
export async function isPrivateNetwork(hostname: string): Promise<boolean> {
  // Fast path: IP literals
  if (isPrivateIP(hostname)) return true

  const lower = hostname.toLowerCase()

  // Well-known private hostnames (RFC 6761, mDNS, cloud metadata conventions)
  if (lower === "localhost" || lower.endsWith(".localhost")) return true
  if (lower.endsWith(".local")) return true
  if (lower.endsWith(".internal")) return true

  // Not an IP literal and not a known-private hostname — resolve DNS and
  // check whether any of the resulting addresses are private.
  const { promises: dns } = await import("node:dns")
  try {
    const addrs = await dns.resolve4(hostname)
    if (addrs.some((ip) => isPrivateIP(ip))) return true
  } catch {
    // ENODATA / ENOTFOUND — no A records, continue to AAAA check
  }
  try {
    const addrs = await dns.resolve6(hostname)
    if (addrs.some((ip) => isPrivateIP(ip))) return true
  } catch {
    // ENODATA / ENOTFOUND — no AAAA records
  }

  return false
}

/**
 * Validate a resource identifier per RFC 9728 §2:
 * - MUST use https scheme
 * - MUST be an absolute URI
 * - MUST NOT contain a fragment
 */
function validateResource(resource: string): boolean {
  const url = requireHttps(resource)
  if (!url) return false
  if (url.hash) return false
  return true
}

/**
 * Validate an issuer identifier per RFC 8414 §2:
 * - MUST use https scheme
 * - MUST NOT contain query or fragment components
 */
function validateIssuer(issuer: string): boolean {
  const url = requireHttps(issuer)
  if (!url) return false
  if (url.search || url.hash) return false
  return true
}

// ---------------------------------------------------------------------------
// Field-level validation
// ---------------------------------------------------------------------------

const BEARER_METHODS = new Set(["header", "body", "query"])

/** Validate that value is a non-empty string array with all non-empty entries. */
function isStringArray(val: unknown): val is string[] {
  if (!Array.isArray(val)) return false
  return val.every((v) => typeof v === "string" && v.length > 0)
}

/** Type-check known fields of a resource metadata object. Returns false on type mismatch. */
function validateResourceFields(obj: Record<string, unknown>): boolean {
  // String fields
  for (const f of ["resource", "jwks_uri", "resource_name", "resource_documentation",
    "resource_policy_uri", "resource_tos_uri", "signed_metadata"] as const) {
    if (obj[f] !== undefined && typeof obj[f] !== "string") return false
  }
  // String array fields
  for (const f of ["authorization_servers", "scopes_supported", "bearer_methods_supported",
    "resource_signing_alg_values_supported", "dpop_signing_alg_values_supported",
    "authorization_details_types_supported"] as const) {
    if (obj[f] !== undefined && !isStringArray(obj[f])) return false
  }
  // Boolean fields
  for (const f of ["tls_client_certificate_bound_access_tokens",
    "dpop_bound_access_tokens_required"] as const) {
    if (obj[f] !== undefined && typeof obj[f] !== "boolean") return false
  }
  return true
}

/** Semantic validation of resource metadata per RFC 9728 §2. */
function validateResourceSemantics(meta: ResourceMetadata): string | undefined {
  if (!validateResource(meta.resource))
    return "resource must be HTTPS absolute URI without fragment"

  // RFC 9728 §2: bearer_methods_supported — defined values are "header",
  // "body", "query" but the list is descriptive, not exhaustive. Future
  // extensions may add new methods, so unknown values are accepted.

  // RFC 9728 §2: resource_signing_alg_values_supported must not include "none"
  if (meta.resource_signing_alg_values_supported?.includes("none"))
    return 'resource_signing_alg_values_supported must not include "none"'

  // RFC 9728 §2: jwks_uri must be HTTPS
  if (meta.jwks_uri && !requireHttps(meta.jwks_uri))
    return "jwks_uri must be HTTPS"

  // RFC 9728 §2: authorization_servers entries must be valid issuer identifiers
  if (meta.authorization_servers) {
    for (const id of meta.authorization_servers) {
      if (!validateIssuer(id)) return `invalid authorization server identifier: ${id}`
    }
  }

  return undefined
}

/** Type-check known fields of an AS metadata object. */
function validateASFields(obj: Record<string, unknown>): boolean {
  // String fields
  for (const f of ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
    "registration_endpoint", "service_documentation", "device_authorization_endpoint",
    "signed_metadata"] as const) {
    if (obj[f] !== undefined && typeof obj[f] !== "string") return false
  }
  // String array fields
  for (const f of ["scopes_supported", "response_types_supported", "grant_types_supported",
    "code_challenge_methods_supported", "token_endpoint_auth_methods_supported",
    "response_modes_supported"] as const) {
    if (obj[f] !== undefined && !isStringArray(obj[f])) return false
  }
  return true
}

// ---------------------------------------------------------------------------
// Well-known URL construction
// ---------------------------------------------------------------------------

/**
 * Construct the .well-known/oauth-protected-resource URL per RFC 9728 §3.1.
 *
 * Insertion algorithm: the well-known suffix is inserted between the host
 * and the path component of the resource identifier. The query component
 * from the resource URL is preserved.
 *
 * Examples:
 *   https://resource.example.com           -> https://resource.example.com/.well-known/oauth-protected-resource
 *   https://resource.example.com/r1        -> https://resource.example.com/.well-known/oauth-protected-resource/r1
 *   https://resource.example.com/r1?q=1    -> https://resource.example.com/.well-known/oauth-protected-resource/r1?q=1
 *   https://resource.example.com/r1/       -> https://resource.example.com/.well-known/oauth-protected-resource/r1/
 */
export function resourceMetadataUrl(resource: string): string {
  const url = new URL(resource)
  const suffix = url.pathname === "/" ? "" : url.pathname
  return `${url.origin}/.well-known/oauth-protected-resource${suffix}${url.search}`
}

/**
 * Construct the .well-known/oauth-authorization-server URL per RFC 8414 §3.1.
 *
 * Issuer identifiers MUST NOT have query/fragment per RFC 8414 §2.
 * Trailing slashes on the issuer path are normalized (removed).
 */
export function asMetadataUrl(issuer: string): string {
  const url = new URL(issuer)
  // RFC 8414 §3.1: normalize trailing slash on issuer path
  let suffix = url.pathname === "/" ? "" : url.pathname
  if (suffix.endsWith("/")) suffix = suffix.slice(0, -1)
  return `${url.origin}/.well-known/oauth-authorization-server${suffix}`
}

/**
 * Fallback: .well-known/openid-configuration (OIDC Discovery 1.0 §4.1).
 *
 * OIDC Discovery §4.1: the well-known path is appended to the issuer,
 * preserving any path component. For example:
 *   https://example.com          -> https://example.com/.well-known/openid-configuration
 *   https://example.com/tenant   -> https://example.com/tenant/.well-known/openid-configuration
 *
 * This is different from RFC 8414 which inserts the well-known path
 * between the host and the issuer path.
 */
function oidcMetadataUrl(issuer: string): string {
  const url = new URL(issuer)
  let base = url.pathname
  if (base.endsWith("/")) base = base.slice(0, -1)
  return `${url.origin}${base}/.well-known/openid-configuration`
}

// ---------------------------------------------------------------------------
// Fetch + validate
// ---------------------------------------------------------------------------

/** Maximum metadata response size (1 MiB). Prevents OOM from malicious servers. */
const MAX_METADATA_BYTES = 1_048_576

/**
 * Read response body as JSON, enforcing a byte size limit.
 * Prevents OOM from malicious servers returning multi-gigabyte responses.
 */
async function readJsonLimited(response: Response, limit: number): Promise<unknown> {
  const cl = response.headers.get("content-length")
  if (cl && parseInt(cl, 10) > limit) return undefined

  const reader = response.body?.getReader()
  if (!reader) return undefined

  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > limit) {
      await reader.cancel()
      return undefined
    }
    chunks.push(value)
  }

  try {
    return JSON.parse(await new Blob(chunks).text())
  } catch {
    return undefined
  }
}

/**
 * Fetch and validate Protected Resource Metadata (RFC 9728).
 *
 * Validation steps per RFC 9728:
 * - §3.2: Response Content-Type MUST be application/json
 * - §3.2: The response MUST NOT be the result of a redirect
 * - §3.3: The "resource" value MUST exactly match the expected resource identifier
 * - §2: All known fields are type-checked
 * - §2: bearer_methods_supported values must be "header", "body", or "query"
 * - §2: resource_signing_alg_values_supported must not include "none"
 * - §2: jwks_uri must be HTTPS
 * - §2: authorization_servers entries must be valid issuer identifiers
 *
 * @param url - The metadata URL to fetch (from WWW-Authenticate or well-known probe)
 * @param resource - The original resource URL for §3.3 match validation
 */
export async function fetchResourceMetadata(
  url: string,
  resource: string,
  signal?: AbortSignal,
): Promise<ResourceMetadata | undefined> {
  // RFC 9728 §7.7: metadata URL must be HTTPS
  if (!requireHttps(url)) {
    log.error("resource metadata URL must be HTTPS", { url })
    return undefined
  }

  log.info("fetching resource metadata", { url })

  // RFC 9728 §3.2: redirect MUST NOT be followed
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    redirect: "error",
    signal,
  }).catch(() => undefined)

  if (!response || !response.ok) {
    log.info("resource metadata not found", { url, status: response?.status })
    return undefined
  }

  // RFC 9728 §3.2: Content-Type MUST be application/json.
  // Only accept application/json (with optional parameters like charset).
  // Reject loose matches like text/json or application/vnd.api+json.
  const ct = response.headers.get("content-type") ?? ""
  const mediaType = ct.split(";")[0]?.trim().toLowerCase() ?? ""
  if (mediaType !== "application/json") {
    log.info("resource metadata wrong content-type", { url, contentType: ct })
    return undefined
  }

  const body = await readJsonLimited(response, MAX_METADATA_BYTES)
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    log.info("resource metadata invalid or oversized response", { url })
    return undefined
  }

  const obj = body as Record<string, unknown>

  // Type-check known fields
  if (!validateResourceFields(obj)) {
    log.info("resource metadata has invalid field types", { url })
    return undefined
  }

  if (typeof obj.resource !== "string") {
    log.info("resource metadata missing resource field", { url })
    return undefined
  }

  const metadata = obj as ResourceMetadata

  // Semantic validation
  const err = validateResourceSemantics(metadata)
  if (err) {
    log.error("resource metadata semantic error", { url, error: err })
    return undefined
  }

  // RFC 9728 §3.3 + §6: resource value MUST exactly match the expected
  // resource identifier using code-point-to-code-point comparison.
  // URL normalization (e.g. https://example.com:443/ vs https://example.com/)
  // MUST NOT be applied — the comparison is on the original string values.
  if (metadata.resource !== resource) {
    log.error("resource metadata mismatch", { expected: resource, got: metadata.resource })
    return undefined
  }

  log.info("resource metadata fetched", {
    resource: metadata.resource,
    servers: metadata.authorization_servers,
  })
  return metadata
}

/**
 * Fetch and validate Authorization Server Metadata (RFC 8414).
 *
 * Validation steps per RFC 8414:
 * - §2: issuer MUST be HTTPS, no query/fragment
 * - §2: response_types_supported is REQUIRED and must be a non-empty string array
 * - §2: default grant_types_supported is ["authorization_code", "implicit"]
 * - §3.3: issuer value MUST exactly match the expected issuer
 * - All known fields are type-checked
 *
 * Falls back to OIDC Discovery (.well-known/openid-configuration) if
 * the RFC 8414 endpoint is not available.
 */
export async function fetchASMetadata(issuer: string, signal?: AbortSignal): Promise<ASMetadata | undefined> {
  // RFC 8414 §2: issuer must be HTTPS, no query/fragment
  if (!validateIssuer(issuer)) {
    log.error("invalid issuer identifier", { issuer })
    return undefined
  }

  const url = asMetadataUrl(issuer)
  log.info("fetching AS metadata", { url })

  // Block redirects to prevent SSRF — a malicious or compromised AS metadata
  // endpoint could redirect to internal services (cloud metadata, private nets).
  // This matches the stricter behavior used for resource metadata (RFC 9728 §3.2).
  let response = await fetch(url, {
    headers: { Accept: "application/json" },
    redirect: "error",
    signal,
  }).catch(() => undefined)

  // Fallback to OIDC discovery
  if (!response || !response.ok) {
    const fallback = oidcMetadataUrl(issuer)
    log.info("trying OIDC discovery fallback", { url: fallback })
    response = await fetch(fallback, {
      headers: { Accept: "application/json" },
      redirect: "error",
      signal,
    }).catch(() => undefined)
  }

  if (!response || !response.ok) {
    log.info("AS metadata not found", { issuer })
    return undefined
  }

  // Content-Type check — only accept application/json (with optional parameters)
  const ct = response.headers.get("content-type") ?? ""
  const asMediaType = ct.split(";")[0]?.trim().toLowerCase() ?? ""
  if (asMediaType !== "application/json") {
    log.info("AS metadata wrong content-type", { issuer, contentType: ct })
    return undefined
  }

  const body = await readJsonLimited(response, MAX_METADATA_BYTES)
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    log.info("AS metadata invalid or oversized response", { issuer })
    return undefined
  }

  const obj = body as Record<string, unknown>

  // Type-check known fields
  if (!validateASFields(obj)) {
    log.info("AS metadata has invalid field types", { issuer })
    return undefined
  }

  if (typeof obj.issuer !== "string") {
    log.info("AS metadata missing issuer field", { issuer })
    return undefined
  }

  const metadata = obj as ASMetadata

  // RFC 8414 §3.3: issuer must exactly match
  if (metadata.issuer !== issuer) {
    log.error("AS metadata issuer mismatch", { expected: issuer, got: metadata.issuer })
    return undefined
  }

  // RFC 8414 §2: response_types_supported is REQUIRED
  if (!Array.isArray(metadata.response_types_supported) || metadata.response_types_supported.length === 0) {
    log.error("AS metadata missing or empty response_types_supported", { issuer })
    return undefined
  }

  // RFC 8414 §2: jwks_uri MUST be HTTPS
  if (metadata.jwks_uri && !requireHttps(metadata.jwks_uri)) {
    log.error("AS metadata jwks_uri must be HTTPS", { issuer, value: metadata.jwks_uri })
    return undefined
  }

  // RFC 8414 §2: token_endpoint_auth_signing_alg_values_supported MUST NOT
  // include "none" (it would allow unsigned client assertions).
  const sigAlgs = obj.token_endpoint_auth_signing_alg_values_supported
  if (Array.isArray(sigAlgs) && sigAlgs.includes("none")) {
    log.error("AS metadata token_endpoint_auth_signing_alg_values_supported must not include 'none'", { issuer })
    return undefined
  }

  // Validate endpoint URLs are HTTPS (or HTTP loopback per RFC 8252 §7.3).
  // A malicious AS metadata document could set these to HTTP URLs, exposing
  // authorization codes, PKCE verifiers, or tokens in cleartext.
  for (const field of [
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "device_authorization_endpoint",
  ] as const) {
    if (metadata[field] && !requireHttps(metadata[field]!)) {
      log.error(`AS metadata ${field} must be HTTPS`, { issuer, value: metadata[field] })
      return undefined
    }
  }

  // RFC 8414 §2: default grant_types_supported
  if (!metadata.grant_types_supported) {
    metadata.grant_types_supported = ["authorization_code", "implicit"]
  }

  // RFC 8414 §2: defaults for optional fields when omitted
  const asObj = metadata as Record<string, unknown>
  if (!asObj.response_modes_supported) asObj.response_modes_supported = ["query", "fragment"]
  if (!asObj.token_endpoint_auth_methods_supported)
    asObj.token_endpoint_auth_methods_supported = ["client_secret_basic"]

  // RFC 8414 §2: authorization_endpoint required when grant types include
  // authorization_code or implicit
  const grants = new Set(metadata.grant_types_supported)
  if ((grants.has("authorization_code") || grants.has("implicit")) && !metadata.authorization_endpoint) {
    log.error("AS metadata missing authorization_endpoint for supported grant types", { issuer })
    return undefined
  }

  // RFC 8414 §2: token_endpoint required unless only implicit grant
  if (!(grants.size === 1 && grants.has("implicit")) && !metadata.token_endpoint) {
    log.error("AS metadata missing token_endpoint", { issuer })
    return undefined
  }

  log.info("AS metadata fetched", {
    issuer: metadata.issuer,
    grants: metadata.grant_types_supported,
  })
  return metadata
}

/** Cap on authorization_servers entries to prevent abuse via enumeration. */
export const MAX_AUTHORIZATION_SERVERS = 5

/**
 * Full discovery flow: given a resource URL and optional resource_metadata URL
 * from WWW-Authenticate, discover the resource metadata and AS metadata.
 *
 * This implements the discovery flow described in RFC 9728 §4:
 * 1. Fetch protected resource metadata (explicit URL or well-known probe)
 * 2. For each authorization_servers entry, fetch AS metadata per RFC 8414
 */
export async function discover(
  resource: string,
  metadataUrl?: string,
  signal?: AbortSignal,
): Promise<{ resource?: ResourceMetadata; servers: ASMetadata[] }> {
  const resourceHost = new URL(resource).hostname
  const local = await isPrivateNetwork(resourceHost)

  // SSRF protection: reject private-network metadata URLs from public resources.
  // A malicious server could return 401 with resource_metadata pointing at
  // http://169.254.169.254/... (cloud metadata) or http://10.x.x.x/... to
  // probe internal services. Only allow private targets when the resource
  // itself is on a private network (e.g. local development).
  if (metadataUrl) {
    const metaHost = new URL(metadataUrl).hostname
    if ((await isPrivateNetwork(metaHost)) && !local) {
      log.error("rejecting private-network metadata URL from public resource", {
        resource,
        metadataUrl,
      })
      return { servers: [] }
    }
  }

  const probe = metadataUrl ?? resourceMetadataUrl(resource)
  const meta = await fetchResourceMetadata(probe, resource, signal)

  if (!meta || !meta.authorization_servers?.length)
    return { resource: meta, servers: [] }

  const capped = meta.authorization_servers.slice(0, MAX_AUTHORIZATION_SERVERS)
  const servers: ASMetadata[] = []
  for (const issuer of capped) {
    // SSRF protection: reject private-network AS from public resource
    const issuerHost = new URL(issuer).hostname
    if ((await isPrivateNetwork(issuerHost)) && !local) {
      log.error("rejecting private-network AS from public resource", { resource, issuer })
      continue
    }
    const as = await fetchASMetadata(issuer, signal)
    if (as) servers.push(as)
  }

  return { resource: meta, servers }
}

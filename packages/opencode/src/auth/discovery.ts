/**
 * RFC 9728 (Protected Resource Metadata) and RFC 8414 (AS Metadata) discovery.
 *
 * Validates metadata documents with field-level type checking adapted from
 * the audited implementation in irvinebroque/http-rfc-utils.
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
// Types — adapted from irvinebroque/http-rfc-utils src/types/discovery.ts
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
function requireHttps(raw: string): URL | undefined {
  if (!URL.canParse(raw)) return undefined
  const url = new URL(raw)
  if (url.protocol === "https:") return url
  if (url.protocol === "http:" && isLoopback(url.hostname)) return url
  return undefined
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"])

function isLoopback(hostname: string): boolean {
  return LOOPBACK.has(hostname)
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
// Field-level validation — adapted from irvinebroque/http-rfc-utils
// src/oauth-protected-resource-metadata.ts and
// src/oauth-authorization-server-metadata.ts
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

  // RFC 9728 §2: bearer_methods_supported values
  if (meta.bearer_methods_supported) {
    for (const m of meta.bearer_methods_supported) {
      if (!BEARER_METHODS.has(m)) return `invalid bearer method: ${m}`
    }
  }

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
 * Trailing slashes on the issuer path are normalized (removed) per the
 * reference implementation in irvinebroque/http-rfc-utils.
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
 * Unlike RFC 8414, OIDC places the well-known path at the origin level.
 */
function oidcMetadataUrl(issuer: string): string {
  const url = new URL(issuer)
  return `${url.origin}/.well-known/openid-configuration`
}

// ---------------------------------------------------------------------------
// Fetch + validate
// ---------------------------------------------------------------------------

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
  }).catch(() => undefined)

  if (!response || !response.ok) {
    log.info("resource metadata not found", { url, status: response?.status })
    return undefined
  }

  // RFC 9728 §3.2: Content-Type must be application/json
  const ct = response.headers.get("content-type") ?? ""
  if (!ct.includes("application/json") && !ct.includes("json")) {
    log.info("resource metadata wrong content-type", { url, contentType: ct })
    return undefined
  }

  const body = await response.json().catch(() => undefined)
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    log.info("resource metadata invalid JSON", { url })
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

  // RFC 9728 §3.3: resource value MUST exactly match the expected resource identifier
  const expected = new URL(resource)
  const actual = new URL(metadata.resource)
  // Fragments are not sent to servers, strip for comparison
  expected.hash = ""
  if (expected.href !== actual.href) {
    log.error("resource metadata mismatch", { expected: expected.href, got: actual.href })
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
export async function fetchASMetadata(issuer: string): Promise<ASMetadata | undefined> {
  // RFC 8414 §2: issuer must be HTTPS, no query/fragment
  if (!validateIssuer(issuer)) {
    log.error("invalid issuer identifier", { issuer })
    return undefined
  }

  const url = asMetadataUrl(issuer)
  log.info("fetching AS metadata", { url })

  let response = await fetch(url, {
    headers: { Accept: "application/json" },
    redirect: "error",
  }).catch(() => undefined)

  // Fallback to OIDC discovery
  if (!response || !response.ok) {
    const fallback = oidcMetadataUrl(issuer)
    log.info("trying OIDC discovery fallback", { url: fallback })
    response = await fetch(fallback, {
      headers: { Accept: "application/json" },
      redirect: "error",
    }).catch(() => undefined)
  }

  if (!response || !response.ok) {
    log.info("AS metadata not found", { issuer })
    return undefined
  }

  // Content-Type check
  const ct = response.headers.get("content-type") ?? ""
  if (!ct.includes("application/json") && !ct.includes("json")) {
    log.info("AS metadata wrong content-type", { issuer, contentType: ct })
    return undefined
  }

  const body = await response.json().catch(() => undefined)
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    log.info("AS metadata invalid JSON", { issuer })
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

  // RFC 8414 §2: default grant_types_supported
  if (!metadata.grant_types_supported) {
    metadata.grant_types_supported = ["authorization_code", "implicit"]
  }

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
): Promise<{ resource?: ResourceMetadata; servers: ASMetadata[] }> {
  const probe = metadataUrl ?? resourceMetadataUrl(resource)
  const meta = await fetchResourceMetadata(probe, resource)

  if (!meta || !meta.authorization_servers?.length)
    return { resource: meta, servers: [] }

  const servers: ASMetadata[] = []
  for (const issuer of meta.authorization_servers) {
    const as = await fetchASMetadata(issuer)
    if (as) servers.push(as)
  }

  return { resource: meta, servers }
}

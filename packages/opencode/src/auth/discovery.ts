/**
 * RFC 9728 (Protected Resource Metadata) and RFC 8414 (AS Metadata) discovery.
 *
 * Fetches .well-known documents and validates them per the RFCs.
 */

import { Log } from "../util/log"

const log = Log.create({ service: "webfetch.discovery" })

export type ResourceMetadata = {
  resource: string
  authorization_servers?: string[]
  scopes_supported?: string[]
  bearer_methods_supported?: string[]
  resource_name?: string
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
}

/**
 * Validate that a URL uses HTTPS and is an absolute URI.
 * Returns the parsed URL or undefined if invalid.
 */
function requireHttps(raw: string): URL | undefined {
  if (!URL.canParse(raw)) return undefined
  const url = new URL(raw)
  if (url.protocol !== "https:") return undefined
  return url
}

/**
 * Validate a resource identifier per RFC 9728 Section 2:
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
 * Validate an issuer identifier per RFC 8414 Section 2:
 * - MUST use https scheme
 * - MUST NOT contain query or fragment components
 */
function validateIssuer(issuer: string): boolean {
  const url = requireHttps(issuer)
  if (!url) return false
  if (url.search || url.hash) return false
  return true
}

/**
 * Validate an authorization server URL per RFC 9728 Section 2:
 * - MUST be an HTTPS URI per RFC 8414
 * - MUST NOT contain query or fragment components
 */
function validateASIdentifier(id: string): boolean {
  return validateIssuer(id)
}

/**
 * Construct the .well-known/oauth-protected-resource URL per RFC 9728 Section 3.1.
 * Insert /.well-known/oauth-protected-resource between host and path.
 * Preserves the query string from the resource URL.
 *
 * https://resource.example.com -> https://resource.example.com/.well-known/oauth-protected-resource
 * https://resource.example.com/r1 -> https://resource.example.com/.well-known/oauth-protected-resource/r1
 * https://resource.example.com/r1?q=1 -> https://resource.example.com/.well-known/oauth-protected-resource/r1?q=1
 */
export function resourceMetadataUrl(resource: string): string {
  const url = new URL(resource)
  const prefix = `${url.protocol}//${url.host}`
  const suffix = url.pathname === "/" ? "" : url.pathname
  const query = url.search
  return `${prefix}/.well-known/oauth-protected-resource${suffix}${query}`
}

/**
 * Construct the .well-known/oauth-authorization-server URL per RFC 8414 Section 3.1.
 * Issuer identifiers must not have query/fragment per RFC 8414 Section 2.
 */
export function asMetadataUrl(issuer: string): string {
  const url = new URL(issuer)
  const prefix = `${url.protocol}//${url.host}`
  const suffix = url.pathname === "/" ? "" : url.pathname
  return `${prefix}/.well-known/oauth-authorization-server${suffix}`
}

/**
 * Fallback: try .well-known/openid-configuration
 */
function oidcMetadataUrl(issuer: string): string {
  const url = new URL(issuer)
  return `${url.origin}/.well-known/openid-configuration`
}

/**
 * Fetch and validate Protected Resource Metadata (RFC 9728).
 *
 * @param url - Either the resource_metadata URL from WWW-Authenticate, or a well-known URL to probe
 * @param resource - The original resource URL the client requested (for validation)
 */
export async function fetchResourceMetadata(
  url: string,
  resource: string,
): Promise<ResourceMetadata | undefined> {
  // RFC 9728 Section 7.7: metadata URL must be HTTPS
  const parsed = requireHttps(url)
  if (!parsed) {
    log.error("resource metadata URL must be HTTPS", { url })
    return undefined
  }

  log.info("fetching resource metadata", { url })

  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    redirect: "error",
  }).catch(() => undefined)

  if (!response || !response.ok) {
    log.info("resource metadata not found", { url, status: response?.status })
    return undefined
  }

  const body = await response.json().catch(() => undefined)
  if (!body || typeof body !== "object" || !("resource" in body)) {
    log.info("resource metadata invalid", { url })
    return undefined
  }

  const metadata = body as ResourceMetadata

  // RFC 9728 Section 2: resource must be HTTPS, absolute URI, no fragment
  if (!validateResource(metadata.resource)) {
    log.error("resource metadata has invalid resource identifier", { resource: metadata.resource })
    return undefined
  }

  // RFC 9728 Section 3.3: resource value must be identical to the resource identifier
  // used in building the well-known request (exact match, not just origin)
  const expected = new URL(resource)
  const actual = new URL(metadata.resource)
  // Strip fragment from expected for comparison (fragments are not sent to servers)
  expected.hash = ""
  if (expected.href !== actual.href) {
    log.error("resource metadata mismatch", { expected: expected.href, got: actual.href })
    return undefined
  }

  // Validate authorization_servers entries
  if (metadata.authorization_servers) {
    const valid = metadata.authorization_servers.filter((id) => {
      if (!validateASIdentifier(id)) {
        log.error("invalid authorization server identifier", { id })
        return false
      }
      return true
    })
    metadata.authorization_servers = valid.length ? valid : undefined
  }

  log.info("resource metadata fetched", {
    resource: metadata.resource,
    servers: metadata.authorization_servers,
  })
  return metadata
}

/**
 * Fetch and validate Authorization Server Metadata (RFC 8414).
 */
export async function fetchASMetadata(issuer: string): Promise<ASMetadata | undefined> {
  // RFC 8414 Section 2: issuer must be HTTPS, no query/fragment
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

  const body = await response.json().catch(() => undefined)
  if (!body || typeof body !== "object" || !("issuer" in body)) {
    log.info("AS metadata invalid", { issuer })
    return undefined
  }

  const metadata = body as ASMetadata

  // RFC 8414 Section 3.3: issuer must match
  if (metadata.issuer !== issuer) {
    log.error("AS metadata issuer mismatch", { expected: issuer, got: metadata.issuer })
    return undefined
  }

  // RFC 8414 Section 2: response_types_supported is REQUIRED
  if (!Array.isArray(metadata.response_types_supported)) {
    log.error("AS metadata missing required response_types_supported", { issuer })
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
 */
export async function discover(
  resource: string,
  metadataUrl?: string,
): Promise<{ resource?: ResourceMetadata; servers: ASMetadata[] }> {
  // Try explicit metadata URL first, then probe .well-known on origin
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

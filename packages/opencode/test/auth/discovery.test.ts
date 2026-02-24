/**
 * Tests for RFC 9728 (Protected Resource Metadata) and RFC 8414 (AS Metadata) discovery.
 *
 * Tests the well-known URL construction and metadata validation logic.
 * Network-level fetch tests use mock servers via Bun.serve.
 *

 */
import { describe, test, expect, afterEach } from "bun:test"
import {
  resourceMetadataUrl,
  asMetadataUrl,
  fetchResourceMetadata,
  fetchASMetadata,
  isPrivateNetwork,
  MAX_AUTHORIZATION_SERVERS,
} from "../../src/auth/discovery"

// ---------------------------------------------------------------------------
// Well-known URL construction — RFC 9728 §3.1
// ---------------------------------------------------------------------------

describe("resourceMetadataUrl (RFC 9728 §3.1)", () => {
  test("root resource — no path", () => {
    expect(resourceMetadataUrl("https://example.com")).toBe(
      "https://example.com/.well-known/oauth-protected-resource",
    )
  })

  test("root resource with trailing slash", () => {
    expect(resourceMetadataUrl("https://example.com/")).toBe(
      "https://example.com/.well-known/oauth-protected-resource",
    )
  })

  test("resource with path", () => {
    expect(resourceMetadataUrl("https://example.com/resource1")).toBe(
      "https://example.com/.well-known/oauth-protected-resource/resource1",
    )
  })

  test("resource with path and trailing slash", () => {
    expect(resourceMetadataUrl("https://example.com/resource1/")).toBe(
      "https://example.com/.well-known/oauth-protected-resource/resource1/",
    )
  })

  test("resource with path and query string", () => {
    expect(resourceMetadataUrl("https://example.com/resource1?x=1")).toBe(
      "https://example.com/.well-known/oauth-protected-resource/resource1?x=1",
    )
  })

  test("resource with only query string", () => {
    expect(resourceMetadataUrl("https://example.com/?x=1")).toBe(
      "https://example.com/.well-known/oauth-protected-resource?x=1",
    )
  })

  test("resource with nested path", () => {
    expect(resourceMetadataUrl("https://example.com/a/b/c")).toBe(
      "https://example.com/.well-known/oauth-protected-resource/a/b/c",
    )
  })
})

// ---------------------------------------------------------------------------
// Well-known URL construction — RFC 8414 §3.1
// ---------------------------------------------------------------------------

describe("asMetadataUrl (RFC 8414 §3.1)", () => {
  test("root issuer", () => {
    expect(asMetadataUrl("https://as.example.com")).toBe(
      "https://as.example.com/.well-known/oauth-authorization-server",
    )
  })

  test("issuer with path", () => {
    expect(asMetadataUrl("https://as.example.com/tenant")).toBe(
      "https://as.example.com/.well-known/oauth-authorization-server/tenant",
    )
  })

  test("issuer with trailing slash is normalized", () => {
    expect(asMetadataUrl("https://as.example.com/tenant/")).toBe(
      "https://as.example.com/.well-known/oauth-authorization-server/tenant",
    )
  })

  test("root issuer with trailing slash", () => {
    expect(asMetadataUrl("https://as.example.com/")).toBe(
      "https://as.example.com/.well-known/oauth-authorization-server",
    )
  })

  test("issuer with nested path", () => {
    expect(asMetadataUrl("https://example.com/tenant/sub")).toBe(
      "https://example.com/.well-known/oauth-authorization-server/tenant/sub",
    )
  })

  test("issuer with nested path and trailing slash", () => {
    expect(asMetadataUrl("https://example.com/tenant/sub/")).toBe(
      "https://example.com/.well-known/oauth-authorization-server/tenant/sub",
    )
  })
})

// ---------------------------------------------------------------------------
// fetchResourceMetadata — field validation (RFC 9728 §2)
// ---------------------------------------------------------------------------

describe("fetchResourceMetadata validation", () => {
  const servers: ReturnType<typeof Bun.serve>[] = []
  afterEach(() => {
    for (const s of servers) s.stop()
    servers.length = 0
  })

  function serve(body: unknown, ct = "application/json"): string {
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(JSON.stringify(body), {
          headers: { "Content-Type": ct },
        })
      },
    })
    servers.push(s)
    // Use http for tests (the HTTPS check is bypassed by passing an explicit URL)
    return `http://127.0.0.1:${s.port}`
  }

  test("rejects non-HTTPS metadata URL", async () => {
    const result = await fetchResourceMetadata("http://example.com/.well-known/test", "https://example.com")
    expect(result).toBeUndefined()
  })

  test("rejects wrong content-type", async () => {
    const url = serve({ resource: "https://example.com" }, "text/html")
    // Bypass HTTPS check by providing the URL directly
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("rejects non-object JSON response", async () => {
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response("[]", {
          headers: { "Content-Type": "application/json" },
        })
      },
    })
    servers.push(s)
    const result = await fetchResourceMetadata(`http://127.0.0.1:${s.port}`, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("accepts metadata with unknown bearer_methods_supported values", async () => {
    // RFC 9728 §2: bearer_methods_supported values are descriptive, not exhaustive.
    // Unknown values from future extensions must be accepted.
    const url = serve({
      resource: "https://example.com",
      bearer_methods_supported: ["header", "future_method"],
    })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeDefined()
    expect(result!.bearer_methods_supported).toEqual(["header", "future_method"])
  })

  test("rejects metadata where resource_signing_alg includes 'none'", async () => {
    const url = serve({
      resource: "https://example.com",
      resource_signing_alg_values_supported: ["RS256", "none"],
    })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("rejects metadata where jwks_uri is not HTTPS", async () => {
    const url = serve({
      resource: "https://example.com",
      jwks_uri: "http://example.com/jwks.json",
    })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("rejects metadata where resource does not match expected", async () => {
    const url = serve({ resource: "https://other.example.com" })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("rejects metadata with non-string array in string array field", async () => {
    const url = serve({
      resource: "https://example.com",
      scopes_supported: ["read", 42],
    })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("rejects metadata with non-boolean boolean field", async () => {
    const url = serve({
      resource: "https://example.com",
      tls_client_certificate_bound_access_tokens: "true",
    })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("rejects metadata with invalid authorization_server identifier", async () => {
    const url = serve({
      resource: "https://example.com",
      authorization_servers: ["https://as.example.com?q=1"],
    })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("rejects metadata from a redirect (RFC 9728 §3.2)", async () => {
    // RFC 9728 §3.2: "The resource server MUST NOT redirect"
    // Our fetch uses redirect: "error" so a 302 should cause rejection
    let resPort = 0
    const s = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url)
        if (url.pathname === "/target") {
          return new Response(
            JSON.stringify({ resource: `http://127.0.0.1:${resPort}` }),
            { headers: { "Content-Type": "application/json" } },
          )
        }
        // Return a redirect
        return new Response(null, {
          status: 302,
          headers: { Location: `http://127.0.0.1:${resPort}/target` },
        })
      },
    })
    resPort = s.port as number
    servers.push(s)
    const result = await fetchResourceMetadata(
      `http://127.0.0.1:${resPort}`,
      `http://127.0.0.1:${resPort}`,
    )
    // redirect: "error" causes fetch to reject → result is undefined
    expect(result).toBeUndefined()
  })

  test("rejects resource match with port normalization (RFC 9728 §6 exact match)", async () => {
    // RFC 9728 §6: comparison is code-point-to-code-point.
    // https://example.com:443/ and https://example.com/ are different strings.
    const url = serve({ resource: "https://example.com:443/" })
    const result = await fetchResourceMetadata(url, "https://example.com/")
    expect(result).toBeUndefined()
  })

  test("rejects resource match with trailing slash difference", async () => {
    // RFC 9728 §6: https://example.com and https://example.com/ are different strings
    const url = serve({ resource: "https://example.com/" })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("accepts application/json with charset parameter", async () => {
    const url = serve(
      { resource: "https://example.com" },
      "application/json; charset=utf-8",
    )
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeDefined()
    expect(result!.resource).toBe("https://example.com")
  })

  test("accepts valid metadata with all fields", async () => {
    const url = serve({
      resource: "https://example.com",
      authorization_servers: ["https://as.example.com"],
      scopes_supported: ["read", "write"],
      bearer_methods_supported: ["header"],
      jwks_uri: "https://example.com/jwks.json",
      resource_name: "Test Resource",
      tls_client_certificate_bound_access_tokens: true,
    })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeDefined()
    expect(result!.resource).toBe("https://example.com")
    expect(result!.authorization_servers).toEqual(["https://as.example.com"])
    expect(result!.scopes_supported).toEqual(["read", "write"])
  })
})

// ---------------------------------------------------------------------------
// fetchASMetadata — validation (RFC 8414 §2)
// ---------------------------------------------------------------------------

describe("fetchASMetadata validation", () => {
  const servers: ReturnType<typeof Bun.serve>[] = []
  afterEach(() => {
    for (const s of servers) s.stop()
    servers.length = 0
  })

  function serveAS(body: unknown, ct = "application/json"): string {
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(JSON.stringify(body), {
          headers: { "Content-Type": ct },
        })
      },
    })
    servers.push(s)
    return `http://127.0.0.1:${s.port}`
  }

  test("rejects non-HTTPS issuer", async () => {
    const result = await fetchASMetadata("http://as.example.com")
    expect(result).toBeUndefined()
  })

  test("rejects issuer with query string", async () => {
    const result = await fetchASMetadata("https://as.example.com?q=1")
    expect(result).toBeUndefined()
  })

  test("rejects issuer with fragment", async () => {
    const result = await fetchASMetadata("https://as.example.com#frag")
    expect(result).toBeUndefined()
  })

  test("rejects metadata with wrong content-type", async () => {
    const issuer = serveAS({ issuer: "placeholder" }, "text/plain")
    const result = await fetchASMetadata(issuer)
    expect(result).toBeUndefined()
  })

  test("accepts application/json with charset in Content-Type", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
            token_endpoint: `http://127.0.0.1:${port}/token`,
            response_types_supported: ["code"],
          }),
          { headers: { "Content-Type": "application/json; charset=utf-8" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeDefined()
    expect(result!.issuer).toBe(`http://127.0.0.1:${port}`)
  })

  test("rejects text/plain content-type for AS metadata", async () => {
    const issuer = serveAS(
      {
        issuer: "placeholder",
        response_types_supported: ["code"],
      },
      "text/plain",
    )
    const result = await fetchASMetadata(issuer)
    expect(result).toBeUndefined()
  })

  test("rejects empty response_types_supported array (RFC 8414 §2)", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
            token_endpoint: `http://127.0.0.1:${port}/token`,
            response_types_supported: [],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeUndefined()
  })

  test("rejects metadata where issuer does not match (RFC 8414 §3.3)", async () => {
    const issuer = serveAS({
      issuer: "http://127.0.0.1:99999",
      response_types_supported: ["code"],
      authorization_endpoint: "http://127.0.0.1:99999/authorize",
      token_endpoint: "http://127.0.0.1:99999/token",
    })
    const result = await fetchASMetadata(issuer)
    expect(result).toBeUndefined()
  })

  test("rejects metadata missing response_types_supported (RFC 8414 §2)", async () => {
    // Must create server first to know port for issuer match
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
            token_endpoint: `http://127.0.0.1:${port}/token`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeUndefined()
  })

  test("rejects metadata missing authorization_endpoint for authorization_code grant", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
            token_endpoint: `http://127.0.0.1:${port}/token`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeUndefined()
  })

  test("rejects metadata missing token_endpoint (non-implicit grant)", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
            authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeUndefined()
  })

  test("accepts valid AS metadata with all required fields", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
            token_endpoint: `http://127.0.0.1:${port}/token`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
            scopes_supported: ["read", "write"],
            code_challenge_methods_supported: ["S256"],
            registration_endpoint: `http://127.0.0.1:${port}/register`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeDefined()
    expect(result!.issuer).toBe(`http://127.0.0.1:${port}`)
    expect(result!.authorization_endpoint).toBe(`http://127.0.0.1:${port}/authorize`)
    expect(result!.token_endpoint).toBe(`http://127.0.0.1:${port}/token`)
    expect(result!.response_types_supported).toEqual(["code"])
    expect(result!.grant_types_supported).toEqual(["authorization_code"])
    expect(result!.scopes_supported).toEqual(["read", "write"])
  })

  test("applies default grant_types_supported when omitted (RFC 8414 §2)", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
            token_endpoint: `http://127.0.0.1:${port}/token`,
            response_types_supported: ["code"],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeDefined()
    // RFC 8414 §2: default is ["authorization_code", "implicit"]
    expect(result!.grant_types_supported).toEqual(["authorization_code", "implicit"])
  })

  test("allows implicit-only grant without token_endpoint", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
            response_types_supported: ["token"],
            grant_types_supported: ["implicit"],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeDefined()
    expect(result!.grant_types_supported).toEqual(["implicit"])
  })

  test("rejects AS metadata where jwks_uri is not HTTPS", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
            token_endpoint: `http://127.0.0.1:${port}/token`,
            response_types_supported: ["code"],
            jwks_uri: "http://example.com/jwks.json",
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeUndefined()
  })

  test("rejects AS metadata with 'none' in token_endpoint_auth_signing_alg_values_supported", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
            token_endpoint: `http://127.0.0.1:${port}/token`,
            response_types_supported: ["code"],
            token_endpoint_auth_signing_alg_values_supported: ["RS256", "none"],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeUndefined()
  })

  test("rejects redirects for AS metadata (SSRF prevention)", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url)
        if (url.pathname === "/target") {
          return new Response(
            JSON.stringify({
              issuer: `http://127.0.0.1:${port}`,
              authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
              token_endpoint: `http://127.0.0.1:${port}/token`,
              response_types_supported: ["code"],
            }),
            { headers: { "Content-Type": "application/json" } },
          )
        }
        return new Response(null, {
          status: 302,
          headers: { Location: `http://127.0.0.1:${port}/target` },
        })
      },
    })
    port = s.port as number
    servers.push(s)
    // Redirects are blocked to prevent SSRF via malicious AS metadata endpoints
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeUndefined()
  })

  test("falls back to OIDC discovery when RFC 8414 endpoint fails", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url)
        // RFC 8414 endpoint returns 404
        if (url.pathname.includes("oauth-authorization-server"))
          return new Response("Not found", { status: 404 })
        // OIDC endpoint returns valid metadata
        if (url.pathname.includes("openid-configuration"))
          return new Response(
            JSON.stringify({
              issuer: `http://127.0.0.1:${port}`,
              authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
              token_endpoint: `http://127.0.0.1:${port}/token`,
              response_types_supported: ["code"],
            }),
            { headers: { "Content-Type": "application/json" } },
          )
        return new Response("Not found", { status: 404 })
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}`)
    expect(result).toBeDefined()
    expect(result!.issuer).toBe(`http://127.0.0.1:${port}`)
  })

  test("OIDC fallback with path-bearing issuer preserves path (RFC 8414 §5)", async () => {
    // OIDC Discovery §4.1: .well-known is appended to the issuer path:
    //   https://example.com/tenant -> https://example.com/tenant/.well-known/openid-configuration
    // NOT placed at the origin like: https://example.com/.well-known/openid-configuration
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url)
        // RFC 8414 returns 404 for path-bearing issuer
        if (url.pathname.includes("oauth-authorization-server"))
          return new Response("Not found", { status: 404 })
        // OIDC endpoint: must be at /tenant/.well-known/openid-configuration
        if (url.pathname === "/tenant/.well-known/openid-configuration")
          return new Response(
            JSON.stringify({
              issuer: `http://127.0.0.1:${port}/tenant`,
              authorization_endpoint: `http://127.0.0.1:${port}/tenant/authorize`,
              token_endpoint: `http://127.0.0.1:${port}/tenant/token`,
              response_types_supported: ["code"],
            }),
            { headers: { "Content-Type": "application/json" } },
          )
        return new Response("Not found", { status: 404 })
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://127.0.0.1:${port}/tenant`)
    expect(result).toBeDefined()
    expect(result!.issuer).toBe(`http://127.0.0.1:${port}/tenant`)
  })
})

// ---------------------------------------------------------------------------
// discover() — end-to-end integration (RFC 9728 §4)
// ---------------------------------------------------------------------------

describe("discover() integration", () => {
  const servers: ReturnType<typeof Bun.serve>[] = []
  afterEach(() => {
    for (const s of servers) s.stop()
    servers.length = 0
  })

  test("discovers resource and AS metadata from a resource URL", async () => {
    // Set up AS server
    let asPort = 0
    const as = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${asPort}`,
            authorization_endpoint: `http://127.0.0.1:${asPort}/authorize`,
            token_endpoint: `http://127.0.0.1:${asPort}/token`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    asPort = as.port as number
    servers.push(as)

    // Set up resource server that serves its own metadata.
    // The resource field must match the resource identifier passed to discover().
    // discover(resource, metadataUrl) uses resource for the comparison check.
    let resPort = 0
    const res = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            resource: `http://127.0.0.1:${resPort}`,
            authorization_servers: [`http://127.0.0.1:${asPort}`],
            scopes_supported: ["read"],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    resPort = res.port as number
    servers.push(res)

    const { discover } = await import("../../src/auth/discovery")
    // Both resource and metadataUrl point to the same origin so the
    // resource field comparison passes (RFC 9728 §3.3).
    const result = await discover(
      `http://127.0.0.1:${resPort}`,
      `http://127.0.0.1:${resPort}`,
    )

    expect(result.resource).toBeDefined()
    expect(result.resource!.resource).toBe(`http://127.0.0.1:${resPort}`)
    expect(result.servers).toHaveLength(1)
    expect(result.servers[0]!.issuer).toBe(`http://127.0.0.1:${asPort}`)
    expect(result.servers[0]!.authorization_endpoint).toBe(`http://127.0.0.1:${asPort}/authorize`)
  })

  test("returns empty servers when resource has no authorization_servers", async () => {
    let resPort = 0
    const res = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            resource: `http://127.0.0.1:${resPort}`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    resPort = res.port as number
    servers.push(res)

    const { discover } = await import("../../src/auth/discovery")
    const result = await discover(
      `http://127.0.0.1:${resPort}`,
      `http://127.0.0.1:${resPort}`,
    )

    expect(result.resource).toBeDefined()
    expect(result.servers).toHaveLength(0)
  })

  test("caps authorization_servers to MAX_AUTHORIZATION_SERVERS", async () => {
    // Track how many times the AS server is contacted
    let fetches = 0

    let asPort = 0
    const as = Bun.serve({
      port: 0,
      fetch() {
        fetches++
        return new Response(
          JSON.stringify({
            issuer: `http://127.0.0.1:${asPort}`,
            authorization_endpoint: `http://127.0.0.1:${asPort}/authorize`,
            token_endpoint: `http://127.0.0.1:${asPort}/token`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    asPort = as.port as number
    servers.push(as)

    // Resource metadata returns well over the cap
    const count = MAX_AUTHORIZATION_SERVERS + 20
    let resPort = 0
    const res = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            resource: `http://127.0.0.1:${resPort}`,
            authorization_servers: Array.from(
              { length: count },
              () => `http://127.0.0.1:${asPort}`,
            ),
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    resPort = res.port as number
    servers.push(res)

    const { discover } = await import("../../src/auth/discovery")
    const result = await discover(
      `http://127.0.0.1:${resPort}`,
      `http://127.0.0.1:${resPort}`,
    )

    // Only MAX_AUTHORIZATION_SERVERS entries should have been fetched
    expect(result.servers).toHaveLength(MAX_AUTHORIZATION_SERVERS)
    // AS server should have been contacted at most MAX_AUTHORIZATION_SERVERS
    // times (each entry triggers one primary fetch, possibly an OIDC fallback,
    // but never more than 2 per entry).
    expect(fetches).toBeLessThanOrEqual(MAX_AUTHORIZATION_SERVERS * 2)
    expect(fetches).toBeGreaterThanOrEqual(MAX_AUTHORIZATION_SERVERS)
  })
})

// ---------------------------------------------------------------------------
// isPrivateNetwork — SSRF protection (IP literals, hostnames, DNS resolution)
// ---------------------------------------------------------------------------

describe("isPrivateNetwork", () => {
  // IP literal checks (existing behavior, now async)
  test("detects private IPv4 addresses", async () => {
    expect(await isPrivateNetwork("10.0.0.1")).toBe(true)
    expect(await isPrivateNetwork("172.16.0.1")).toBe(true)
    expect(await isPrivateNetwork("192.168.1.1")).toBe(true)
    expect(await isPrivateNetwork("127.0.0.1")).toBe(true)
    expect(await isPrivateNetwork("169.254.169.254")).toBe(true)
    expect(await isPrivateNetwork("100.64.0.1")).toBe(true)
  })

  test("allows public IPv4 addresses", async () => {
    expect(await isPrivateNetwork("8.8.8.8")).toBe(false)
    expect(await isPrivateNetwork("1.1.1.1")).toBe(false)
    expect(await isPrivateNetwork("93.184.216.34")).toBe(false)
  })

  test("detects private IPv6 addresses", async () => {
    expect(await isPrivateNetwork("::1")).toBe(true)
    expect(await isPrivateNetwork("[::1]")).toBe(true)
    expect(await isPrivateNetwork("fc00::1")).toBe(true)
    expect(await isPrivateNetwork("fe80::1")).toBe(true)
  })

  // Known private hostname patterns
  test("blocks localhost and .localhost hostnames", async () => {
    expect(await isPrivateNetwork("localhost")).toBe(true)
    expect(await isPrivateNetwork("LOCALHOST")).toBe(true)
    expect(await isPrivateNetwork("app.localhost")).toBe(true)
    expect(await isPrivateNetwork("foo.bar.localhost")).toBe(true)
  })

  test("blocks .local (mDNS) hostnames", async () => {
    expect(await isPrivateNetwork("myhost.local")).toBe(true)
    expect(await isPrivateNetwork("printer.local")).toBe(true)
  })

  test("blocks .internal hostnames (cloud metadata)", async () => {
    expect(await isPrivateNetwork("metadata.google.internal")).toBe(true)
    expect(await isPrivateNetwork("anything.internal")).toBe(true)
  })

  // DNS resolution — localhost resolves to 127.0.0.1 on virtually all systems
  test("resolves DNS and detects private IPs (localhost)", async () => {
    // Even without the .localhost pattern check, DNS resolution of "localhost"
    // should yield 127.0.0.1 which is private. This test validates both layers.
    expect(await isPrivateNetwork("localhost")).toBe(true)
  })

  test("allows public DNS hostnames", async () => {
    // google.com resolves to public IPs
    expect(await isPrivateNetwork("google.com")).toBe(false)
  })

  test("allows unresolvable hostnames (fail-open for fetch to handle)", async () => {
    // A hostname that doesn't resolve should return false — the subsequent
    // fetch will fail with a network error, which is safe.
    expect(await isPrivateNetwork("this-domain-definitely-does-not-exist-abc123xyz.example")).toBe(false)
  })
})

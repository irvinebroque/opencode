/**
 * Tests for RFC 9728 (Protected Resource Metadata) and RFC 8414 (AS Metadata) discovery.
 *
 * Tests the well-known URL construction and metadata validation logic.
 * Network-level fetch tests use mock servers via Bun.serve.
 *
 * Test cases adapted from irvinebroque/http-rfc-utils test suite.
 */
import { describe, test, expect, afterEach } from "bun:test"
import {
  resourceMetadataUrl,
  asMetadataUrl,
  fetchResourceMetadata,
  fetchASMetadata,
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
    return `http://localhost:${s.port}`
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
    const result = await fetchResourceMetadata(`http://localhost:${s.port}`, "https://example.com")
    expect(result).toBeUndefined()
  })

  test("rejects metadata with invalid bearer_methods_supported values", async () => {
    const url = serve({
      resource: "https://example.com",
      bearer_methods_supported: ["header", "invalid_method"],
    })
    const result = await fetchResourceMetadata(url, "https://example.com")
    expect(result).toBeUndefined()
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
            JSON.stringify({ resource: `http://localhost:${resPort}` }),
            { headers: { "Content-Type": "application/json" } },
          )
        }
        // Return a redirect
        return new Response(null, {
          status: 302,
          headers: { Location: `http://localhost:${resPort}/target` },
        })
      },
    })
    resPort = s.port as number
    servers.push(s)
    const result = await fetchResourceMetadata(
      `http://localhost:${resPort}`,
      `http://localhost:${resPort}`,
    )
    // redirect: "error" causes fetch to reject → result is undefined
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
    return `http://localhost:${s.port}`
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
            issuer: `http://localhost:${port}`,
            authorization_endpoint: `http://localhost:${port}/authorize`,
            token_endpoint: `http://localhost:${port}/token`,
            response_types_supported: ["code"],
          }),
          { headers: { "Content-Type": "application/json; charset=utf-8" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://localhost:${port}`)
    expect(result).toBeDefined()
    expect(result!.issuer).toBe(`http://localhost:${port}`)
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
            issuer: `http://localhost:${port}`,
            authorization_endpoint: `http://localhost:${port}/authorize`,
            token_endpoint: `http://localhost:${port}/token`,
            response_types_supported: [],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://localhost:${port}`)
    expect(result).toBeUndefined()
  })

  test("rejects metadata where issuer does not match (RFC 8414 §3.3)", async () => {
    const issuer = serveAS({
      issuer: "http://localhost:99999",
      response_types_supported: ["code"],
      authorization_endpoint: "http://localhost:99999/authorize",
      token_endpoint: "http://localhost:99999/token",
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
            issuer: `http://localhost:${port}`,
            authorization_endpoint: `http://localhost:${port}/authorize`,
            token_endpoint: `http://localhost:${port}/token`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://localhost:${port}`)
    expect(result).toBeUndefined()
  })

  test("rejects metadata missing authorization_endpoint for authorization_code grant", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://localhost:${port}`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
            token_endpoint: `http://localhost:${port}/token`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://localhost:${port}`)
    expect(result).toBeUndefined()
  })

  test("rejects metadata missing token_endpoint (non-implicit grant)", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://localhost:${port}`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
            authorization_endpoint: `http://localhost:${port}/authorize`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://localhost:${port}`)
    expect(result).toBeUndefined()
  })

  test("accepts valid AS metadata with all required fields", async () => {
    let port = 0
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            issuer: `http://localhost:${port}`,
            authorization_endpoint: `http://localhost:${port}/authorize`,
            token_endpoint: `http://localhost:${port}/token`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
            scopes_supported: ["read", "write"],
            code_challenge_methods_supported: ["S256"],
            registration_endpoint: `http://localhost:${port}/register`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://localhost:${port}`)
    expect(result).toBeDefined()
    expect(result!.issuer).toBe(`http://localhost:${port}`)
    expect(result!.authorization_endpoint).toBe(`http://localhost:${port}/authorize`)
    expect(result!.token_endpoint).toBe(`http://localhost:${port}/token`)
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
            issuer: `http://localhost:${port}`,
            authorization_endpoint: `http://localhost:${port}/authorize`,
            token_endpoint: `http://localhost:${port}/token`,
            response_types_supported: ["code"],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://localhost:${port}`)
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
            issuer: `http://localhost:${port}`,
            authorization_endpoint: `http://localhost:${port}/authorize`,
            response_types_supported: ["token"],
            grant_types_supported: ["implicit"],
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://localhost:${port}`)
    expect(result).toBeDefined()
    expect(result!.grant_types_supported).toEqual(["implicit"])
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
              issuer: `http://localhost:${port}`,
              authorization_endpoint: `http://localhost:${port}/authorize`,
              token_endpoint: `http://localhost:${port}/token`,
              response_types_supported: ["code"],
            }),
            { headers: { "Content-Type": "application/json" } },
          )
        return new Response("Not found", { status: 404 })
      },
    })
    port = s.port as number
    servers.push(s)
    const result = await fetchASMetadata(`http://localhost:${port}`)
    expect(result).toBeDefined()
    expect(result!.issuer).toBe(`http://localhost:${port}`)
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
            issuer: `http://localhost:${asPort}`,
            authorization_endpoint: `http://localhost:${asPort}/authorize`,
            token_endpoint: `http://localhost:${asPort}/token`,
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
            resource: `http://localhost:${resPort}`,
            authorization_servers: [`http://localhost:${asPort}`],
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
      `http://localhost:${resPort}`,
      `http://localhost:${resPort}`,
    )

    expect(result.resource).toBeDefined()
    expect(result.resource!.resource).toBe(`http://localhost:${resPort}`)
    expect(result.servers).toHaveLength(1)
    expect(result.servers[0]!.issuer).toBe(`http://localhost:${asPort}`)
    expect(result.servers[0]!.authorization_endpoint).toBe(`http://localhost:${asPort}/authorize`)
  })

  test("returns empty servers when resource has no authorization_servers", async () => {
    let resPort = 0
    const res = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            resource: `http://localhost:${resPort}`,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    resPort = res.port as number
    servers.push(res)

    const { discover } = await import("../../src/auth/discovery")
    const result = await discover(
      `http://localhost:${resPort}`,
      `http://localhost:${resPort}`,
    )

    expect(result.resource).toBeDefined()
    expect(result.servers).toHaveLength(0)
  })
})

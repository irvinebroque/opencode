/**
 * Tests for the webfetch credential store.
 *
 * Covers:
 * - Token expiry detection
 * - Authorization header generation (Bearer + Basic)
 * - UTF-8 Basic auth encoding (RFC 7617 §2.1)
 * - Token refresh via RFC 6749 §6
 * - get() lookup: exact, origin, and prefix matching
 * - resolve() auto-refresh on expired tokens
 */
import { describe, test, expect, afterEach } from "bun:test"
import { expired, headers, refresh, get, set, remove, resolve } from "../../src/auth/webfetch-auth"
import type { Credential } from "../../src/auth/webfetch-auth"
import type { ASMetadata } from "../../src/auth/discovery"

// ---------------------------------------------------------------------------
// expired() — token expiry detection
// ---------------------------------------------------------------------------

describe("expired()", () => {
  test("returns false when no expires_at is set", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "test",
    }
    expect(expired(cred)).toBe(false)
  })

  test("returns false when token is not yet expired", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "test",
      expires_at: Date.now() / 1000 + 3600, // 1 hour from now
    }
    expect(expired(cred)).toBe(false)
  })

  test("returns true when token is expired", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "test",
      expires_at: Date.now() / 1000 - 60, // 1 minute ago
    }
    expect(expired(cred)).toBe(true)
  })

  test("uses 30-second buffer before actual expiry", () => {
    // Token expires in 20 seconds — within buffer, should be considered expired
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "test",
      expires_at: Date.now() / 1000 + 20,
    }
    expect(expired(cred)).toBe(true)
  })

  test("token expiring in 31+ seconds is not expired", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "test",
      expires_at: Date.now() / 1000 + 31,
    }
    expect(expired(cred)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// headers() — Authorization header generation
// ---------------------------------------------------------------------------

describe("headers()", () => {
  test("generates Bearer Authorization header", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "mytoken123",
    }
    expect(headers(cred)).toEqual({ Authorization: "Bearer mytoken123" })
  })

  test("returns empty object for bearer without access_token", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
    }
    expect(headers(cred)).toEqual({})
  })

  test("generates Basic Authorization header with ASCII credentials", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "basic",
      username: "Aladdin",
      password: "open sesame",
    }
    const result = headers(cred)
    expect(result.Authorization).toBe("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
  })

  test("generates Basic Authorization header with UTF-8 credentials (RFC 7617 §2.1)", () => {
    // RFC 7617 §2.1: the default charset is UTF-8
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "basic",
      username: "Jäsøn",
      password: "Dœ",
    }
    const result = headers(cred)
    // Verify it uses Buffer (UTF-8) not btoa (which would throw)
    const decoded = Buffer.from(result.Authorization!.replace("Basic ", ""), "base64").toString("utf-8")
    expect(decoded).toBe("Jäsøn:Dœ")
  })

  test("returns empty object for basic without username", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "basic",
      password: "test",
    }
    expect(headers(cred)).toEqual({})
  })

  test("returns empty object for basic without password", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "basic",
      username: "test",
    }
    expect(headers(cred)).toEqual({})
  })

  test("handles empty username and password for basic auth", () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "basic",
      username: "",
      password: "",
    }
    const result = headers(cred)
    const decoded = Buffer.from(result.Authorization!.replace("Basic ", ""), "base64").toString("utf-8")
    expect(decoded).toBe(":")
  })
})

// ---------------------------------------------------------------------------
// get() — credential lookup with prefix matching
// ---------------------------------------------------------------------------

describe("get() prefix matching", () => {
  const keys = [
    "https://api.example.com/v1",
    "https://api.example.com/v1/deep",
    "https://api.example.com",
  ]
  afterEach(async () => {
    for (const k of keys) await remove(k)
  })

  test("returns exact URL match over prefix match", async () => {
    const prefix: Credential = {
      resource: "https://api.example.com/v1",
      scheme: "bearer",
      access_token: "prefix-token",
    }
    const exact: Credential = {
      resource: "https://api.example.com/v1/deep",
      scheme: "bearer",
      access_token: "exact-token",
    }
    await set("https://api.example.com/v1", prefix)
    await set("https://api.example.com/v1/deep", exact)

    const result = await get("https://api.example.com/v1/deep")
    expect(result).toBeDefined()
    expect(result!.access_token).toBe("exact-token")
  })

  test("returns origin match when no exact match exists", async () => {
    const origin: Credential = {
      resource: "https://api.example.com",
      scheme: "bearer",
      access_token: "origin-token",
    }
    await set("https://api.example.com", origin)

    const result = await get("https://api.example.com/other/path")
    expect(result).toBeDefined()
    expect(result!.access_token).toBe("origin-token")
  })

  test("returns longest prefix match", async () => {
    const short: Credential = {
      resource: "https://api.example.com/v1",
      scheme: "bearer",
      access_token: "short-prefix",
    }
    const long: Credential = {
      resource: "https://api.example.com/v1/deep",
      scheme: "bearer",
      access_token: "long-prefix",
    }
    await set("https://api.example.com/v1", short)
    await set("https://api.example.com/v1/deep", long)

    const result = await get("https://api.example.com/v1/deep/nested")
    expect(result).toBeDefined()
    expect(result!.access_token).toBe("long-prefix")
  })

  test("returns undefined when no match exists", async () => {
    const result = await get("https://nomatch.example.com/resource")
    expect(result).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// resolve() — lookup + auto-refresh for expired tokens
// ---------------------------------------------------------------------------

describe("resolve()", () => {
  const servers: ReturnType<typeof Bun.serve>[] = []
  const keys = ["https://resolve-test.example.com"]
  afterEach(async () => {
    for (const s of servers) s.stop()
    servers.length = 0
    for (const k of keys) await remove(k)
  })

  test("returns headers for valid non-expired credential", async () => {
    const cred: Credential = {
      resource: "https://resolve-test.example.com",
      scheme: "bearer",
      access_token: "valid-token",
      expires_at: Date.now() / 1000 + 3600, // 1 hour from now
    }
    await set("https://resolve-test.example.com", cred)

    const result = await resolve("https://resolve-test.example.com")
    expect(result).toEqual({ Authorization: "Bearer valid-token" })
  })

  test("returns empty headers for expired credential without refresh_token", async () => {
    const cred: Credential = {
      resource: "https://resolve-test.example.com",
      scheme: "bearer",
      access_token: "expired-token",
      expires_at: Date.now() / 1000 - 60, // expired 1 minute ago
    }
    await set("https://resolve-test.example.com", cred)

    const result = await resolve("https://resolve-test.example.com")
    expect(result).toEqual({})
  })

  test("returns empty headers when no credential exists", async () => {
    const result = await resolve("https://no-such-credential.example.com")
    expect(result).toEqual({})
  })
})

// ---------------------------------------------------------------------------
// refresh() — token refresh via RFC 6749 §6
// ---------------------------------------------------------------------------

describe("refresh() (RFC 6749 §6)", () => {
  const servers: ReturnType<typeof Bun.serve>[] = []
  afterEach(() => {
    for (const s of servers) s.stop()
    servers.length = 0
  })

  test("returns undefined without refresh_token", async () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "expired",
    }
    const meta: ASMetadata = {
      issuer: "https://as.example.com",
      token_endpoint: "https://as.example.com/token",
      response_types_supported: ["code"],
    }
    const result = await refresh(cred, meta)
    expect(result).toBeUndefined()
  })

  test("returns undefined without token_endpoint", async () => {
    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "expired",
      refresh_token: "refresh-me",
    }
    const meta: ASMetadata = {
      issuer: "https://as.example.com",
      response_types_supported: ["code"],
    }
    const result = await refresh(cred, meta)
    expect(result).toBeUndefined()
  })

  test("refreshes token successfully", async () => {
    const s = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = new URLSearchParams(await req.text())
        // Verify RFC 6749 §6 request format
        expect(body.get("grant_type")).toBe("refresh_token")
        expect(body.get("refresh_token")).toBe("old-refresh-token")
        expect(body.get("client_id")).toBe("my-client")

        return new Response(
          JSON.stringify({
            access_token: "new-access-token",
            refresh_token: "new-refresh-token",
            expires_in: 3600,
            scope: "read write",
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    servers.push(s)

    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "old-access-token",
      refresh_token: "old-refresh-token",
      oauth_client_id: "my-client",
    }
    const meta: ASMetadata = {
      issuer: "https://as.example.com",
      token_endpoint: `http://localhost:${s.port as number}/token`,
      response_types_supported: ["code"],
    }
    const result = await refresh(cred, meta)
    expect(result).toBeDefined()
    expect(result!.access_token).toBe("new-access-token")
    expect(result!.refresh_token).toBe("new-refresh-token")
    expect(result!.scope).toBe("read write")
    expect(result!.expires_at).toBeDefined()
  })

  test("preserves old refresh_token when new one not provided", async () => {
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({
            access_token: "new-access-token",
            expires_in: 1800,
          }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    servers.push(s)

    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "old",
      refresh_token: "keep-this",
    }
    const meta: ASMetadata = {
      issuer: "https://as.example.com",
      token_endpoint: `http://localhost:${s.port as number}/token`,
      response_types_supported: ["code"],
    }
    const result = await refresh(cred, meta)
    expect(result).toBeDefined()
    expect(result!.refresh_token).toBe("keep-this")
  })

  test("returns undefined on refresh failure (HTTP 400)", async () => {
    const s = Bun.serve({
      port: 0,
      fetch() {
        return new Response(
          JSON.stringify({ error: "invalid_grant" }),
          { status: 400 },
        )
      },
    })
    servers.push(s)

    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "old",
      refresh_token: "bad-token",
    }
    const meta: ASMetadata = {
      issuer: "https://as.example.com",
      token_endpoint: `http://localhost:${s.port as number}/token`,
      response_types_supported: ["code"],
    }
    const result = await refresh(cred, meta)
    expect(result).toBeUndefined()
  })

  test("includes client_secret when available", async () => {
    const s = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = new URLSearchParams(await req.text())
        expect(body.get("client_id")).toBe("my-client")
        expect(body.get("client_secret")).toBe("my-secret")

        return new Response(
          JSON.stringify({ access_token: "new-token" }),
          { headers: { "Content-Type": "application/json" } },
        )
      },
    })
    servers.push(s)

    const cred: Credential = {
      resource: "https://example.com",
      scheme: "bearer",
      access_token: "old",
      refresh_token: "refresh-me",
      oauth_client_id: "my-client",
      oauth_client_secret: "my-secret",
    }
    const meta: ASMetadata = {
      issuer: "https://as.example.com",
      token_endpoint: `http://localhost:${s.port as number}/token`,
      response_types_supported: ["code"],
    }
    const result = await refresh(cred, meta)
    expect(result).toBeDefined()
    expect(result!.access_token).toBe("new-token")
  })
})

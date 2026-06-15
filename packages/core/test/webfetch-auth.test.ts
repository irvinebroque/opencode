import { describe, expect, test } from "bun:test"
import { WebFetchAuth } from "@opencode-ai/core/tool/webfetch-auth"

describe("WebFetchAuth", () => {
  test("parses quoted WWW-Authenticate parameters without splitting on commas", () => {
    expect(
      WebFetchAuth.parseWWWAuthenticate(
        'Bearer realm="example", scope="read,write", resource_metadata="https://resource.example/.well-known/oauth-protected-resource"',
      ),
    ).toEqual([
      {
        scheme: "Bearer",
        params: {
          realm: "example",
          scope: "read,write",
          resource_metadata: "https://resource.example/.well-known/oauth-protected-resource",
        },
      },
    ])
  })

  test("rejects duplicate auth params in one challenge", () => {
    expect(WebFetchAuth.parseWWWAuthenticate('Bearer realm="one", realm="two"')).toEqual([])
  })

  test("constructs RFC 9728 and RFC 8414 well-known URLs", () => {
    expect(WebFetchAuth.resourceMetadataUrl("https://resource.example.com/r1?q=1")).toBe(
      "https://resource.example.com/.well-known/oauth-protected-resource/r1?q=1",
    )
    expect(WebFetchAuth.asMetadataUrl("https://issuer.example.com/tenant/")).toBe(
      "https://issuer.example.com/.well-known/oauth-authorization-server/tenant",
    )
  })

  test("generates S256 PKCE values with the RFC 7636 verifier shape", async () => {
    const result = await WebFetchAuth.pkce()
    expect(result.verifier).toMatch(/^[A-Za-z0-9\-._~]{43,128}$/)
    expect(result.challenge).toMatch(/^[A-Za-z0-9\-_]+$/)
    expect(result.challenge).not.toContain("=")
  })
})

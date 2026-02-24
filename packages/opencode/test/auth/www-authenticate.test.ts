/**
 * Tests for WWW-Authenticate header parser.
 *
 * Covers RFC 9110 §11.6.1, RFC 7235 §2.1, and RFC 9728 §5.1.
 * Test cases adapted from the audited irvinebroque/http-rfc-utils test suite.
 */
import { describe, test, expect } from "bun:test"
import { parse, all, resourceMetadataUrl } from "../../src/auth/www-authenticate"

describe("WWW-Authenticate parser (RFC 9110 §11.6.1)", () => {
  // -----------------------------------------------------------------------
  // Basic challenge parsing
  // -----------------------------------------------------------------------

  test("parses a single Bearer challenge with params", () => {
    const result = parse('Bearer realm="example", error="invalid_token"')
    expect(result).toHaveLength(1)
    expect(result[0]!.scheme).toBe("Bearer")
    expect(result[0]!.params["realm"]).toBe("example")
    expect(result[0]!.params["error"]).toBe("invalid_token")
  })

  test("parses a single Basic challenge with realm", () => {
    const result = parse('Basic realm="Restricted Area"')
    expect(result).toHaveLength(1)
    expect(result[0]!.scheme).toBe("Basic")
    expect(result[0]!.params["realm"]).toBe("Restricted Area")
  })

  test("parses bare scheme with no params", () => {
    const result = parse("Negotiate")
    expect(result).toHaveLength(1)
    expect(result[0]!.scheme).toBe("Negotiate")
    expect(Object.keys(result[0]!.params)).toHaveLength(0)
  })

  // -----------------------------------------------------------------------
  // Multiple challenges — RFC 7235 §2.1
  // -----------------------------------------------------------------------

  test("parses multiple challenges separated by comma", () => {
    const result = parse('Basic realm="docs", Bearer realm="api"')
    expect(result).toHaveLength(2)
    expect(result[0]!.scheme).toBe("Basic")
    expect(result[0]!.params["realm"]).toBe("docs")
    expect(result[1]!.scheme).toBe("Bearer")
    expect(result[1]!.params["realm"]).toBe("api")
  })

  test("parses multiple challenges with multiple params each", () => {
    const result = parse(
      'Bearer realm="example", error="invalid_token", error_description="expired", ' +
        'Basic realm="test"',
    )
    expect(result).toHaveLength(2)
    expect(result[0]!.scheme).toBe("Bearer")
    expect(result[0]!.params["realm"]).toBe("example")
    expect(result[0]!.params["error"]).toBe("invalid_token")
    expect(result[0]!.params["error_description"]).toBe("expired")
    expect(result[1]!.scheme).toBe("Basic")
    expect(result[1]!.params["realm"]).toBe("test")
  })

  // -----------------------------------------------------------------------
  // Quoted strings — RFC 9110 §5.6.4
  // -----------------------------------------------------------------------

  test("handles quoted strings with escaped characters", () => {
    const result = parse('Bearer realm="hello \\"world\\""')
    expect(result).toHaveLength(1)
    expect(result[0]!.params["realm"]).toBe('hello "world"')
  })

  test("handles quoted strings with commas inside", () => {
    const result = parse('Basic realm="hello, world"')
    expect(result).toHaveLength(1)
    expect(result[0]!.scheme).toBe("Basic")
    expect(result[0]!.params["realm"]).toBe("hello, world")
  })

  test("handles quoted strings with backslash escaping", () => {
    const result = parse('Bearer realm="path\\\\to\\\\file"')
    expect(result).toHaveLength(1)
    expect(result[0]!.params["realm"]).toBe("path\\to\\file")
  })

  // -----------------------------------------------------------------------
  // Token68 — RFC 7235 §2.1
  // -----------------------------------------------------------------------

  test("parses token68 value", () => {
    const result = parse("Negotiate dGVzdA==")
    expect(result).toHaveLength(1)
    expect(result[0]!.scheme).toBe("Negotiate")
    expect(result[0]!.token68).toBe("dGVzdA==")
  })

  test("parses token68 without padding", () => {
    const result = parse("Bearer mF_9.B5f-4.1JqM")
    expect(result).toHaveLength(1)
    expect(result[0]!.token68).toBe("mF_9.B5f-4.1JqM")
  })

  // -----------------------------------------------------------------------
  // Param name case normalization — RFC 9110 §5.6.2
  // -----------------------------------------------------------------------

  test("lowercases param names", () => {
    const result = parse('Bearer Realm="test", Error="invalid_token"')
    expect(result).toHaveLength(1)
    expect(result[0]!.params["realm"]).toBe("test")
    expect(result[0]!.params["error"]).toBe("invalid_token")
  })

  // -----------------------------------------------------------------------
  // Duplicate param detection — RFC 9110 §11.2
  // -----------------------------------------------------------------------

  test("rejects challenge with duplicate param names (case-insensitive)", () => {
    const result = parse('Basic realm="one", realm="two"')
    // Duplicate params — challenge should be rejected
    expect(result).toHaveLength(0)
  })

  test("rejects duplicate param names with different casing", () => {
    const result = parse('Basic Realm="one", realm="two"')
    expect(result).toHaveLength(0)
  })

  // -----------------------------------------------------------------------
  // Whitespace handling — RFC 9110 §5.6.3 (OWS)
  // -----------------------------------------------------------------------

  test("handles optional whitespace around = and values", () => {
    const result = parse('Bearer realm = "example" , error = "invalid_token"')
    expect(result).toHaveLength(1)
    expect(result[0]!.params["realm"]).toBe("example")
    expect(result[0]!.params["error"]).toBe("invalid_token")
  })

  test("handles tab characters as OWS", () => {
    const result = parse("Bearer\trealm=\"test\"")
    expect(result).toHaveLength(1)
    expect(result[0]!.params["realm"]).toBe("test")
  })

  // -----------------------------------------------------------------------
  // Edge cases
  // -----------------------------------------------------------------------

  test("handles empty input", () => {
    expect(parse("")).toHaveLength(0)
  })

  test("handles whitespace-only input", () => {
    expect(parse("   ")).toHaveLength(0)
  })

  test("handles leading/trailing commas", () => {
    const result = parse(',Bearer realm="test",')
    expect(result).toHaveLength(1)
    expect(result[0]!.scheme).toBe("Bearer")
  })

  test("handles multiple consecutive commas", () => {
    const result = parse('Bearer realm="a",,, Basic realm="b"')
    expect(result).toHaveLength(2)
  })

  test("handles unquoted param values (tokens)", () => {
    const result = parse("Bearer realm=example, error=invalid_token")
    expect(result).toHaveLength(1)
    expect(result[0]!.params["realm"]).toBe("example")
    expect(result[0]!.params["error"]).toBe("invalid_token")
  })

  // -----------------------------------------------------------------------
  // RFC 9728 §5.1: resource_metadata in Bearer challenge
  // -----------------------------------------------------------------------

  test("parses resource_metadata from Bearer challenge", () => {
    const result = parse(
      'Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"',
    )
    expect(result).toHaveLength(1)
    expect(result[0]!.params["resource_metadata"]).toBe(
      "https://resource.example.com/.well-known/oauth-protected-resource",
    )
  })
})

describe("all() — extract challenges from Response", () => {
  test("extracts challenges from WWW-Authenticate header", () => {
    const response = new Response("", {
      status: 401,
      headers: { "WWW-Authenticate": 'Bearer realm="test"' },
    })
    const challenges = all(response)
    expect(challenges).toHaveLength(1)
    expect(challenges[0]!.scheme).toBe("Bearer")
  })

  test("handles multiple WWW-Authenticate headers", () => {
    const response = new Response("", {
      status: 401,
      headers: [
        ["WWW-Authenticate", 'Bearer realm="api"'],
        ["WWW-Authenticate", 'Basic realm="docs"'],
      ],
    })
    const challenges = all(response)
    expect(challenges).toHaveLength(2)
  })

  test("returns empty array for response without WWW-Authenticate", () => {
    const response = new Response("", { status: 200 })
    expect(all(response)).toHaveLength(0)
  })
})

describe("resourceMetadataUrl() — RFC 9728 §5.1", () => {
  test("extracts resource_metadata from Bearer challenge", () => {
    const challenges = parse(
      'Bearer realm="api", resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource"',
    )
    expect(resourceMetadataUrl(challenges)).toBe(
      "https://rs.example.com/.well-known/oauth-protected-resource",
    )
  })

  test("returns undefined when no Bearer challenge has resource_metadata", () => {
    const challenges = parse('Basic realm="test"')
    expect(resourceMetadataUrl(challenges)).toBeUndefined()
  })

  test("is case-insensitive on scheme name", () => {
    const challenges = parse(
      'bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"',
    )
    expect(resourceMetadataUrl(challenges)).toBe(
      "https://example.com/.well-known/oauth-protected-resource",
    )
  })
})

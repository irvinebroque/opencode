import { describe, test, expect, afterEach } from "bun:test"
import { handleAuthChallenge } from "../../src/auth/orchestrate"
import type { CredentialStore, Credential } from "../../src/auth/webfetch-auth"

class MemoryStore implements CredentialStore {
  #data: Record<string, Credential> = {}

  async get(resource: string) {
    return this.#data[resource]
  }

  async set(resource: string, cred: Credential) {
    this.#data[resource] = cred
  }

  async remove(resource: string) {
    delete this.#data[resource]
  }

  async all() {
    return this.#data
  }
}

function json(body: unknown, init?: ResponseInit) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  })
}

describe("handleAuthChallenge()", () => {
  const servers: ReturnType<typeof Bun.serve>[] = []

  afterEach(() => {
    for (const s of servers) s.stop()
    servers.length = 0
  })

  test("tries later discovered authorization servers when the first one fails", async () => {
    let resource: ReturnType<typeof Bun.serve>
    let first: ReturnType<typeof Bun.serve>
    let second: ReturnType<typeof Bun.serve>
    let firstTokens = 0
    let secondTokens = 0

    first = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url)
        if (url.pathname === "/.well-known/oauth-authorization-server") {
          return json({
            issuer: `http://127.0.0.1:${first.port as number}`,
            authorization_endpoint: `http://127.0.0.1:${first.port as number}/authorize`,
            token_endpoint: `http://127.0.0.1:${first.port as number}/token`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
          })
        }
        if (url.pathname === "/token") {
          firstTokens++
          return json({ error: "invalid_grant" }, { status: 400 })
        }
        return new Response("Not found", { status: 404 })
      },
    })
    second = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url)
        if (url.pathname === "/.well-known/oauth-authorization-server") {
          return json({
            issuer: `http://127.0.0.1:${second.port as number}`,
            authorization_endpoint: `http://127.0.0.1:${second.port as number}/authorize`,
            token_endpoint: `http://127.0.0.1:${second.port as number}/token`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
          })
        }
        if (url.pathname === "/token") {
          secondTokens++
          return json({ access_token: "second-token", token_type: "Bearer" })
        }
        return new Response("Not found", { status: 404 })
      },
    })
    resource = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url)
        const base = `http://127.0.0.1:${resource.port as number}`
        if (url.pathname === "/.well-known/oauth-protected-resource/protected") {
          return json({
            resource: `${base}/protected`,
            authorization_servers: [
              `http://127.0.0.1:${first.port as number}`,
              `http://127.0.0.1:${second.port as number}`,
            ],
          })
        }
        if (url.pathname === "/protected") {
          if (req.headers.get("authorization") === "Bearer second-token") {
            return new Response("ok")
          }
          return new Response("unauthorized", { status: 401 })
        }
        return new Response("Not found", { status: 404 })
      },
    })
    servers.push(first, second, resource)

    const url = `http://127.0.0.1:${resource.port as number}/protected`
    const response = new Response("unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": `Bearer resource_metadata="http://127.0.0.1:${resource.port as number}/.well-known/oauth-protected-resource/protected"`,
      },
    })

    const result = await handleAuthChallenge({
      response,
      url,
      baseHeaders: {},
      signal: new AbortController().signal,
      store: new MemoryStore(),
      interaction: {
        async askConsent() {},
        async openUrl() {},
        async showDeviceCode() {},
      },
      callbackServer: {
        async start() {
          return { redirectUri: "http://127.0.0.1:19877/oauth/callback" }
        },
        async waitForCode() {
          return "test-code"
        },
        async stop() {},
      },
      client: { name: "OpenCode", clientId: "test-client" },
    })

    expect(result).toBeDefined()
    expect(await result!.text()).toBe("ok")
    expect(firstTokens).toBe(1)
    expect(secondTokens).toBe(1)
  })
})

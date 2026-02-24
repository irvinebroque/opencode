import { describe, expect, mock, test } from "bun:test"
import path from "path"
import { Instance } from "../../src/project/instance"

const projectRoot = path.join(import.meta.dir, "../..")

const ctx = {
  sessionID: "test",
  messageID: "message",
  callID: "",
  agent: "build",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => {},
  ask: async () => {},
}

const seen: { status?: number; calls: number } = { calls: 0 }
let mode: "ok" | "none" | "throw" = "ok"

mock.module("../../src/auth/orchestrate", () => ({
  handleAuthChallenge: async (options: { response: Response }) => {
    seen.calls++
    seen.status = options.response.status
    if (mode === "none") return undefined
    if (mode === "throw") throw new Error("auth failed")
    return new Response("authed", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    })
  },
}))

const { WebFetchTool } = await import("../../src/tool/webfetch")

async function withFetch(
  mockFetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>,
  fn: () => Promise<void>,
) {
  const originalFetch = globalThis.fetch
  globalThis.fetch = mockFetch as unknown as typeof fetch
  try {
    await fn()
  } finally {
    globalThis.fetch = originalFetch
  }
}

describe("tool.webfetch redirect auth", () => {
  test("triggers auth flow on redirect challenge", async () => {
    mode = "ok"
    seen.calls = 0
    seen.status = undefined
    let calls = 0

    await withFetch(
      async (_input, init) => {
        calls++
        if ((init?.redirect ?? "follow") === "manual") {
          return new Response("", {
            status: 302,
            headers: {
              location: "https://example.com/login",
              "www-authenticate":
                'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"',
            },
          })
        }
        return new Response("unexpected", { status: 500 })
      },
      async () => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await WebFetchTool.init()
            const result = await webfetch.execute({ url: "https://example.com/redirect", format: "text" }, ctx)
            expect(result.output).toBe("authed")
            expect(seen.calls).toBe(1)
            expect(seen.status).toBe(302)
            expect(calls).toBe(1)
          },
        })
      },
    )
  })

  test("falls back to normal redirects when auth challenge is not handled", async () => {
    mode = "none"
    seen.calls = 0
    seen.status = undefined
    let calls = 0

    await withFetch(
      async (_input, init) => {
        calls++
        if ((init?.redirect ?? "follow") === "manual") {
          return new Response("", {
            status: 302,
            headers: {
              location: "https://example.com/login",
              "www-authenticate":
                'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"',
            },
          })
        }
        return new Response("login page", {
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
        })
      },
      async () => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await WebFetchTool.init()
            const result = await webfetch.execute({ url: "https://example.com/redirect", format: "text" }, ctx)
            expect(result.output).toBe("login page")
            expect(seen.calls).toBe(1)
            expect(seen.status).toBe(302)
            expect(calls).toBe(2)
          },
        })
      },
    )
  })

  test("does not trigger auth flow for redirect without challenge", async () => {
    mode = "ok"
    seen.calls = 0

    await withFetch(
      async (_input, init) => {
        if ((init?.redirect ?? "follow") === "manual") {
          return new Response("", {
            status: 302,
            headers: { location: "https://example.com/next" },
          })
        }
        return new Response("redirect target", {
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
        })
      },
      async () => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await WebFetchTool.init()
            const result = await webfetch.execute({ url: "https://example.com/redirect", format: "text" }, ctx)
            expect(result.output).toBe("redirect target")
            expect(seen.calls).toBe(0)
          },
        })
      },
    )
  })

  test("throws auth error when auth flow throws on redirect challenge", async () => {
    mode = "throw"
    seen.calls = 0
    seen.status = undefined

    await withFetch(
      async (_input, init) => {
        if ((init?.redirect ?? "follow") === "manual") {
          return new Response("", {
            status: 302,
            headers: {
              location: "https://example.com/login",
              "www-authenticate":
                'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"',
            },
          })
        }
        return new Response("login page", {
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
        })
      },
      async () => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await WebFetchTool.init()
            await expect(webfetch.execute({ url: "https://example.com/redirect", format: "text" }, ctx)).rejects.toThrow(
              "auth failed",
            )
            expect(seen.calls).toBe(1)
            expect(seen.status).toBe(302)
          },
        })
      },
    )
  })
})

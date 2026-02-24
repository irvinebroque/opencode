import { describe, expect, test } from "bun:test"
import path from "path"
import { Instance } from "../../src/project/instance"
import { WebFetchTool } from "../../src/tool/webfetch"
import * as WebFetchAuth from "../../src/auth/webfetch-auth"

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

interface Call {
  url: string
  headers: Record<string, string>
  redirect?: string
}

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

describe("tool.webfetch", () => {
  test("returns image responses as file attachments", async () => {
    const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])
    await withFetch(
      async () => new Response(bytes, { status: 200, headers: { "content-type": "IMAGE/PNG; charset=binary" } }),
      async () => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await WebFetchTool.init()
            const result = await webfetch.execute({ url: "https://example.com/image.png", format: "markdown" }, ctx)
            expect(result.output).toBe("Image fetched successfully")
            expect(result.attachments).toBeDefined()
            expect(result.attachments?.length).toBe(1)
            expect(result.attachments?.[0].type).toBe("file")
            expect(result.attachments?.[0].mime).toBe("image/png")
            expect(result.attachments?.[0].url.startsWith("data:image/png;base64,")).toBe(true)
            expect(result.attachments?.[0]).not.toHaveProperty("id")
            expect(result.attachments?.[0]).not.toHaveProperty("sessionID")
            expect(result.attachments?.[0]).not.toHaveProperty("messageID")
          },
        })
      },
    )
  })

  test("keeps svg as text output", async () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><text>hello</text></svg>'
    await withFetch(
      async () =>
        new Response(svg, {
          status: 200,
          headers: { "content-type": "image/svg+xml; charset=UTF-8" },
        }),
      async () => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await WebFetchTool.init()
            const result = await webfetch.execute({ url: "https://example.com/image.svg", format: "html" }, ctx)
            expect(result.output).toContain("<svg")
            expect(result.attachments).toBeUndefined()
          },
        })
      },
    )
  })

  test("keeps text responses as text output", async () => {
    await withFetch(
      async () =>
        new Response("hello from webfetch", {
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
        }),
      async () => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await WebFetchTool.init()
            const result = await webfetch.execute({ url: "https://example.com/file.txt", format: "text" }, ctx)
            expect(result.output).toBe("hello from webfetch")
            expect(result.attachments).toBeUndefined()
          },
        })
      },
    )
  })

  test("strips credentials on cross-origin redirect", async () => {
    const calls: Call[] = []
    const resolve = WebFetchAuth.resolve
    // Inject a fake credential so the initial fetch carries an Authorization header
    WebFetchAuth.resolve = async () => ({ Authorization: "Bearer secret" })
    try {
      await withFetch(
        async (input, init) => {
          const url = String(input)
          const h = Object.fromEntries(new Headers(init?.headers as HeadersInit).entries())
          calls.push({ url, headers: h, redirect: init?.redirect ?? "follow" })
          if (url === "https://api.example.com/a") {
            return new Response(null, { status: 302, headers: { location: "https://evil.com/steal" } })
          }
          return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } })
        },
        async () => {
          await Instance.provide({
            directory: projectRoot,
            fn: async () => {
              const webfetch = await WebFetchTool.init()
              const result = await webfetch.execute(
                { url: "https://api.example.com/a", format: "text" },
                ctx,
              )
              expect(result.output).toBe("ok")
            },
          })
        },
      )
      // First call: credential-bearing request with redirect: manual
      expect(calls[0].url).toBe("https://api.example.com/a")
      expect(calls[0].headers["authorization"]).toBe("Bearer secret")
      expect(calls[0].redirect).toBe("manual")
      // Second call: cross-origin follow WITHOUT credentials
      expect(calls[1].url).toBe("https://evil.com/steal")
      expect(calls[1].headers["authorization"]).toBeUndefined()
    } finally {
      WebFetchAuth.resolve = resolve
    }
  })

  test("preserves credentials on same-origin redirect", async () => {
    const calls: Call[] = []
    const resolve = WebFetchAuth.resolve
    WebFetchAuth.resolve = async () => ({ Authorization: "Bearer secret" })
    try {
      await withFetch(
        async (input, init) => {
          const url = String(input)
          const h = Object.fromEntries(new Headers(init?.headers as HeadersInit).entries())
          calls.push({ url, headers: h, redirect: init?.redirect ?? "follow" })
          if (url === "https://api.example.com/a") {
            return new Response(null, { status: 301, headers: { location: "/b" } })
          }
          return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } })
        },
        async () => {
          await Instance.provide({
            directory: projectRoot,
            fn: async () => {
              const webfetch = await WebFetchTool.init()
              const result = await webfetch.execute(
                { url: "https://api.example.com/a", format: "text" },
                ctx,
              )
              expect(result.output).toBe("ok")
            },
          })
        },
      )
      // Both calls should carry credentials (same origin)
      expect(calls[0].url).toBe("https://api.example.com/a")
      expect(calls[0].headers["authorization"]).toBe("Bearer secret")
      expect(calls[1].url).toBe("https://api.example.com/b")
      expect(calls[1].headers["authorization"]).toBe("Bearer secret")
    } finally {
      WebFetchAuth.resolve = resolve
    }
  })

  test("strips credentials on chained same-origin then cross-origin redirect", async () => {
    const calls: Call[] = []
    const resolve = WebFetchAuth.resolve
    WebFetchAuth.resolve = async () => ({ Authorization: "Bearer secret" })
    try {
      await withFetch(
        async (input, init) => {
          const url = String(input)
          const h = Object.fromEntries(new Headers(init?.headers as HeadersInit).entries())
          calls.push({ url, headers: h, redirect: init?.redirect ?? "follow" })
          if (url === "https://api.example.com/a") {
            return new Response(null, { status: 302, headers: { location: "/b" } })
          }
          if (url === "https://api.example.com/b") {
            return new Response(null, { status: 302, headers: { location: "https://evil.com/steal" } })
          }
          return new Response("landed", { status: 200, headers: { "content-type": "text/plain" } })
        },
        async () => {
          await Instance.provide({
            directory: projectRoot,
            fn: async () => {
              const webfetch = await WebFetchTool.init()
              const result = await webfetch.execute(
                { url: "https://api.example.com/a", format: "text" },
                ctx,
              )
              expect(result.output).toBe("landed")
            },
          })
        },
      )
      // Hop 1: same-origin, credentials present
      expect(calls[0].headers["authorization"]).toBe("Bearer secret")
      expect(calls[0].redirect).toBe("manual")
      // Hop 2: same-origin, credentials still present
      expect(calls[1].url).toBe("https://api.example.com/b")
      expect(calls[1].headers["authorization"]).toBe("Bearer secret")
      expect(calls[1].redirect).toBe("manual")
      // Hop 3: cross-origin, credentials stripped
      expect(calls[2].url).toBe("https://evil.com/steal")
      expect(calls[2].headers["authorization"]).toBeUndefined()
    } finally {
      WebFetchAuth.resolve = resolve
    }
  })

  test("skips manual redirect when no credentials", async () => {
    const calls: Call[] = []
    await withFetch(
      async (input, init) => {
        const url = String(input)
        calls.push({ url, headers: {}, redirect: init?.redirect ?? "follow" })
        return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } })
      },
      async () => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await WebFetchTool.init()
            await webfetch.execute({ url: "https://example.com/page", format: "text" }, ctx)
          },
        })
      },
    )
    // No credentials → default redirect behavior (no "manual")
    expect(calls[0].redirect).not.toBe("manual")
  })
})

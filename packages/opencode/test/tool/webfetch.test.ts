import { describe, expect, test } from "bun:test"
import path from "path"
import { Effect } from "effect"
import { FetchHttpClient } from "effect/unstable/http"
import * as WebFetchAuth from "../../src/auth/webfetch-auth"
import { Instance } from "../../src/project/instance"
import { SessionID, MessageID } from "../../src/session/schema"
import { WebFetchTool } from "../../src/tool/webfetch"

const projectRoot = path.join(import.meta.dir, "../..")

const ctx = {
  sessionID: SessionID.make("ses_test"),
  messageID: MessageID.make("message"),
  callID: "",
  agent: "build",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  ask: () => Effect.void,
}

interface Call {
  url: string
  headers: Record<string, string>
  redirect?: string
}

async function withFetch(fetch: (req: Request) => Response | Promise<Response>, fn: (url: URL) => Promise<void>) {
  using server = Bun.serve({ port: 0, fetch })
  await fn(server.url)
}

async function withMockFetch(
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

function initTool() {
  return WebFetchTool.pipe(
    Effect.flatMap((info) => info.init()),
    Effect.provide(FetchHttpClient.layer),
    Effect.runPromise,
  )
}

describe("tool.webfetch", () => {
  test("returns image responses as file attachments", async () => {
    const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])
    await withFetch(
      () => new Response(bytes, { status: 200, headers: { "content-type": "IMAGE/PNG; charset=binary" } }),
      async (url) => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await initTool()
            const result = await Effect.runPromise(
              webfetch.execute({ url: new URL("/image.png", url).toString(), format: "markdown" }, ctx),
            )
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
      () =>
        new Response(svg, {
          status: 200,
          headers: { "content-type": "image/svg+xml; charset=UTF-8" },
        }),
      async (url) => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await initTool()
            const result = await Effect.runPromise(
              webfetch.execute({ url: new URL("/image.svg", url).toString(), format: "html" }, ctx),
            )
            expect(result.output).toContain("<svg")
            expect(result.attachments).toBeUndefined()
          },
        })
      },
    )
  })

  test("keeps text responses as text output", async () => {
    await withFetch(
      () =>
        new Response("hello from webfetch", {
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
        }),
      async (url) => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await initTool()
            const result = await Effect.runPromise(
              webfetch.execute({ url: new URL("/file.txt", url).toString(), format: "text" }, ctx),
            )
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
    WebFetchAuth.resolve = async () => ({ Authorization: "Bearer secret" })
    try {
      await withMockFetch(
        async (input, init) => {
          const url = String(input)
          const headers = Object.fromEntries(new Headers(init?.headers as HeadersInit).entries())
          calls.push({ url, headers, redirect: init?.redirect ?? "follow" })
          if (url === "https://api.example.com/a") {
            return new Response(null, { status: 302, headers: { location: "https://evil.com/steal" } })
          }
          return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } })
        },
        async () => {
          await Instance.provide({
            directory: projectRoot,
            fn: async () => {
              const webfetch = await initTool()
              const result = await Effect.runPromise(webfetch.execute({ url: "https://api.example.com/a", format: "text" }, ctx))
              expect(result.output).toBe("ok")
            },
          })
        },
      )
      expect(calls[0].url).toBe("https://api.example.com/a")
      expect(calls[0].headers["authorization"]).toBe("Bearer secret")
      expect(calls[0].redirect).toBe("manual")
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
      await withMockFetch(
        async (input, init) => {
          const url = String(input)
          const headers = Object.fromEntries(new Headers(init?.headers as HeadersInit).entries())
          calls.push({ url, headers, redirect: init?.redirect ?? "follow" })
          if (url === "https://api.example.com/a") {
            return new Response(null, { status: 301, headers: { location: "/b" } })
          }
          return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } })
        },
        async () => {
          await Instance.provide({
            directory: projectRoot,
            fn: async () => {
              const webfetch = await initTool()
              const result = await Effect.runPromise(webfetch.execute({ url: "https://api.example.com/a", format: "text" }, ctx))
              expect(result.output).toBe("ok")
            },
          })
        },
      )
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
      await withMockFetch(
        async (input, init) => {
          const url = String(input)
          const headers = Object.fromEntries(new Headers(init?.headers as HeadersInit).entries())
          calls.push({ url, headers, redirect: init?.redirect ?? "follow" })
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
              const webfetch = await initTool()
              const result = await Effect.runPromise(webfetch.execute({ url: "https://api.example.com/a", format: "text" }, ctx))
              expect(result.output).toBe("landed")
            },
          })
        },
      )
      expect(calls[0].headers["authorization"]).toBe("Bearer secret")
      expect(calls[0].redirect).toBe("manual")
      expect(calls[1].url).toBe("https://api.example.com/b")
      expect(calls[1].headers["authorization"]).toBe("Bearer secret")
      expect(calls[1].redirect).toBe("manual")
      expect(calls[2].url).toBe("https://evil.com/steal")
      expect(calls[2].headers["authorization"]).toBeUndefined()
    } finally {
      WebFetchAuth.resolve = resolve
    }
  })

  test("skips manual redirect when no credentials", async () => {
    const calls: Call[] = []
    await withMockFetch(
      async (input, init) => {
        calls.push({ url: String(input), headers: {}, redirect: init?.redirect ?? "follow" })
        return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } })
      },
      async () => {
        await Instance.provide({
          directory: projectRoot,
          fn: async () => {
            const webfetch = await initTool()
            await Effect.runPromise(webfetch.execute({ url: "https://example.com/page", format: "text" }, ctx))
          },
        })
      },
    )
    expect(calls[0].redirect).not.toBe("manual")
  })
})

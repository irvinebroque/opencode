import { afterAll, describe, expect, test } from "bun:test"
import { tmpdir } from "node:os"
import path from "node:path"
import fs from "node:fs/promises"
import { Effect, Layer, Schema } from "effect"
import { FetchHttpClient, HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { FSUtil } from "@opencode-ai/core/fs-util"
import { Global } from "@opencode-ai/core/global"
import { PermissionV2 } from "@opencode-ai/core/permission"
import { SessionV2 } from "@opencode-ai/core/session"
import { ToolRegistry } from "@opencode-ai/core/tool/registry"
import { WebFetchTool } from "@opencode-ai/core/tool/webfetch"
import { testEffect } from "./lib/effect"
import { toolIdentity, executeTool, settleTool, toolDefinitions } from "./lib/tool"

const sessionID = SessionV2.ID.make("ses_webfetch_test")
const requests: Array<{ readonly url: string; readonly headers: Record<string, string> }> = []
const assertions: PermissionV2.AssertInput[] = []
let respond = (_request: HttpClientRequest.HttpClientRequest) =>
  Effect.succeed(new Response("hello", { headers: { "content-type": "text/plain" } }))

const http = Layer.succeed(
  HttpClient.HttpClient,
  HttpClient.make((request) =>
    Effect.sync(() => requests.push({ url: request.url, headers: request.headers })).pipe(
      Effect.andThen(respond(request)),
      Effect.map((response) => HttpClientResponse.fromWeb(request, response)),
    ),
  ),
)
const permission = Layer.succeed(
  PermissionV2.Service,
  PermissionV2.Service.of({
    assert: (input) => Effect.sync(() => assertions.push(input)),
    ask: () => Effect.die("unused"),
    reply: () => Effect.die("unused"),
    get: () => Effect.die("unused"),
    forSession: () => Effect.die("unused"),
    list: () => Effect.die("unused"),
  }),
)
const registry = ToolRegistry.defaultLayer.pipe(Layer.provide(permission))
const authData = path.join(tmpdir(), `opencode-webfetch-auth-${Date.now()}`)
const authDeps = Layer.mergeAll(FSUtil.defaultLayer, Global.layerWith({ data: authData }))
const webfetch = WebFetchTool.layer.pipe(Layer.provide(registry), Layer.provide(permission), Layer.provide(http))
const it = testEffect(Layer.mergeAll(registry, permission, http, authDeps, webfetch.pipe(Layer.provide(authDeps))))
const fetchWebfetch = WebFetchTool.layer.pipe(
  Layer.provide(registry),
  Layer.provide(permission),
  Layer.provide(FetchHttpClient.layer),
  Layer.provide(authDeps),
)
const live = testEffect(Layer.mergeAll(registry, permission, FetchHttpClient.layer, authDeps, fetchWebfetch))

afterAll(() => fs.rm(authData, { recursive: true, force: true }))

const reset = () => {
  requests.length = 0
  assertions.length = 0
  respond = () => Effect.succeed(new Response("hello", { headers: { "content-type": "text/plain" } }))
}

const call = (input: typeof WebFetchTool.Input.Type, id = "call-webfetch") => ({
  sessionID,
  ...toolIdentity,
  call: { type: "tool-call" as const, id, name: "webfetch", input },
})

describe("WebFetchTool helpers", () => {
  test("defaults format and rejects invalid timeout controls", () => {
    const decode = Schema.decodeUnknownSync(WebFetchTool.Input)
    expect(decode({ url: "https://example.com" })).toEqual({ url: "https://example.com", format: "markdown" })
    expect(() => decode({ url: "https://example.com", timeout: 0 })).toThrow()
    expect(() => decode({ url: "https://example.com", timeout: WebFetchTool.MAX_TIMEOUT_SECONDS + 1 })).toThrow()
  })

  test("ports HTML text and markdown conversions without active content", () => {
    const html = "<h1>Hello</h1><script>bad()</script><p>world <strong>wide</strong></p><style>.bad {}</style>"
    expect(WebFetchTool.extractTextFromHTML(html)).toBe("Helloworld wide")
    expect(WebFetchTool.convertHTMLToMarkdown(html)).toBe("# Hello\n\nworld **wide**")
  })
})

describe("WebFetchTool registration", () => {
  it.effect("registers and fetches an ordinary hostname HTTP URL without rewriting it", () =>
    Effect.gen(function* () {
      reset()
      const registry = yield* ToolRegistry.Service
      const url = "http://example.com/public"

      expect((yield* toolDefinitions(registry)).map((tool) => tool.name)).toEqual(["webfetch"])
      expect(yield* settleTool(registry, call({ url, format: "text", timeout: 4 }))).toEqual({
        result: { type: "text", value: "hello" },
        output: {
          structured: { url, contentType: "text/plain", format: "text", output: "hello" },
          content: [{ type: "text", text: "hello" }],
        },
      })
      expect(assertions).toMatchObject([
        { sessionID, action: "webfetch", resources: [url], save: ["*"], metadata: { url, format: "text", timeout: 4 } },
      ])
      expect(requests).toMatchObject([{ url, headers: { accept: expect.stringContaining("text/plain;q=1.0") } }])
    }),
  )

  it.effect("accepts localhost URLs with the same requested-URL permission check", () =>
    Effect.gen(function* () {
      reset()
      const registry = yield* ToolRegistry.Service
      const url = "http://localhost/private"

      expect(yield* executeTool(registry, call({ url, format: "text" }))).toEqual({
        type: "text",
        value: "hello",
      })
      expect(assertions).toMatchObject([
        { sessionID, action: "webfetch", resources: [url], save: ["*"], metadata: { url, format: "text" } },
      ])
      expect(requests.map((request) => request.url)).toEqual([url])
    }),
  )

  live.effect("follows redirects while approving only the requested URL", () =>
    Effect.acquireUseRelease(
      Effect.sync(() =>
        Bun.serve({
          port: 0,
          fetch: (request) =>
            new URL(request.url).pathname === "/redirect"
              ? new Response("", { status: 302, headers: { location: "/target" } })
              : new Response("redirected", { headers: { "content-type": "text/plain" } }),
        }),
      ),
      (server) =>
        Effect.gen(function* () {
          reset()
          const registry = yield* ToolRegistry.Service
          const url = new URL("/redirect", server.url).toString()

          expect(yield* executeTool(registry, call({ url, format: "text" }))).toEqual({
            type: "text",
            value: "redirected",
          })
          expect(assertions).toMatchObject([
            { sessionID, action: "webfetch", resources: [url], save: ["*"], metadata: { url, format: "text" } },
          ])
        }),
      (server) => Effect.promise(() => server.stop(true)),
    ),
  )

  it.effect("rejects non-HTTP schemes before permission or transport", () =>
    Effect.gen(function* () {
      reset()
      const registry = yield* ToolRegistry.Service

      expect(yield* executeTool(registry, call({ url: "file:///etc/passwd", format: "text" }))).toEqual({
        type: "error",
        value: "Unable to fetch file:///etc/passwd",
      })
      expect(assertions).toEqual([])
      expect(requests).toEqual([])
    }),
  )

  it.effect("converts HTML to requested markdown and text", () =>
    Effect.gen(function* () {
      reset()
      respond = () =>
        Effect.succeed(
          new Response("<h1>Hello</h1><p>world</p><script>bad()</script>", {
            headers: { "content-type": "text/html; charset=utf-8" },
          }),
        )
      const registry = yield* ToolRegistry.Service

      expect(yield* executeTool(registry, call({ url: "https://1.1.1.1", format: "markdown" }))).toEqual({
        type: "text",
        value: "# Hello\n\nworld",
      })
      expect(yield* executeTool(registry, call({ url: "https://1.1.1.1", format: "text" }))).toEqual({
        type: "text",
        value: "Helloworld",
      })
    }),
  )

  it.effect("rejects declared and streamed oversized bodies", () =>
    Effect.gen(function* () {
      reset()
      const registry = yield* ToolRegistry.Service
      respond = () =>
        Effect.succeed(
          new Response("small", {
            headers: { "content-type": "text/plain", "content-length": String(WebFetchTool.MAX_RESPONSE_BYTES + 1) },
          }),
        )
      expect(yield* executeTool(registry, call({ url: "https://1.1.1.1/declared", format: "text" }))).toEqual({
        type: "error",
        value: "Unable to fetch https://1.1.1.1/declared",
      })

      respond = () =>
        Effect.succeed(
          new Response("x".repeat(WebFetchTool.MAX_RESPONSE_BYTES + 1), { headers: { "content-type": "text/plain" } }),
        )
      expect(yield* executeTool(registry, call({ url: "https://1.1.1.1/streamed", format: "text" }))).toEqual({
        type: "error",
        value: "Unable to fetch https://1.1.1.1/streamed",
      })
    }),
  )

  it.effect("keeps images and files unsupported until typed settlement can carry attachments", () =>
    Effect.gen(function* () {
      reset()
      const registry = yield* ToolRegistry.Service
      respond = () => Effect.succeed(new Response("png", { headers: { "content-type": "image/png" } }))
      expect(yield* executeTool(registry, call({ url: "https://1.1.1.1/image", format: "html" }))).toEqual({
        type: "error",
        value: "Unable to fetch https://1.1.1.1/image",
      })

      respond = () => Effect.succeed(new Response("pdf", { headers: { "content-type": "application/pdf" } }))
      expect(yield* executeTool(registry, call({ url: "https://1.1.1.1/file", format: "html" }))).toEqual({
        type: "error",
        value: "Unable to fetch https://1.1.1.1/file",
      })
    }),
  )

  it.effect("retries Cloudflare challenges with an honest user agent", () =>
    Effect.gen(function* () {
      reset()
      let count = 0
      respond = () =>
        Effect.succeed(
          ++count === 1
            ? new Response("challenge", { status: 403, headers: { "cf-mitigated": "challenge" } })
            : new Response("ok", { headers: { "content-type": "text/plain" } }),
        )
      const registry = yield* ToolRegistry.Service

      expect(yield* executeTool(registry, call({ url: "https://1.1.1.1", format: "text" }))).toEqual({
        type: "text",
        value: "ok",
      })
      expect(requests).toHaveLength(2)
      expect(requests[0]?.headers["user-agent"]).toContain("Mozilla/5.0")
      expect(requests[1]?.headers["user-agent"]).toBe("opencode")
    }),
  )

  live.effect("authenticates protected resources via RFC 9728 and device authorization", () =>
    Effect.acquireUseRelease(
      Effect.sync(() => {
        let server: ReturnType<typeof Bun.serve>
        server = Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          fetch: async (request): Promise<Response> => {
            const url = new URL(request.url)
            const origin = new URL(server.url).origin
            const protectedUrl = new URL("/protected", server.url).toString()
            if (url.pathname === "/protected") {
              if (request.headers.get("authorization") === "Bearer access-token") {
                return new Response("oauth ok", { headers: { "content-type": "text/plain" } })
              }
              return new Response("auth required", {
                status: 401,
                headers: {
                  "www-authenticate": `Bearer resource_metadata="${new URL("/.well-known/oauth-protected-resource/protected", server.url)}"`,
                },
              })
            }
            if (url.pathname === "/.well-known/oauth-protected-resource/protected") {
              return Response.json(
                { resource: protectedUrl, authorization_servers: [origin], scopes_supported: ["read"] },
                { headers: { "content-type": "application/json" } },
              )
            }
            if (url.pathname === "/.well-known/oauth-authorization-server") {
              return Response.json(
                {
                  issuer: origin,
                  response_types_supported: ["code"],
                  grant_types_supported: ["urn:ietf:params:oauth:grant-type:device_code"],
                  token_endpoint: new URL("/token", server.url).toString(),
                  registration_endpoint: new URL("/register", server.url).toString(),
                  device_authorization_endpoint: new URL("/device", server.url).toString(),
                },
                { headers: { "content-type": "application/json" } },
              )
            }
            if (url.pathname === "/register") return Response.json({ client_id: "client" })
            if (url.pathname === "/device") {
              return Response.json({
                device_code: "device",
                user_code: "USER-CODE",
                verification_uri: new URL("/verify", server.url).toString(),
                expires_in: 30,
                interval: 1,
              })
            }
            if (url.pathname === "/token") {
              const body = new URLSearchParams(await request.text())
              if (body.get("grant_type") === "urn:ietf:params:oauth:grant-type:device_code") {
                return Response.json({ access_token: "access-token", token_type: "Bearer", expires_in: 60 })
              }
            }
            return new Response("not found", { status: 404 })
          },
        })
        return server
      }),
      (server) =>
        Effect.gen(function* () {
          yield* Effect.promise(() => fs.rm(authData, { recursive: true, force: true }))
          reset()
          const registry = yield* ToolRegistry.Service
          const url = new URL("/protected", server.url).toString()

          expect(yield* executeTool(registry, call({ url, format: "text" }))).toEqual({
            type: "text",
            value: "oauth ok",
          })
          expect(assertions).toMatchObject([
            { action: "webfetch", resources: [url] },
            { action: "webfetch_auth", resources: [url], metadata: { url, action: "authenticate" } },
            {
              action: "webfetch_auth",
              resources: [`${url}#device-code`],
              metadata: {
                url,
                action: "device_code",
                verification_uri: new URL("/verify", server.url).toString(),
                user_code: "USER-CODE",
              },
            },
          ])
        }),
      (server) => Effect.promise(() => server.stop(true)),
    ),
  )

  it.live("times out stalled requests", () =>
    Effect.gen(function* () {
      reset()
      respond = () => Effect.never
      const registry = yield* ToolRegistry.Service
      expect(yield* executeTool(registry, call({ url: "https://1.1.1.1/slow", format: "text", timeout: 1 }))).toEqual({
        type: "error",
        value: "Unable to fetch https://1.1.1.1/slow",
      })
    }),
  )
})

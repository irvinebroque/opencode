import { afterAll, describe, expect } from "bun:test"
import { tmpdir } from "node:os"
import path from "node:path"
import fs from "node:fs/promises"
import { Effect, Layer } from "effect"
import { FetchHttpClient } from "effect/unstable/http"
import { FSUtil } from "@opencode-ai/core/fs-util"
import { Global } from "@opencode-ai/core/global"
import { Agent } from "../../src/agent/agent"
import { Truncate } from "@/tool/truncate"
import { WebFetchTool } from "../../src/tool/webfetch"
import { SessionID, MessageID } from "../../src/session/schema"
import { Tool } from "@/tool/tool"
import { testEffect } from "../lib/effect"

const authData = path.join(tmpdir(), `opencode-legacy-webfetch-auth-${Date.now()}`)
const it = testEffect(
  Layer.mergeAll(
    FetchHttpClient.layer,
    FSUtil.defaultLayer,
    Global.layerWith({ data: authData }),
    Truncate.defaultLayer,
    Agent.defaultLayer,
  ),
)

afterAll(() => fs.rm(authData, { recursive: true, force: true }))

const ctx = {
  sessionID: SessionID.make("ses_test"),
  messageID: MessageID.make("msg_message"),
  callID: "",
  agent: "build",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  ask: () => Effect.void,
}

const withFetch = <A, E, R>(
  fetch: (req: Request) => Response | Promise<Response>,
  fn: (url: URL) => Effect.Effect<A, E, R>,
) =>
  Effect.acquireUseRelease(
    Effect.sync(() => Bun.serve({ port: 0, fetch })),
    (server) => fn(server.url),
    (server) => Effect.sync(() => server.stop(true)),
  )

const exec = Effect.fn("WebFetchToolTest.exec")(function* (
  args: Tool.InferParameters<typeof WebFetchTool>,
  context: Tool.Context = ctx,
) {
  const info = yield* WebFetchTool
  const tool = yield* info.init()
  return yield* tool.execute(args, context)
})

describe("tool.webfetch", () => {
  it.instance("returns image responses as file attachments", () =>
    Effect.gen(function* () {
      const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])
      yield* withFetch(
        () => new Response(bytes, { status: 200, headers: { "content-type": "IMAGE/PNG; charset=binary" } }),
        (url) =>
          Effect.gen(function* () {
            const result = yield* exec({ url: new URL("/image.png", url).toString(), format: "markdown" })
            expect(result.output).toBe("Image fetched successfully")
            expect(result.attachments).toBeDefined()
            expect(result.attachments?.length).toBe(1)
            expect(result.attachments?.[0].type).toBe("file")
            expect(result.attachments?.[0].mime).toBe("image/png")
            expect(result.attachments?.[0].url.startsWith("data:image/png;base64,")).toBe(true)
            expect(result.attachments?.[0]).not.toHaveProperty("id")
            expect(result.attachments?.[0]).not.toHaveProperty("sessionID")
            expect(result.attachments?.[0]).not.toHaveProperty("messageID")
          }),
      )
    }),
  )

  it.instance("keeps svg as text output", () =>
    withFetch(
      () =>
        new Response('<svg xmlns="http://www.w3.org/2000/svg"><text>hello</text></svg>', {
          status: 200,
          headers: { "content-type": "image/svg+xml; charset=UTF-8" },
        }),
      (url) =>
        Effect.gen(function* () {
          const result = yield* exec({ url: new URL("/image.svg", url).toString(), format: "html" })
          expect(result.output).toContain("<svg")
          expect(result.attachments).toBeUndefined()
        }),
    ),
  )

  it.instance("keeps text responses as text output", () =>
    withFetch(
      () =>
        new Response("hello from webfetch", {
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
        }),
      (url) =>
        Effect.gen(function* () {
          const result = yield* exec({ url: new URL("/file.txt", url).toString(), format: "text" })
          expect(result.output).toBe("hello from webfetch")
          expect(result.attachments).toBeUndefined()
        }),
    ),
  )

  it.instance("authenticates protected resources with device authorization in headless mode", () =>
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
          const permissions: string[] = []
          const metadata: Record<string, unknown>[] = []
          const url = new URL("/protected", server.url).toString()
          const result = yield* exec(
            { url, format: "text" },
            {
              ...ctx,
              extra: { headless: true },
              ask: (input) =>
                Effect.sync(() => {
                  permissions.push(input.permission)
                }),
              metadata: (input) =>
                Effect.sync(() => {
                  metadata.push(input.metadata ?? {})
                }),
            },
          )

          expect(result.output).toBe("oauth ok")
          expect(permissions).toContain("webfetch_auth")
          expect(metadata).toContainEqual({
            url,
            action: "device_code",
            verification_uri: new URL("/verify", server.url).toString(),
            user_code: "USER-CODE",
          })
        }),
      (server) => Effect.sync(() => server.stop(true)),
    ),
  )

  it.instance("extracts text from html without scripts or styles", () =>
    withFetch(
      () =>
        new Response(
          "<html><head><style>.hidden{}</style><script>alert('x')</script></head><body>Hello <b>world</b></body></html>",
          {
            status: 200,
            headers: { "content-type": "text/html; charset=utf-8" },
          },
        ),
      (url) =>
        Effect.gen(function* () {
          const result = yield* exec({ url: new URL("/page.html", url).toString(), format: "text" })
          expect(result.output).toBe("Hello world")
          expect(result.attachments).toBeUndefined()
        }),
    ),
  )
})

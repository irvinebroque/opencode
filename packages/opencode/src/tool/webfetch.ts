import z from "zod"
import { Effect } from "effect"
import { Tool } from "./tool"
import TurndownService from "turndown"
import DESCRIPTION from "./webfetch.txt"
import { abortAfterAny } from "../util/abort"
import { Log } from "../util/log"
import { store, resolveCredentials } from "../auth/webfetch-auth"
import { handleAuthChallenge } from "../auth/orchestrate"
import { LocalCallbackServer, type Interaction } from "../auth/flow"

const log = Log.create({ service: "webfetch" })

const MAX_RESPONSE_SIZE = 5 * 1024 * 1024 // 5MB
const DEFAULT_TIMEOUT = 30 * 1000 // 30 seconds
const MAX_TIMEOUT = 120 * 1000 // 2 minutes

const parameters = z.object({
  url: z.string().describe("The URL to fetch content from"),
  format: z
    .enum(["text", "markdown", "html"])
    .default("markdown")
    .describe("The format to return the content in (text, markdown, or html). Defaults to markdown."),
  timeout: z.number().describe("Optional timeout in seconds (max 120)").optional(),
})

export const WebFetchTool = Tool.define(
  "webfetch",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: z.infer<typeof parameters>, ctx: Tool.Context) =>
        Effect.gen(function* () {
          if (!params.url.startsWith("http://") && !params.url.startsWith("https://")) {
            throw new Error("URL must start with http:// or https://")
          }

          yield* ctx.ask({
            permission: "webfetch",
            patterns: [params.url],
            always: ["*"],
            metadata: {
              url: params.url,
              format: params.format,
              timeout: params.timeout,
            },
          })

          return yield* Effect.promise(async () => {
            const timeout = Math.min((params.timeout ?? DEFAULT_TIMEOUT / 1000) * 1000, MAX_TIMEOUT)
            const timer = abortAfterAny(timeout, ctx.abort)

            try {
              let accept = "*/*"
              switch (params.format) {
                case "markdown":
                  accept = "text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1"
                  break
                case "text":
                  accept = "text/plain;q=1.0, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.1"
                  break
                case "html":
                  accept =
                    "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1"
                  break
                default:
                  accept =
                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
              }

              const headers = {
                "User-Agent":
                  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
                Accept: accept,
                "Accept-Language": "en-US,en;q=0.9",
              }

              // Layer 1: resolve stored credentials (local lookup, auto-refresh)
              const auth = await resolveCredentials(params.url, store, log, timer.signal)

              const initial = await fetch(params.url, { signal: timer.signal, headers: { ...headers, ...auth } })

              let response =
                initial.status === 403 && initial.headers.get("cf-mitigated") === "challenge"
                  ? await fetch(params.url, { signal: timer.signal, headers: { ...headers, ...auth, "User-Agent": "opencode" } })
                  : initial

              const tryAuth = response.status === 401 || (response.status === 403 && response.headers.has("www-authenticate"))
              if (!response.ok && tryAuth) {
                timer.clearTimeout()

                const interaction: Interaction = {
                  async askConsent(info) {
                    const data: Record<string, string> = {
                      url: params.url,
                      action: "authenticate",
                      server: info.server,
                      scopes: (info.scopes?.join(", ") ?? "default") + " (server-reported, unverified)",
                    }
                    if (new URL(params.url).origin !== new URL(info.server).origin) {
                      data.warning =
                        `Cross-origin auth: ${new URL(params.url).host} directs authentication to ${new URL(info.server).host}. ` +
                        `The resulting token will be sent to ${new URL(params.url).host}.`
                    }
                    await Effect.runPromise(
                      ctx.ask({
                        permission: "webfetch",
                        patterns: [params.url],
                        always: [new URL(params.url).origin + "/*"],
                        metadata: data,
                      }),
                    )
                  },
                  async openUrl(url) {
                    await (await import("open")).default(url)
                  },
                  async showDeviceCode(info) {
                    await Effect.runPromise(
                      ctx.metadata({
                        title: "Authenticate webfetch request",
                        metadata: {
                          url: params.url,
                          action: "device_code",
                          verification_uri: info.verification_uri,
                          user_code: info.user_code,
                        },
                      }),
                    )
                    log.info("device code flow", {
                      uri: info.verification_uri,
                      code: info.user_code,
                    })
                  },
                }

                const authed = await handleAuthChallenge({
                  response,
                  url: params.url,
                  baseHeaders: headers,
                  signal: ctx.abort,
                  store,
                  interaction,
                  callbackServer: new LocalCallbackServer(),
                  client: { name: "OpenCode", uri: "https://opencode.ai" },
                  logger: log,
                })
                if (authed) response = authed
              } else {
                timer.clearTimeout()
              }

              if (!response.ok) {
                throw new Error(`Request failed with status code: ${response.status}`)
              }

              const length = response.headers.get("content-length")
              if (length && parseInt(length) > MAX_RESPONSE_SIZE) {
                throw new Error("Response too large (exceeds 5MB limit)")
              }

              const buffer = await response.arrayBuffer()
              if (buffer.byteLength > MAX_RESPONSE_SIZE) {
                throw new Error("Response too large (exceeds 5MB limit)")
              }

              const contentType = response.headers.get("content-type") || ""
              const mime = contentType.split(";")[0]?.trim().toLowerCase() || ""
              const title = `${params.url} (${contentType})`
              const isImage = mime.startsWith("image/") && mime !== "image/svg+xml" && mime !== "image/vnd.fastbidsheet"

              if (isImage) {
                const base64 = Buffer.from(buffer).toString("base64")
                return {
                  title,
                  output: "Image fetched successfully",
                  metadata: {},
                  attachments: [
                    {
                      type: "file" as const,
                      mime,
                      url: `data:${mime};base64,${base64}`,
                    },
                  ],
                }
              }

              const content = new TextDecoder().decode(buffer)

              switch (params.format) {
                case "markdown":
                  if (contentType.includes("text/html")) {
                    return {
                      output: convertHTMLToMarkdown(content),
                      title,
                      metadata: {},
                    }
                  }
                  return { output: content, title, metadata: {} }

                case "text":
                  if (contentType.includes("text/html")) {
                    return {
                      output: await extractTextFromHTML(content),
                      title,
                      metadata: {},
                    }
                  }
                  return { output: content, title, metadata: {} }

                case "html":
                  return { output: content, title, metadata: {} }

                default:
                  return { output: content, title, metadata: {} }
              }
            } finally {
              timer.clearTimeout()
            }
          })
        }).pipe(Effect.orDie),
    }
  }),
)

async function extractTextFromHTML(html: string) {
  let text = ""
  let skipContent = false

  const rewriter = new HTMLRewriter()
    .on("script, style, noscript, iframe, object, embed", {
      element() {
        skipContent = true
      },
      text() {
        // Skip text content inside these elements
      },
    })
    .on("*", {
      element(element) {
        // Reset skip flag when entering other elements
        if (!["script", "style", "noscript", "iframe", "object", "embed"].includes(element.tagName)) {
          skipContent = false
        }
      },
      text(input) {
        if (!skipContent) {
          text += input.text
        }
      },
    })
    .transform(new Response(html))

  await rewriter.text()
  return text.trim()
}

function convertHTMLToMarkdown(html: string): string {
  const turndownService = new TurndownService({
    headingStyle: "atx",
    hr: "---",
    bulletListMarker: "-",
    codeBlockStyle: "fenced",
    emDelimiter: "*",
  })
  turndownService.remove(["script", "style", "meta", "link"])
  return turndownService.turndown(html)
}

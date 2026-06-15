import { Effect, Schema } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { Parser } from "htmlparser2"
import * as Tool from "./tool"
import TurndownService from "turndown"
import DESCRIPTION from "./webfetch.txt"
import { isImageAttachment } from "@/util/media"
import { FSUtil } from "@opencode-ai/core/fs-util"
import { Global } from "@opencode-ai/core/global"
import { WebFetchAuth } from "@opencode-ai/core/tool/webfetch-auth"

const MAX_RESPONSE_SIZE = 5 * 1024 * 1024 // 5MB
const DEFAULT_TIMEOUT = 30 * 1000 // 30 seconds
const MAX_TIMEOUT = 120 * 1000 // 2 minutes
const SIGN_IN_TITLE = "Sign in to access this URL"

function abortAfterAny(timeout: number, parent: AbortSignal) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new Error("Request timed out")), timeout)
  const abort = () => controller.abort(parent.reason)
  parent.addEventListener("abort", abort, { once: true })
  return {
    signal: controller.signal,
    clear() {
      clearTimeout(timer)
      parent.removeEventListener("abort", abort)
    },
  }
}

export const Parameters = Schema.Struct({
  url: Schema.String.annotate({ description: "The URL to fetch content from" }),
  format: Schema.Literals(["text", "markdown", "html"])
    .annotate({
      description: "The format to return the content in (text, markdown, or html). Defaults to markdown.",
      default: "markdown",
    })
    .pipe(Schema.withDecodingDefault(Effect.succeed("markdown" as const))),
  timeout: Schema.optional(Schema.Number).annotate({ description: "Optional timeout in seconds (max 120)" }),
})

export const WebFetchTool = Tool.define(
  "webfetch",
  Effect.gen(function* () {
    const http = yield* HttpClient.HttpClient
    const fs = yield* FSUtil.Service
    const global = yield* Global.Service
    const store = WebFetchAuth.fileStore(fs, global)

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, ctx: Tool.Context) =>
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

          const timeout = Math.min((params.timeout ?? DEFAULT_TIMEOUT / 1000) * 1000, MAX_TIMEOUT)

          // Build Accept header based on requested format with q parameters for fallbacks
          let acceptHeader = "*/*"
          switch (params.format) {
            case "markdown":
              acceptHeader = "text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1"
              break
            case "text":
              acceptHeader = "text/plain;q=1.0, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.1"
              break
            case "html":
              acceptHeader =
                "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1"
              break
            default:
              acceptHeader =
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
          }
          const headers = {
            "User-Agent":
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            Accept: acceptHeader,
            "Accept-Language": "en-US,en;q=0.9",
          }

          const header = (response: Response | HttpClientResponse.HttpClientResponse, key: string) =>
            response instanceof Response ? (response.headers.get(key) ?? "") : (response.headers[key] ?? "")
          const ok = (response: Response | HttpClientResponse.HttpClientResponse) =>
            response.status >= 200 && response.status < 300

          const response = yield* Effect.promise(async () => {
            const timer = abortAfterAny(timeout, ctx.abort)
            let auth: ReturnType<typeof abortAfterAny> | undefined
            const execute = (requestHeaders: Record<string, string>) =>
              Effect.runPromise(
                http.execute(HttpClientRequest.get(params.url).pipe(HttpClientRequest.setHeaders(requestHeaders))),
              )
            const fetchAuthorized = (requestHeaders: Record<string, string>) =>
              fetch(params.url, { headers: requestHeaders, redirect: "error", signal: timer.signal })
            try {
              const stored = await WebFetchAuth.resolveCredentials(params.url, store, undefined, timer.signal)
              const initial = stored.Authorization
                ? await fetchAuthorized({ ...headers, ...stored })
                : await execute(headers)
              let response: Response | HttpClientResponse.HttpClientResponse =
                initial.status === 403 && header(initial, "cf-mitigated") === "challenge"
                  ? stored.Authorization
                    ? await fetchAuthorized({ ...headers, ...stored, "User-Agent": "opencode" })
                    : await execute({ ...headers, "User-Agent": "opencode" })
                  : initial

              const shouldAuth =
                !ok(response) &&
                (response.status === 401 || (response.status === 403 && !!header(response, "www-authenticate")))
              if (shouldAuth) {
                auth = abortAfterAny(WebFetchAuth.AUTH_TIMEOUT_SECONDS * 1000, ctx.abort)
                const interaction: WebFetchAuth.Interaction = {
                  askConsent: (info) =>
                    Effect.runPromise(
                      ctx.ask({
                        permission: "webfetch_auth",
                        patterns: [params.url],
                        always: [params.url],
                        metadata: {
                          url: params.url,
                          action: "authenticate",
                          server: info.server,
                          scopes: info.scopes?.join(", ") ?? "server default",
                        },
                      }),
                    ),
                  openUrl: WebFetchAuth.openAuthorizationUrl,
                  showDeviceCode: (info) =>
                    Effect.runPromise(
                      ctx.metadata({
                        title: SIGN_IN_TITLE,
                        metadata: {
                          url: params.url,
                          action: "device_code",
                          verification_uri: info.verification_uri,
                          user_code: info.user_code,
                        },
                      }),
                    ),
                }
                const authed = await WebFetchAuth.handleAuthChallenge({
                  headers: response instanceof Response ? response.headers : response.headers,
                  url: params.url,
                  baseHeaders: headers,
                  signal: auth.signal,
                  store,
                  interaction,
                  callbackServer: new WebFetchAuth.LocalCallbackServer(),
                  client: { name: "OpenCode", uri: "https://opencode.ai" },
                  preferDevice: ctx.extra?.headless === true || process.env.OPENCODE_WEBFETCH_OAUTH_DEVICE === "1",
                })
                if (authed) response = authed
              }

              if (!ok(response)) throw new Error(`Request failed with status code: ${response.status}`)
              return response
            } catch (error) {
              if ((timer.signal.aborted || auth?.signal.aborted) && !ctx.abort.aborted)
                throw new Error("Request timed out", { cause: error })
              throw error
            } finally {
              auth?.clear()
              timer.clear()
            }
          })

          // Check content length
          const contentLength = header(response, "content-length")
          if (contentLength && parseInt(contentLength) > MAX_RESPONSE_SIZE) {
            throw new Error("Response too large (exceeds 5MB limit)")
          }

          const arrayBuffer =
            response instanceof Response
              ? yield* Effect.promise(() => response.arrayBuffer())
              : yield* response.arrayBuffer
          if (arrayBuffer.byteLength > MAX_RESPONSE_SIZE) {
            throw new Error("Response too large (exceeds 5MB limit)")
          }

          const contentType = header(response, "content-type")
          const mime = contentType.split(";")[0]?.trim().toLowerCase() || ""
          const title = `${params.url} (${contentType})`

          if (isImageAttachment(mime)) {
            const base64Content = Buffer.from(arrayBuffer).toString("base64")
            return {
              title,
              output: "Image fetched successfully",
              metadata: {},
              attachments: [
                {
                  type: "file" as const,
                  mime,
                  url: `data:${mime};base64,${base64Content}`,
                },
              ],
            }
          }

          const content = new TextDecoder().decode(arrayBuffer)

          // Handle content based on requested format and actual content type
          switch (params.format) {
            case "markdown":
              if (contentType.includes("text/html")) {
                const markdown = convertHTMLToMarkdown(content)
                return {
                  output: markdown,
                  title,
                  metadata: {},
                }
              }
              return { output: content, title, metadata: {} }

            case "text":
              if (contentType.includes("text/html")) {
                return { output: extractTextFromHTML(content), title, metadata: {} }
              }
              return { output: content, title, metadata: {} }

            case "html":
              return { output: content, title, metadata: {} }

            default:
              return { output: content, title, metadata: {} }
          }
        }).pipe(Effect.orDie),
    }
  }),
)

function extractTextFromHTML(html: string) {
  let text = ""
  let skipDepth = 0

  const parser = new Parser({
    onopentag(name) {
      if (skipDepth > 0 || ["script", "style", "noscript", "iframe", "object", "embed"].includes(name)) {
        skipDepth++
      }
    },
    ontext(input) {
      if (skipDepth === 0) text += input
    },
    onclosetag() {
      if (skipDepth > 0) skipDepth--
    },
  })

  parser.write(html)
  parser.end()

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

export * as WebFetchTool from "./webfetch"

import { ToolFailure } from "@opencode-ai/llm"
import { Duration, Effect, Layer, Schema, Stream } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { Parser } from "htmlparser2"
import TurndownService from "turndown"
import { FSUtil } from "../fs-util"
import { Global } from "../global"
import { PermissionV2 } from "../permission"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { WebFetchAuth } from "./webfetch-auth"

export const name = "webfetch"
export const MAX_RESPONSE_BYTES = 5 * 1024 * 1024
export const DEFAULT_TIMEOUT_SECONDS = 30
export const MAX_TIMEOUT_SECONDS = 120

export const description = `Fetch content from an HTTP or HTTPS URL and return it as text, markdown, or HTML. Markdown is the default.

Use a more targeted tool when one is available. This tool is read-only. Large text results may be replaced with a preview while the complete output is retained in managed storage.`

const Timeout = Schema.Number.check(Schema.isGreaterThan(0), Schema.isLessThanOrEqualTo(MAX_TIMEOUT_SECONDS))

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "The HTTP or HTTPS URL to fetch content from" }),
  format: Schema.Literals(["text", "markdown", "html"])
    .annotate({ description: "The format to return the content in. Defaults to markdown." })
    .pipe(Schema.withDecodingDefault(Effect.succeed("markdown" as const))),
  timeout: Timeout.pipe(Schema.optional).annotate({
    description: `Optional timeout in seconds (maximum: ${MAX_TIMEOUT_SECONDS})`,
  }),
})

const Output = Schema.Struct({
  url: Schema.String,
  contentType: Schema.String,
  format: Input.fields.format,
  output: Schema.String,
})

type Format = (typeof Input.Type)["format"]

const acceptHeader = (format: Format) => {
  switch (format) {
    case "markdown":
      return "text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1"
    case "text":
      return "text/plain;q=1.0, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.1"
    case "html":
      return "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1"
  }
  return "*/*"
}

const headers = (format: Format, userAgent: string) => ({
  "User-Agent": userAgent,
  Accept: acceptHeader(format),
  "Accept-Language": "en-US,en;q=0.9",
})

const browserUserAgent =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"

const isCloudflareChallenge = (error: unknown) => {
  if (!error || typeof error !== "object" || !("reason" in error)) return false
  const reason = error.reason
  if (
    !reason ||
    typeof reason !== "object" ||
    !("_tag" in reason) ||
    reason._tag !== "StatusCodeError" ||
    !("response" in reason)
  )
    return false
  const response = reason.response as HttpClientResponse.HttpClientResponse
  return response.status === 403 && response.headers["cf-mitigated"] === "challenge"
}

const request = (
  url: string,
  format: Format,
  userAgent = browserUserAgent,
  extraHeaders: Record<string, string> = {},
) => HttpClientRequest.get(url).pipe(HttpClientRequest.setHeaders({ ...headers(format, userAgent), ...extraHeaders }))

const assertHttpUrl = (url: URL) => {
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("URL must use http:// or https://")
}

const execute = (http: HttpClient.HttpClient, url: string, format: Format, userAgent = browserUserAgent) =>
  http.execute(request(url, format, userAgent)).pipe(Effect.flatMap(HttpClientResponse.filterStatusOk))

const hasAuthChallenge = (status: number, headers: Headers | Record<string, string | undefined>) =>
  (status === 401 || status === 403) && WebFetchAuth.challenges(headers).length > 0

const authChallengeResponse = (error: unknown) => {
  if (!error || typeof error !== "object" || !("reason" in error)) return
  const reason = error.reason
  if (
    !reason ||
    typeof reason !== "object" ||
    !("_tag" in reason) ||
    reason._tag !== "StatusCodeError" ||
    !("response" in reason)
  )
    return
  const response = reason.response as HttpClientResponse.HttpClientResponse
  return hasAuthChallenge(response.status, response.headers) ? response : undefined
}

const fetchWithAuthorization = (url: string, format: Format, extraHeaders: Record<string, string>) =>
  Effect.tryPromise({
    try: () => fetch(url, { headers: { ...headers(format, browserUserAgent), ...extraHeaders }, redirect: "error" }),
    catch: (error) => error,
  })

const fromWebResponse = (url: string, format: Format, response: Response) =>
  HttpClientResponse.fromWeb(request(url, format), response)

const collectBody = (response: HttpClientResponse.HttpClientResponse) =>
  Effect.gen(function* () {
    const contentLength = response.headers["content-length"]
    if (contentLength && Number.parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
      return yield* Effect.fail(new Error(`Response too large (exceeds ${MAX_RESPONSE_BYTES} byte limit)`))
    }
    const chunks: Uint8Array[] = []
    let size = 0
    yield* Stream.runForEach(response.stream, (chunk) =>
      Effect.gen(function* () {
        size += chunk.byteLength
        if (size > MAX_RESPONSE_BYTES)
          return yield* Effect.fail(new Error(`Response too large (exceeds ${MAX_RESPONSE_BYTES} byte limit)`))
        chunks.push(chunk)
        return undefined
      }),
    )
    return Buffer.concat(chunks, size)
  })

const mimeFrom = (contentType: string) => contentType.split(";", 1)[0]?.trim().toLowerCase() ?? ""
const isImageAttachment = (mime: string) =>
  mime.startsWith("image/") && mime !== "image/svg+xml" && mime !== "image/vnd.fastbidsheet"
const isTextualMime = (mime: string) =>
  !mime ||
  mime.startsWith("text/") ||
  mime === "application/json" ||
  mime.endsWith("+json") ||
  mime === "application/xml" ||
  mime.endsWith("+xml") ||
  mime === "application/javascript" ||
  mime === "application/x-javascript"
const convert = (content: string, contentType: string, format: Format) => {
  if (!contentType.includes("text/html")) return content
  if (format === "markdown") return convertHTMLToMarkdown(content)
  if (format === "text") return extractTextFromHTML(content)
  return content
}

export const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const http = yield* HttpClient.HttpClient
    const permission = yield* PermissionV2.Service
    const fs = yield* FSUtil.Service
    const global = yield* Global.Service
    const store = WebFetchAuth.fileStore(fs, global)

    yield* tools
      .register({
        [name]: Tool.make({
          description,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input, context) =>
            Effect.gen(function* () {
              yield* Effect.try({
                try: () => assertHttpUrl(new URL(input.url)),
                catch: (error) => error,
              })

              yield* permission.assert({
                action: name,
                resources: [input.url],
                save: ["*"],
                metadata: input,
                sessionID: context.sessionID,
                agent: context.agent,
                source: { type: "tool", messageID: context.assistantMessageID, callID: context.toolCallID },
              })

              const source = {
                type: "tool" as const,
                messageID: context.assistantMessageID,
                callID: context.toolCallID,
              }
              const timeout = Effect.timeoutOrElse({
                duration: Duration.seconds(input.timeout ?? DEFAULT_TIMEOUT_SECONDS),
                orElse: () => Effect.fail(new Error("Request timed out")),
              })
              const response = yield* Effect.gen(function* () {
                const authHeaders = yield* Effect.tryPromise(() => WebFetchAuth.resolveCredentials(input.url, store))
                if (authHeaders.Authorization) {
                  const response = yield* fetchWithAuthorization(input.url, input.format, authHeaders).pipe(timeout)
                  if (response.ok) return fromWebResponse(input.url, input.format, response)
                  if (!hasAuthChallenge(response.status, response.headers)) {
                    return yield* Effect.fail(new Error(`Request failed with status code: ${response.status}`))
                  }
                  const authed = yield* Effect.tryPromise(() =>
                    WebFetchAuth.handleAuthChallenge({
                      headers: response.headers,
                      url: input.url,
                      baseHeaders: headers(input.format, browserUserAgent),
                      store,
                      callbackServer: new WebFetchAuth.LocalCallbackServer(),
                      client: { name: "OpenCode", uri: "https://opencode.ai" },
                      interaction: {
                        askConsent: (info) =>
                          Effect.runPromise(
                            permission.assert({
                              action: "webfetch_auth",
                              resources: [input.url],
                              save: [input.url],
                              metadata: {
                                url: input.url,
                                action: "authenticate",
                                server: info.server,
                                scopes: info.scopes?.join(", ") ?? "server default",
                              },
                              sessionID: context.sessionID,
                              agent: context.agent,
                              source,
                            }),
                          ),
                        openUrl: WebFetchAuth.openAuthorizationUrl,
                        showDeviceCode: (info) =>
                          Effect.runPromise(
                            permission.assert({
                              action: "webfetch_auth",
                              resources: [`${input.url}#device-code`],
                              metadata: {
                                url: input.url,
                                action: "device_code",
                                verification_uri: info.verification_uri,
                                user_code: info.user_code,
                              },
                              sessionID: context.sessionID,
                              agent: context.agent,
                              source,
                            }),
                          ),
                      },
                      preferDevice: process.env.OPENCODE_WEBFETCH_OAUTH_DEVICE === "1",
                    }),
                  ).pipe(
                    Effect.timeoutOrElse({
                      duration: Duration.seconds(WebFetchAuth.AUTH_TIMEOUT_SECONDS),
                      orElse: () => Effect.fail(new Error("Authentication timed out")),
                    }),
                  )
                  if (!authed)
                    return yield* Effect.fail(new Error(`Request failed with status code: ${response.status}`))
                  return fromWebResponse(input.url, input.format, authed)
                }

                return yield* execute(http, input.url, input.format).pipe(
                  Effect.catchIf(isCloudflareChallenge, () => execute(http, input.url, input.format, "opencode")),
                  timeout,
                  Effect.catchIf(
                    (error) => authChallengeResponse(error) !== undefined,
                    (error) =>
                      Effect.gen(function* () {
                        const challenged = authChallengeResponse(error)
                        if (!challenged) return yield* Effect.fail(error)
                        const authed = yield* Effect.tryPromise(() =>
                          WebFetchAuth.handleAuthChallenge({
                            headers: challenged.headers,
                            url: input.url,
                            baseHeaders: headers(input.format, browserUserAgent),
                            store,
                            callbackServer: new WebFetchAuth.LocalCallbackServer(),
                            client: { name: "OpenCode", uri: "https://opencode.ai" },
                            interaction: {
                              askConsent: (info) =>
                                Effect.runPromise(
                                  permission.assert({
                                    action: "webfetch_auth",
                                    resources: [input.url],
                                    save: [input.url],
                                    metadata: {
                                      url: input.url,
                                      action: "authenticate",
                                      server: info.server,
                                      scopes: info.scopes?.join(", ") ?? "server default",
                                    },
                                    sessionID: context.sessionID,
                                    agent: context.agent,
                                    source,
                                  }),
                                ),
                              openUrl: WebFetchAuth.openAuthorizationUrl,
                              showDeviceCode: (info) =>
                                Effect.runPromise(
                                  permission.assert({
                                    action: "webfetch_auth",
                                    resources: [`${input.url}#device-code`],
                                    metadata: {
                                      url: input.url,
                                      action: "device_code",
                                      verification_uri: info.verification_uri,
                                      user_code: info.user_code,
                                    },
                                    sessionID: context.sessionID,
                                    agent: context.agent,
                                    source,
                                  }),
                                ),
                            },
                            preferDevice: process.env.OPENCODE_WEBFETCH_OAUTH_DEVICE === "1",
                          }),
                        ).pipe(
                          Effect.timeoutOrElse({
                            duration: Duration.seconds(WebFetchAuth.AUTH_TIMEOUT_SECONDS),
                            orElse: () => Effect.fail(new Error("Authentication timed out")),
                          }),
                        )
                        if (!authed) return yield* Effect.fail(error)
                        return fromWebResponse(input.url, input.format, authed)
                      }),
                  ),
                )
              })

              const { body, contentType } = yield* Effect.gen(function* () {
                const contentType = response.headers["content-type"] || ""
                const mime = mimeFrom(contentType)
                if (isImageAttachment(mime))
                  return yield* Effect.fail(new Error(`Unsupported fetched image content type: ${mime}`))
                if (!isTextualMime(mime))
                  return yield* Effect.fail(new Error(`Unsupported fetched file content type: ${mime}`))
                return { body: yield* collectBody(response), contentType }
              })
              const content = convert(new TextDecoder().decode(body), contentType, input.format)
              return {
                url: input.url,
                contentType,
                format: input.format,
                output: content,
              }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: `Unable to fetch ${input.url}` }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export function extractTextFromHTML(html: string) {
  let text = ""
  let skipDepth = 0
  const parser = new Parser({
    onopentag(name) {
      if (skipDepth > 0 || ["script", "style", "noscript", "iframe", "object", "embed"].includes(name)) skipDepth++
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

export function convertHTMLToMarkdown(html: string) {
  const turndown = new TurndownService({
    headingStyle: "atx",
    hr: "---",
    bulletListMarker: "-",
    codeBlockStyle: "fenced",
    emDelimiter: "*",
  })
  turndown.remove(["script", "style", "meta", "link"])
  return turndown.turndown(html)
}

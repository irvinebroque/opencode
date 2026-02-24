import z from "zod"
import { Effect } from "effect"
import { Tool } from "./tool"
import TurndownService from "turndown"
import DESCRIPTION from "./webfetch.txt"
import { abortAfterAny } from "../util/abort"
import { Log } from "../util/log"
import * as WebFetchAuth from "../auth/webfetch-auth"
import * as WwwAuthenticate from "../auth/www-authenticate"
import * as Discovery from "../auth/discovery"
import * as Flow from "../auth/flow"

const log = Log.create({ service: "webfetch" })

const MAX_RESPONSE_SIZE = 5 * 1024 * 1024 // 5MB
const DEFAULT_TIMEOUT = 30 * 1000 // 30 seconds
const MAX_TIMEOUT = 120 * 1000 // 2 minutes
const MAX_REDIRECTS = 10

/**
 * Follow redirects manually, stripping credentials when crossing origins.
 * Prevents Authorization header leakage on cross-origin 3xx chains.
 */
async function safeFetch(
  url: string,
  options: { signal: AbortSignal; headers: Record<string, string> },
  credentials: Record<string, string>,
): Promise<Response> {
  if (!Object.keys(credentials).length) {
    return fetch(url, {
      signal: options.signal,
      headers: options.headers,
    })
  }

  const origin = new URL(url).origin
  let current = url

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const response = await fetch(current, {
      signal: options.signal,
      headers: { ...options.headers, ...credentials },
      redirect: "manual",
    })

    if (response.status < 300 || response.status >= 400) {
      return response
    }

    const location = response.headers.get("location")
    if (!location) return response

    const target = new URL(location, current)
    if (target.origin !== origin) {
      log.info("cross-origin redirect, stripping credentials", {
        from: new URL(current).origin,
        to: target.origin,
      })
      return fetch(target.href, {
        signal: options.signal,
        headers: options.headers,
      })
    }
    current = target.href
  }

  throw new Error(`Too many redirects (>${MAX_REDIRECTS})`)
}

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
            const { signal, clearTimeout } = abortAfterAny(timeout, ctx.abort)

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

              // Local file lookup only; OAuth discovery runs after a 401/403 challenge.
              const auth = await WebFetchAuth.resolve(params.url)

              const initial = await safeFetch(params.url, { signal, headers }, auth)

              let response =
                initial.status === 403 && initial.headers.get("cf-mitigated") === "challenge"
                  ? await safeFetch(params.url, { signal, headers: { ...headers, "User-Agent": "opencode" } }, auth)
                  : initial

              // Clear the request timeout before entering the interactive OAuth flow.
              if (!response.ok && (response.status === 401 || response.status === 403)) {
                clearTimeout()
                const authed = await handleAuth(response, params.url, headers, ctx.abort, ctx)
                if (authed) response = authed
              } else {
                clearTimeout()
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
              clearTimeout()
            }
          })
        }).pipe(Effect.orDie),
    }
  }),
)

function credential(resource: string, tokens: Flow.TokenResult, issuer: string): WebFetchAuth.Credential {
  return {
    resource,
    scheme: "bearer",
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: tokens.expires_in ? Date.now() / 1000 + tokens.expires_in : undefined,
    scope: tokens.scope,
    oauth_client_id: tokens.client.client_id,
    oauth_client_secret: tokens.client.client_secret,
    issuer,
  }
}

async function handleAuth(
  response: Response,
  url: string,
  base: Record<string, string>,
  signal: AbortSignal,
  ctx: Tool.Context,
): Promise<Response | undefined> {
  log.info("auth required", { url, status: response.status })

  // 1. Parse WWW-Authenticate challenges — RFC 9110 §11.6.1
  //    Extract resource_metadata URL from challenge params — RFC 9728 §5.1
  const challenges = WwwAuthenticate.all(response)
  const metaUrl = WwwAuthenticate.resourceMetadataUrl(challenges)

  // 2. Discovery — RFC 9728 §4 (resource metadata) + RFC 8414 §3 (AS metadata)
  const result = await Discovery.discover(url, metaUrl ?? undefined, signal)

  if (!result.resource || !result.servers.length) {
    // Basic auth challenge without discovery — RFC 7617
    const basic = challenges.find((c) => c.scheme.toLowerCase() === "basic")
    if (basic) {
      log.info("basic auth challenge detected", { realm: basic.params["realm"] })
      throw new Error(
        `This URL requires Basic authentication (realm: ${basic.params["realm"] ?? "unknown"}). ` +
          `Configure credentials for this origin in the webfetch auth store.`,
      )
    }

    log.info("no auth discovery available", { url, challenges: challenges.length })
    return undefined
  }

  const server = result.servers[0]!

  // 3. Client resolution — stored credentials first; auth-code registration is deferred
  //    until authorizationCode() binds the callback server and knows the real port.
  let client: Flow.ClientInfo | undefined

  const existing = await WebFetchAuth.get(url).catch(() => undefined)
  if (existing?.oauth_client_id) {
    client = { client_id: existing.oauth_client_id, client_secret: existing.oauth_client_secret }
  }

  // 4. Prompt user for consent
  await Effect.runPromise(
    ctx.ask({
      permission: "webfetch",
      patterns: [url],
      always: [new URL(url).origin + "/*"],
      metadata: {
        url,
        action: "authenticate",
        server: server.issuer,
        scopes: (result.resource.scopes_supported?.join(", ") ?? "default") + " (server-reported, unverified)",
      },
    }),
  )

  // 5. Execute OAuth flow — RFC 6749 §4.1 (auth code) + RFC 7636 (PKCE)
  const supports = server.grant_types_supported ?? ["authorization_code"]
  let cred: WebFetchAuth.Credential | undefined

  if (supports.includes("authorization_code") && server.authorization_endpoint) {
    const tokens = await Flow.authorizationCode(
      url,
      result.resource,
      server,
      client,
      result.resource.scopes_supported,
    )
    if (tokens) {
      cred = credential(result.resource.resource, tokens, server.issuer)
      await WebFetchAuth.set(result.resource.resource, cred)
    }
  }

  // Fallback: Device Authorization Grant — RFC 8628 §3.1
  if (
    !cred &&
    supports.includes("urn:ietf:params:oauth:grant-type:device_code") &&
    server.device_authorization_endpoint
  ) {
    if (!client && server.registration_endpoint) {
      client = (await Flow.register(server, "http://127.0.0.1:19877/webfetch/oauth/callback")) ?? undefined
    }
    if (client) {
      const device = await Flow.deviceCode(url, result.resource, server, client, result.resource.scopes_supported)
      if (device) {
        log.info("device code flow", {
          uri: device.info.verification_uri,
          code: device.info.user_code,
        })
        const tokens = await device.poll()
        if (tokens) {
          cred = credential(result.resource.resource, tokens, server.issuer)
          await WebFetchAuth.set(result.resource.resource, cred)
        }
      }
    }
  }

  if (!cred) {
    if (!client) {
      const docs = server.service_documentation ?? server.issuer
      throw new Error(
        `This URL requires OAuth authentication via ${server.issuer}, ` +
          `but no client_id is configured and dynamic registration is not available. ` +
          `Register a client at ${docs} and configure it in opencode.json.`,
      )
    }
    throw new Error(`OAuth authentication failed for ${url}. Please try again.`)
  }

  // 6. Retry with credentials — RFC 6750 §2.1 (Bearer in Authorization header).
  //    safeFetch uses redirect: "manual" with per-hop origin checks to prevent
  //    Bearer token leakage on cross-origin redirect chains.
  const retry = await safeFetch(url, { signal, headers: base }, WebFetchAuth.headers(cred))

  if (retry.ok) return retry

  // Remove stale credentials on retry failure so the user isn't stuck
  // with a bad token on subsequent requests.
  log.error("auth retry failed, removing stale credential", { url, status: retry.status })
  await WebFetchAuth.remove(url).catch(() => {})
  return undefined
}

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

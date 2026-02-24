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

              const initial = await fetch(params.url, {
                signal,
                headers: { ...headers, ...auth },
              })

              let response =
                initial.status === 403 && initial.headers.get("cf-mitigated") === "challenge"
                  ? await fetch(params.url, {
                      signal,
                      headers: { ...headers, ...auth, "User-Agent": "opencode" },
                    })
                  : initial

              if (!response.ok && (response.status === 401 || response.status === 403)) {
                const authed = await handleAuth(response, params.url, headers, signal, ctx)
                if (authed) response = authed
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

// Auth orchestration lives here to avoid a circular import between
// `webfetch-auth.ts` and `flow.ts`.
async function handleAuth(
  response: Response,
  url: string,
  base: Record<string, string>,
  signal: AbortSignal,
  ctx: Tool.Context,
): Promise<Response | undefined> {
  log.info("auth required", { url, status: response.status })

  // 1. Parse WWW-Authenticate challenges — RFC 9110 §11.6.1
  //    Extract resource_metadata URL from Bearer challenge — RFC 9728 §5.1
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

  // 3. Client resolution — RFC 7591 §2 (dynamic registration) or stored credentials.
  //    Registration is NOT done here for auth code flow — it is deferred to
  //    authorizationCode() which registers after the callback server binds,
  //    ensuring the redirect_uri port matches the actual listening port.
  let client: Flow.ClientInfo | undefined

  const existing = await WebFetchAuth.get(url).catch(() => undefined)
  if (existing?.oauth_client_id) {
    client = { client_id: existing.oauth_client_id, client_secret: existing.oauth_client_secret }
  }

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
    cred = await Flow.authorizationCode(
      url,
      result.resource,
      server,
      client,
      result.resource.scopes_supported,
    )
  }

  // Fallback: Device Authorization Grant — RFC 8628 §3.1
  if (
    !cred &&
    supports.includes("urn:ietf:params:oauth:grant-type:device_code") &&
    server.device_authorization_endpoint
  ) {
    // Register for device code if no client yet (device code doesn't use redirect_uri
    // in the flow itself, so the hardcoded port is acceptable for registration metadata)
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
        cred = await device.poll()
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
  //    Use redirect: "manual" to prevent Bearer token leakage to cross-origin
  //    redirect targets. The Fetch spec says cross-origin redirects strip
  //    Authorization, but runtime behavior varies.
  const retry = await fetch(url, {
    signal,
    headers: { ...base, ...WebFetchAuth.headers(cred) },
    redirect: "manual",
  })

  if (retry.ok) return retry

  // Handle redirects: only forward credentials to same-origin targets
  if (retry.status >= 300 && retry.status < 400) {
    const location = retry.headers.get("location")
    if (location) {
      const target = new URL(location, url)
      const origin = new URL(url).origin
      if (target.origin === origin) {
        return fetch(target.href, {
          signal,
          headers: { ...base, ...WebFetchAuth.headers(cred) },
        })
      }
      // Cross-origin redirect — follow without credentials
      log.info("cross-origin redirect, stripping credentials", {
        from: origin,
        to: target.origin,
      })
      return fetch(target.href, { signal, headers: base })
    }
  }

  log.error("auth retry failed", { url, status: retry.status })
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

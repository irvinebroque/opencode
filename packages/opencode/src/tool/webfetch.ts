import z from "zod"
import { Tool } from "./tool"
import TurndownService from "turndown"
import DESCRIPTION from "./webfetch.txt"
import { abortAfterAny } from "../util/abort"
import { Log } from "../util/log"
import { store, resolveCredentials } from "../auth/webfetch-auth"
import { handleAuthChallenge } from "../auth/orchestrate"
import { LocalCallbackServer } from "../auth/flow"
import type { Interaction } from "../auth/flow"

const log = Log.create({ service: "webfetch" })

const MAX_RESPONSE_SIZE = 5 * 1024 * 1024 // 5MB
const DEFAULT_TIMEOUT = 30 * 1000 // 30 seconds
const MAX_TIMEOUT = 120 * 1000 // 2 minutes

export const WebFetchTool = Tool.define("webfetch", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("The URL to fetch content from"),
    format: z
      .enum(["text", "markdown", "html"])
      .default("markdown")
      .describe("The format to return the content in (text, markdown, or html). Defaults to markdown."),
    timeout: z.number().describe("Optional timeout in seconds (max 120)").optional(),
  }),
  async execute(params, ctx) {
    // Validate URL
    if (!params.url.startsWith("http://") && !params.url.startsWith("https://")) {
      throw new Error("URL must start with http:// or https://")
    }

    await ctx.ask({
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

    const timer = abortAfterAny(timeout, ctx.abort)

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
        acceptHeader = "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1"
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

    // Layer 1: resolve stored credentials (local lookup, auto-refresh)
    const auth = await resolveCredentials(params.url, store, log)

    const probe = await fetch(params.url, {
      signal: timer.signal,
      redirect: "manual",
      headers: { ...headers, ...auth },
    })

    // Retry with honest UA if blocked by Cloudflare bot detection (TLS fingerprint mismatch)
    let response =
      probe.status === 403 && probe.headers.get("cf-mitigated") === "challenge"
        ? await fetch(params.url, {
            signal: timer.signal,
            redirect: "manual",
            headers: { ...headers, ...auth, "User-Agent": "opencode" },
          })
        : probe

    // Auth handling: detect explicit WWW-Authenticate challenges and
    // attempt RFC 9728/8414 authentication.
    // Trigger on redirect statuses too because some servers return the
    // auth challenge on 302 instead of 401/403.
    // Only trigger on 403 if the server explicitly sent a WWW-Authenticate
    // header — a bare 403 means "forbidden" (not an auth challenge) and a
    // malicious server could abuse it to social-engineer the user into
    // authenticating with a legitimate OAuth provider.
    // Clear the request timeout before entering the OAuth flow — the interactive
    // browser authorization may take minutes, and the 30s/120s timeout would
    // abort the signal mid-flow. The retry fetch uses ctx.abort instead.
    const challenge = response.headers.has("www-authenticate")
    const redirect = response.status >= 300 && response.status < 400
    const tryAuth = response.status === 401 || (response.status === 403 && challenge) || (redirect && challenge)
    async function follow() {
      let next = await fetch(params.url, {
        signal: ctx.abort,
        headers: { ...headers, ...auth },
      })
      if (next.status === 403 && next.headers.get("cf-mitigated") === "challenge") {
        next = await fetch(params.url, {
          signal: ctx.abort,
          headers: { ...headers, ...auth, "User-Agent": "opencode" },
        })
      }
      return next
    }
    if (!response.ok && tryAuth) {
      timer.clearTimeout()

      // Build Interaction implementation for opencode
      const interaction: Interaction = {
        async askConsent(info) {
          await ctx.ask({
            permission: "webfetch",
            patterns: [params.url],
            always: [new URL(params.url).origin + "/*"],
            metadata: {
              url: params.url,
              action: "authenticate",
              server: info.server,
              scopes: (info.scopes?.join(", ") ?? "default") + " (server-reported, unverified)",
              ...(new URL(params.url).origin !== new URL(info.server).origin && {
                warning:
                  `Cross-origin auth: ${new URL(params.url).host} directs authentication to ${new URL(info.server).host}. ` +
                  `The resulting token will be sent to ${new URL(params.url).host}.`,
              }),
            },
          })
        },
        async openUrl(url) {
          // Lazy import: only load `open` when OAuth is actually triggered
          await (await import("open")).default(url)
        },
        // TODO: integrate device code display into TUI so the user sees the code
        async showDeviceCode(info) {
          log.info("device code flow", {
            uri: info.verification_uri,
            code: info.user_code,
          })
        },
      }

      let authed: Response | undefined
      let error: unknown
      try {
        authed = await handleAuthChallenge({
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
      } catch (cause) {
        error = cause
      }
      if (authed) response = authed
      if (!authed && error) throw error
      if (!authed && redirect) {
        response = await follow()
      }
    } else {
      timer.clearTimeout()

      // No auth challenge; perform a normal fetch that follows redirects.
      if (redirect) {
        response = await follow()
      }
    }

    if (!response.ok) {
      throw new Error(`Request failed with status code: ${response.status}`)
    }

    // Check content length
    const contentLength = response.headers.get("content-length")
    if (contentLength && parseInt(contentLength) > MAX_RESPONSE_SIZE) {
      throw new Error("Response too large (exceeds 5MB limit)")
    }

    const arrayBuffer = await response.arrayBuffer()
    if (arrayBuffer.byteLength > MAX_RESPONSE_SIZE) {
      throw new Error("Response too large (exceeds 5MB limit)")
    }

    const contentType = response.headers.get("content-type") || ""
    const mime = contentType.split(";")[0]?.trim().toLowerCase() || ""
    const title = `${params.url} (${contentType})`

    // Check if response is an image
    const isImage = mime.startsWith("image/") && mime !== "image/svg+xml" && mime !== "image/vnd.fastbidsheet"

    if (isImage) {
      const base64Content = Buffer.from(arrayBuffer).toString("base64")
      return {
        title,
        output: "Image fetched successfully",
        metadata: {},
        attachments: [
          {
            type: "file",
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
        return {
          output: content,
          title,
          metadata: {},
        }

      case "text":
        if (contentType.includes("text/html")) {
          const text = await extractTextFromHTML(content)
          return {
            output: text,
            title,
            metadata: {},
          }
        }
        return {
          output: content,
          title,
          metadata: {},
        }

      case "html":
        return {
          output: content,
          title,
          metadata: {},
        }

      default:
        return {
          output: content,
          title,
          metadata: {},
        }
    }
  },
})

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

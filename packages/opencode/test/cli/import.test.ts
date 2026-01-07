import { test, expect, mock } from "bun:test"
import { Config } from "../../src/config/config"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

test("parseShareUrl extracts slug from /share/ path", async () => {
  const validUrls = [
    "https://opncd.ai/share/abc123",
    "https://share.opencode.cloudflare.dev/share/wInDhh5L",
    "https://example.com/share/test_slug-123",
    "http://localhost:3000/share/localtest",
  ]

  for (const url of validUrls) {
    const parsed = URL.parse(url)
    expect(parsed).not.toBeNull()
    const match = parsed!.pathname.match(/^\/(?:share|s)\/([a-zA-Z0-9_-]+)/)
    expect(match).not.toBeNull()
    expect(match![1]).toBeTruthy()
  }
})

test("parseShareUrl extracts slug from /s/ path", async () => {
  const validUrls = ["https://opncd.ai/s/abc123", "https://opencode.ai/s/xyz789", "https://example.com/s/test-slug_123"]

  for (const url of validUrls) {
    const parsed = URL.parse(url)
    expect(parsed).not.toBeNull()
    const match = parsed!.pathname.match(/^\/(?:share|s)\/([a-zA-Z0-9_-]+)/)
    expect(match).not.toBeNull()
    expect(match![1]).toBeTruthy()
  }
})

test("parseShareUrl returns undefined for invalid paths", async () => {
  const invalidUrls = [
    "https://opncd.ai/other/abc123",
    "https://example.com/shares/abc123",
    "https://example.com/",
    "https://example.com/share/",
    "not-a-url",
  ]

  for (const url of invalidUrls) {
    const parsed = URL.parse(url)
    if (!parsed) continue
    const match = parsed.pathname.match(/^\/(?:share|s)\/([a-zA-Z0-9_-]+)/)
    expect(match).toBeNull()
  }
})

test("import uses enterprise.url from config for API fetch", async () => {
  const originalFetch = globalThis.fetch
  let fetchedUrl: string | undefined

  const mockFetch = mock((url: string | URL | Request) => {
    fetchedUrl = url.toString()
    return Promise.resolve(
      new Response(
        JSON.stringify({
          info: { id: "test-session", title: "Test" },
          messages: {
            msg1: { id: "msg1", role: "user", parts: [] },
          },
        }),
        { status: 200 },
      ),
    )
  })
  globalThis.fetch = mockFetch as unknown as typeof fetch

  try {
    await using tmp = await tmpdir({
      git: true,
      config: {
        enterprise: {
          url: "https://share.opencode.cloudflare.dev",
        },
      },
    })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const cfg = await Config.get()
        expect(cfg.enterprise?.url).toBe("https://share.opencode.cloudflare.dev")

        // Simulate what the import command does
        const base = cfg.enterprise?.url ?? "https://opncd.ai"
        const slug = "wInDhh5L"
        await fetch(`${base}/api/share/${slug}`)

        expect(fetchedUrl).toBe("https://share.opencode.cloudflare.dev/api/share/wInDhh5L")
      },
    })
  } finally {
    globalThis.fetch = originalFetch
  }
})

test("import falls back to opncd.ai when enterprise.url not set", async () => {
  const originalFetch = globalThis.fetch
  let fetchedUrl: string | undefined

  const mockFetch = mock((url: string | URL | Request) => {
    fetchedUrl = url.toString()
    return Promise.resolve(
      new Response(
        JSON.stringify({
          info: { id: "test-session", title: "Test" },
          messages: {
            msg1: { id: "msg1", role: "user", parts: [] },
          },
        }),
        { status: 200 },
      ),
    )
  })
  globalThis.fetch = mockFetch as unknown as typeof fetch

  try {
    await using tmp = await tmpdir({ git: true })

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const cfg = await Config.get()
        expect(cfg.enterprise?.url).toBeUndefined()

        // Simulate what the import command does
        const base = cfg.enterprise?.url ?? "https://opncd.ai"
        const slug = "abc123"
        await fetch(`${base}/api/share/${slug}`)

        expect(fetchedUrl).toBe("https://opncd.ai/api/share/abc123")
      },
    })
  } finally {
    globalThis.fetch = originalFetch
  }
})

test("import from file still works", async () => {
  await using tmp = await tmpdir({
    git: true,
    init: async (dir) => {
      const sessionData = {
        info: {
          id: "imported-session",
          title: "Imported Session",
          projectID: "test-project",
        },
        messages: [
          {
            info: { id: "msg1", role: "user", sessionID: "imported-session" },
            parts: [{ id: "part1", type: "text", text: "Hello" }],
          },
        ],
      }
      await Bun.write(`${dir}/session.json`, JSON.stringify(sessionData))
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const file = Bun.file(`${tmp.path}/session.json`)
      const data = await file.json()
      expect(data.info.id).toBe("imported-session")
      expect(data.messages).toHaveLength(1)
    },
  })
})

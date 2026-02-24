# Auth Package Extraction Plan

This document covers the changes needed to make `src/auth/` work as a standalone package, and the corresponding changes in opencode to consume it through the new interfaces.

## 1. Storage

### Current state

Credential persistence is hardcoded to a JSON file at a fixed XDG path.

- `webfetch-auth.ts:18` — `const filepath = path.join(Global.Path.data, "webfetch-auth.json")`
- `webfetch-auth.ts:13` — imports `Global` from `../global` (opencode-specific)
- `webfetch-auth.ts:49-55` — `load()` reads the JSON file with `Bun.file(filepath).text()`
- `webfetch-auth.ts:57-66` — `save()` does atomic write with `writeFile` + `rename`, `0o600` permissions, `0o700` parent directory
- `webfetch-auth.ts:78-106` — `get()` implements a three-tier lookup: exact URL match, origin match, longest path-prefix match (path-segment-boundary-aware)
- `webfetch-auth.ts:113-120` — `set()` writes to the file
- `webfetch-auth.ts:127-134` — `remove()` deletes from the file
- `webfetch-auth.ts:22-31` — in-memory mutex (`serialized()`) prevents TOCTOU races on concurrent token refreshes

### Problem

Any consumer that isn't opencode would need to either adopt the same XDG file layout or fork the module. The file-based store is also inappropriate for environments where credentials should go to OS keychain, encrypted storage, or in-memory-only (ephemeral CI jobs).

### Plan

#### In the auth package

Define a `CredentialStore` interface:

```ts
interface CredentialStore {
  get(resource: string): Promise<Credential | undefined>
  set(resource: string, cred: Credential): Promise<void>
  remove(resource: string): Promise<void>
}
```

The three-tier lookup logic in `get()` (`webfetch-auth.ts:78-106` — exact match, origin match, longest prefix match) should stay inside the package as a utility that wraps any `CredentialStore`. This matching logic is part of the RFC 6750 protection space semantics, not an implementation detail of the file store.

The `Credential` type (`webfetch-auth.ts:33-45`) stays in the package unchanged.

The `expired()`, `refresh()`, `headers()`, and `resolve()` functions (`webfetch-auth.ts:141-266`) all operate on `Credential` values and a `CredentialStore` — they should accept the store as a parameter instead of using the module-level file store.

The `serialized()` mutex (`webfetch-auth.ts:22-31`) should move into the package's built-in file store implementation as a reference/default, but not be imposed on all stores. Consumers with their own concurrency model (e.g., a database-backed store with transactions) shouldn't be forced through an in-memory JS mutex.

#### In opencode

Move the current file-based implementation into a `FileCredentialStore` that implements the interface. It keeps:
- The XDG path resolution via `Global.Path.data`
- The atomic write pattern (`webfetch-auth.ts:57-66`)
- The `0o600`/`0o700` permission model
- The in-memory mutex

Pass `FileCredentialStore` to the auth package at the call sites in `tool/webfetch.ts` and `orchestrate.ts`.


## 2. User Interaction

### Current state

There are three distinct user-facing interactions during an OAuth flow, each handled differently:

**Consent prompt**: `orchestrate.ts:92-102` calls `ask()` (the `AskFn` type at `orchestrate.ts:25-30`) to get the user's permission before authenticating. This is already a clean callback — the consumer provides it.

**Open browser**: `flow.ts:702-708` calls `Bun.spawn([open, authUrl])` directly, choosing between `open`/`start`/`xdg-open` based on `process.platform`. No error detection. No fallback. If it fails (SSH, container, no display), the user never sees the authorization URL.

**Show device code**: `orchestrate.ts:136-139` logs the device code info via the structured logger (`log.info("device code flow", { uri, code })`). This is invisible to the user unless they're watching debug logs. There is no mechanism to surface the verification URI and user code through the UI.

### How MCP does it better

The MCP auth flow at `mcp/index.ts:809-834` handles browser failure gracefully:

1. It calls `open(authorizationUrl)` (the `open` npm package)
2. It waits 500ms for the subprocess to fail (`mcp/index.ts:815-828`)
3. On failure, it publishes a `BrowserOpenFailed` event on the bus (`mcp/index.ts:833`)
4. The CLI subscribes to that event and shows the URL for manual opening (`cli/cmd/mcp.ts:233-239`)

This is better because the auth layer doesn't decide how to present the URL — it signals that a URL needs to be shown, and the UI layer (TUI, web app, VS Code extension) decides how to show it.

But it's still not a clean abstraction. The MCP flow hardcodes the `open` npm package and the bus event system, which are both opencode internals.

### Plan

#### In the auth package

Replace all three interaction points with a single `Interaction` interface:

```ts
interface Interaction {
  /** The user needs to visit this URL to authorize. The consumer decides how. */
  openUrl(url: string): Promise<void>

  /** A device code flow requires the user to visit a URL and enter a code. */
  showDeviceCode(info: { verification_uri: string; user_code: string }): Promise<void>
}
```

`openUrl` replaces the `Bun.spawn([open, authUrl])` call at `flow.ts:702-708`. The package doesn't know or care whether the consumer opens a browser, publishes a bus event, renders a QR code, or prints a line to stdout.

`showDeviceCode` replaces the `log.info()` call at `orchestrate.ts:136-139`. The consumer decides how to surface this — TUI prompt, web UI notification, etc.

The existing `AskFn` in `orchestrate.ts:25-30` handles consent. It could either stay as a separate parameter (it's already clean) or fold into the `Interaction` interface. Keeping it separate is reasonable since consent is conceptually different from "show the user a thing."

Remove `flow.ts:702-708` (the `Bun.spawn` call) and `flow.ts:186-227` (the HTML templates). The callback server HTML should also be provided by the consumer or use sensible defaults that aren't branded "OpenCode."

#### In opencode

Implement the `Interaction` interface:

- `openUrl`: try the `open` npm package (like MCP does at `mcp/index.ts:810`), detect failure (like `mcp/index.ts:815-828`), fall back to publishing a bus event (like `mcp/index.ts:833`). This is the MCP pattern, generalized.
- `showDeviceCode`: publish a bus event that the TUI/web UI subscribes to, similar to `BrowserOpenFailed` but for device codes. The TUI can show a prompt like the Copilot plugin does (`plugin/copilot.ts:200-260`).


## 3. Callback Server

### Current state

`flow.ts:598-722` (`callbackServer()`) implements a local HTTP server for receiving the OAuth authorization code callback. It:

1. Binds to `127.0.0.1` starting at port 19877 (`flow.ts:32`), tries up to 10 ports on conflict (`flow.ts:623-682`)
2. Validates the `state` parameter for CSRF protection (`flow.ts:640-645`)
3. Serves branded HTML success/error pages (`flow.ts:186-227`)
4. Has a 5-minute timeout (`flow.ts:34`, `flow.ts:715-719`)
5. Calls `buildAuthUrl(port)` after binding so the `redirect_uri` port matches the actual listening port (`flow.ts:685-689`). This is important — registration is deferred to this point so the `redirect_uri` in the dynamic client registration matches too (`flow.ts:297-302`)

The server is scoped to each flow invocation (not module-level), which correctly allows concurrent OAuth flows (`flow.ts:603-604`).

### Problem

This only works when the OAuth redirect can reach `127.0.0.1` on the machine running the auth flow. In a remote container, the redirect hits the user's browser, which tries to connect to `127.0.0.1` — but the server is in the container, not on the user's machine. Port forwarding can make this work but the user has to know to set it up, and the port is unpredictable (19877-19886).

The callback server is also tightly coupled to Bun (`Bun.serve` at `flow.ts:625`) and the branded HTML.

### Plan

#### In the auth package

Define a `CallbackServer` interface:

```ts
interface CallbackServer {
  /** Start the server, return the redirect URI the AS should send the user back to. */
  start(): Promise<{ redirectUri: string }>

  /** Wait for the authorization code. Reject on timeout or error. */
  waitForCode(expectedState: string): Promise<string>

  /** Stop the server. */
  stop(): Promise<void>
}
```

The package provides a default `LocalCallbackServer` implementation that does what `flow.ts:598-722` does today, but with configurable options:

```ts
interface LocalCallbackServerOptions {
  port?: number           // default 19877
  hostname?: string       // default "127.0.0.1"
  path?: string           // default "/oauth/callback"
  portRetries?: number    // default 10
  timeout?: number        // default 300000 (5 min)
  html?: {
    success?: string
    error?: (msg: string) => string
  }
}
```

The `authorizationCode()` function (`flow.ts:265-381`) accepts a `CallbackServer` instead of calling `callbackServer()` directly. The deferred registration pattern (`flow.ts:297-302` — register after port is known) works naturally: `authorizationCode` calls `server.start()`, gets the `redirectUri`, then registers if needed.

#### In opencode

For local dev: use the default `LocalCallbackServer` with opencode-branded HTML.

For remote/headless: consumers could implement `CallbackServer` to proxy through the web UI the user is already connected to (the opencode server at `server/server.ts` already proxies to `app.opencode.ai`), or skip the callback server entirely and use device code flow only. The `Interaction.openUrl` hook gives the consumer control to detect the environment and choose.


## 4. Fetch Wrapper

### Current state

`webfetch-auth.ts:252-266` has a `resolve()` function that looks up stored credentials, refreshes expired tokens, and returns auth headers:

```ts
export async function resolve(url: string): Promise<Record<string, string>> {
  const cred = await get(url).catch(() => undefined)
  if (!cred) return {}
  if (expired(cred) && cred.refresh_token && cred.issuer) {
    const as = await fetchASMetadata(cred.issuer)
    if (as) {
      const refreshed = await refresh(cred, as)
      if (refreshed) return headers(refreshed)
    }
  }
  if (!expired(cred)) return headers(cred)
  return {}
}
```

The consumer (`tool/webfetch.ts:71-73`) calls this, then manually merges the headers and makes the fetch. On 401/403, it calls `handleAuth()` (`tool/webfetch.ts:92-95`) to run the full OAuth flow and retry:

```ts
const auth = await WebFetchAuth.resolve(params.url)
const initial = await fetch(params.url, { signal, headers: { ...headers, ...auth } })
// ...
if (!response.ok && tryAuth) {
  const authed = await handleAuth(response, params.url, headers, ctx.abort, ctx.ask.bind(ctx))
  if (authed) response = authed
}
```

### Problem

Every consumer has to reimplement this three-step dance: resolve credentials, make request, handle 401 retry. The auth package should provide a `fetch`-compatible wrapper that does this automatically.

### Plan

#### In the auth package

Provide a factory that creates an authenticated `fetch`:

```ts
function createAuthenticatedFetch(options: {
  store: CredentialStore
  interaction: Interaction
  callbackServer?: CallbackServer
  ask?: AskFn
}): typeof fetch
```

The returned function:

1. Looks up stored credentials and attaches them (what `resolve()` does today)
2. Makes the request
3. On 401/403 with `WWW-Authenticate`, runs the full discovery + OAuth flow (what `handleAuth()` does today)
4. Retries with the new credentials
5. Returns the response

This wraps the entire `orchestrate.ts` flow into a single `fetch` call. The consumer doesn't need to know about discovery, flow selection, or retry logic.

The raw functions (`resolve`, `handleAuth`, `authorizationCode`, `deviceCode`, etc.) should still be exported for consumers who need fine-grained control. The `fetch` wrapper is a convenience layer on top.

#### In opencode

`tool/webfetch.ts` replaces the manual resolve + fetch + handleAuth dance with a single call to the authenticated fetch. The tool still handles its own concerns (URL validation, content-type negotiation, HTML-to-markdown conversion, response size limits) — just the auth part gets simpler:

```ts
// before
const auth = await WebFetchAuth.resolve(params.url)
const initial = await fetch(params.url, { signal, headers: { ...headers, ...auth } })
// ... 401 handling ...

// after
const authenticatedFetch = createAuthenticatedFetch({ store, interaction, ask: ctx.ask })
const response = await authenticatedFetch(params.url, { signal, headers })
```


## 5. Logging

### Current state

Every module imports opencode's structured logger:

- `orchestrate.ts:17` — `import { Log } from "../util/log"`
- `flow.ts:27` — `import { Log } from "../util/log"`
- `discovery.ts:19` — `import { Log } from "../util/log"`
- `webfetch-auth.ts:14` — `import { Log } from "../util/log"`

Each creates a service-tagged logger instance (`Log.create({ service: "webfetch.auth" })` etc.) and uses `log.info()`, `log.warn()`, `log.error()` throughout.

### Plan

#### In the auth package

Accept an optional logger at initialization. Define a minimal interface:

```ts
interface Logger {
  info(message: string, data?: Record<string, unknown>): void
  warn(message: string, data?: Record<string, unknown>): void
  error(message: string, data?: Record<string, unknown>): void
}
```

Default to a no-op logger if none is provided. This is a one-line change at each `Log.create()` call site — accept the logger from the options object passed through from the top-level factory.

#### In opencode

Pass `Log.create({ service: "webfetch.auth" })` as the logger when initializing the auth package. No behavior change.


## 6. What stays in the package unchanged

These modules have no opencode dependencies and are already general-purpose:

- **`www-authenticate.ts`** — RFC 9110 parser. Only internal dependency is `isLoopback` from `discovery.ts`. No `Log`, no `Global`, no file I/O.
- **`discovery.ts`** — RFC 9728/8414 discovery. Only imports `Log` (addressed above). All the SSRF protection, URL validation, metadata parsing, and field validation is standard OAuth infrastructure.
- **PKCE and state generation** — `flow.ts:74-85`. Pure crypto, no dependencies.
- **Dynamic client registration** — `flow.ts:113-166`. Only imports `Log` and `requireHttps` from discovery.
- **Device code flow** — `flow.ts:404-576`. Only imports `Log` and discovery types.
- **Token refresh** — `webfetch-auth.ts:156-217`. Operates on `Credential` + `ASMetadata`, no file I/O (storage handled separately).
- **Credential type and header builder** — `webfetch-auth.ts:33-246`. Pure data transformation.


## 7. What does NOT move into the package

- **`index.ts`** (the `Auth` namespace) — provider credential store for LLM API keys/OAuth. This is opencode-specific and stays in opencode.
- **`OAUTH_DUMMY_KEY`** — Codex plugin workaround.
- **Branded HTML** — the "OpenCode - Authorization Successful" pages. The package provides a default or accepts HTML from the consumer.
- **`Bun.spawn([open, authUrl])`** — replaced by `Interaction.openUrl`.
- **`Global.Path.data`** — replaced by the `CredentialStore` interface.
- **`Log` from `../util/log`** — replaced by the `Logger` interface.
- **`Filesystem` from `../util/filesystem`** — only used in `index.ts` which isn't moving.


## 8. Dependency summary

After extraction, the auth package's external dependencies:

| Dependency | Used for |
|---|---|
| `crypto.subtle` | PKCE S256 challenge (Web Crypto API, available in Node/Bun/Deno) |
| `node:dns` | SSRF protection in `discovery.ts:230-242` (`isPrivateNetwork` resolves DNS to check for rebinding) |
| `fetch` | All HTTP operations (globally available in Node 18+/Bun/Deno) |

No npm dependencies. No runtime-specific APIs (Bun, Node, Deno) except `node:dns` for SSRF checks.

The callback server default implementation would use `node:http` (or accept a server factory) instead of `Bun.serve` to avoid a Bun dependency.

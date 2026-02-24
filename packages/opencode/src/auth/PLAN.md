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

### Plan

#### In the auth package

Define a `CredentialStore` interface:

```ts
interface CredentialStore {
  get(resource: string): Promise<Credential | undefined>
  set(resource: string, cred: Credential): Promise<void>
  remove(resource: string): Promise<void>
  all(): Promise<Record<string, Credential>>
}
```

The `all()` method is required because the three-tier URL matching logic in `webfetch-auth.ts:78-106` (exact match, origin match, longest prefix match) iterates over every stored credential. Without `all()`, the package can't implement prefix matching on top of an opaque store.

The three-tier lookup stays in the package as a function that calls `store.all()` and applies matching. This logic is part of RFC 6750 protection space semantics, not a storage implementation detail — every store backend needs the same matching behavior.

The `Credential` type (`webfetch-auth.ts:33-45`) stays in the package unchanged.

The `expired()` and `headers()` functions (`webfetch-auth.ts:141-246`) are pure — they operate on `Credential` values with no I/O. They stay in the package unchanged.

The `refresh()` function (`webfetch-auth.ts:156-217`) is NOT pure — it makes an HTTP call to the token endpoint and writes the updated credential to the store via `set()` at line 215. It needs to accept a `CredentialStore` parameter instead of calling the module-level `set()`.

The `resolve()` function (`webfetch-auth.ts:252-266`) reads from the store and may call `fetchASMetadata` over the network. It needs to accept a `CredentialStore` parameter.

The `serialized()` mutex (`webfetch-auth.ts:22-31`) should not be part of the `CredentialStore` contract. Consumers with their own concurrency model (database transactions, OS keychain APIs) shouldn't be forced through an in-memory JS mutex. The file-based implementation in opencode keeps its own mutex.

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

Define an `Interaction` interface that covers all user-facing touchpoints:

```ts
interface Interaction {
  /** Ask user for consent before authenticating. Reject to deny. */
  askConsent(info: { resource: string; server: string; scopes?: string[] }): Promise<void>

  /** The user needs to visit this URL to authorize. The consumer decides how. */
  openUrl(url: string): Promise<void>

  /** A device code flow requires the user to visit a URL and enter a code. */
  showDeviceCode(info: { verification_uri: string; user_code: string }): Promise<void>
}
```

Consent folds into `Interaction` rather than remaining a separate `AskFn`. The current `AskFn` shape (`orchestrate.ts:25-30`) is opencode-specific — it carries `permission`, `patterns`, `always`, and `metadata` fields that are tied to opencode's permission system. The standalone package doesn't need that. It needs "ask the user if they want to authenticate with this server" — which is `askConsent`.

`openUrl` replaces the `Bun.spawn([open, authUrl])` call at `flow.ts:702-708`. The package doesn't know or care whether the consumer opens a browser, publishes a bus event, renders a QR code, or prints a line to stdout.

`showDeviceCode` replaces the `log.info()` call at `orchestrate.ts:136-139`. The consumer decides how to surface this — TUI prompt, web UI notification, etc.

The authorization URL scheme validation at `flow.ts:691-699` (which blocks `file:///`, custom schemes, non-HTTPS non-loopback URLs) stays in the package. It runs before calling `interaction.openUrl()` and rejects the flow if the URL is unsafe. The consumer's `openUrl` implementation only receives already-validated URLs.

#### In opencode

Implement the `Interaction` interface:

- `askConsent`: delegates to the existing permission system (`ctx.ask` in `tool/webfetch.ts:32-41`), translating the package's consent info into opencode's permission format.
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
6. Opens the browser via `Bun.spawn` (`flow.ts:702-708`)

The server is scoped to each flow invocation (not module-level), which correctly allows concurrent OAuth flows (`flow.ts:603-604`).

### Problem

This only works when the OAuth redirect can reach `127.0.0.1` on the machine running the auth flow. In a remote container, the redirect hits the user's browser, which tries to connect to `127.0.0.1` — but the server is in the container, not on the user's machine. Port forwarding can make this work but the user has to know to set it up, and the port is unpredictable (19877-19886).

The server is also tightly coupled to `Bun.serve` (`flow.ts:625`), `Bun.spawn` for browser opening (`flow.ts:708`), and branded "OpenCode" HTML.

### Plan

#### In the auth package

Define a `CallbackServer` interface:

```ts
interface CallbackServer {
  /** Start the server. Returns the redirect URI the AS should send the user back to. */
  start(): Promise<{ redirectUri: string }>

  /**
   * Wait for the authorization code callback.
   * The implementation is responsible for state/CSRF validation.
   * Must reject on timeout or error. Must call stop() internally on completion.
   */
  waitForCode(expectedState: string): Promise<string>

  /** Stop the server and clean up. Safe to call multiple times. */
  stop(): Promise<void>
}
```

`waitForCode` owns CSRF validation and cleanup. This avoids the footgun where a consumer forgets to call `stop()` — the implementation handles it in both the success and error paths, matching the current behavior where `callbackServer()` auto-cleans via `setTimeout(cleanup, 500)` at `flow.ts:651-668`.

The package provides a default `LocalCallbackServer` implementation with configurable options:

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

The default `LocalCallbackServer` uses `node:http` (not `Bun.serve`) for portability. See section 8 for the runtime dependency discussion.

The `authorizationCode()` function (`flow.ts:265-381`) accepts both a `CallbackServer` and an `Interaction`. The flow becomes:

1. `server.start()` → get `redirectUri`
2. Register client with that `redirectUri` if needed (deferred registration, currently at `flow.ts:297-302`)
3. Build authorization URL
4. Validate URL scheme (currently `flow.ts:691-699`)
5. `interaction.openUrl(authUrl)`
6. `server.waitForCode(state)` → get authorization code
7. Exchange code for tokens

This preserves the deferred registration pattern: registration happens after the port is known because `start()` returns the actual `redirectUri`.

#### Device code registration

`orchestrate.ts:131` hardcodes `http://127.0.0.1:19877/webfetch/oauth/callback` when registering a client for the device code flow. This is wrong with a custom callback server. The fix: if a `CallbackServer` is provided, call `server.start()` to get the `redirectUri` for registration, then `server.stop()` (the device code flow doesn't use the callback server itself, but the redirect URI is needed for the registration request). If no `CallbackServer` is provided, skip registration and require a pre-configured `client_id`.

#### In opencode

For local dev: use the default `LocalCallbackServer` with opencode-branded HTML.

For remote/headless: consumers could implement `CallbackServer` to proxy through their own infrastructure, or skip it entirely (pass `undefined`) to force device code flow only. The `Interaction.openUrl` hook gives the consumer control to detect the environment and choose.


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

The consumer (`tool/webfetch.ts:71-94`) calls this, then manually merges the headers, makes the fetch, and on 401/403 calls `handleAuth()` to run the full OAuth flow and retry:

```ts
const auth = await WebFetchAuth.resolve(params.url)
const initial = await fetch(params.url, { signal, headers: { ...headers, ...auth } })
// ... cloudflare retry ...
if (!response.ok && tryAuth) {
  clearTimeout()
  const authed = await handleAuth(response, params.url, headers, ctx.abort, ctx.ask.bind(ctx))
  if (authed) response = authed
}
```

`handleAuth()` at `orchestrate.ts:163` also does its own retry fetch after obtaining credentials.

### Plan

#### In the auth package

Do NOT provide a `fetch`-compatible wrapper that returns `typeof fetch`. An OAuth flow may open a browser, prompt for consent, spin up an HTTP server, and block for minutes. Hiding that behind `fetch` semantics is deceptive.

Instead, provide two layers:

**Layer 1: Credential resolution** (what `resolve()` does today). A function that takes a URL and a `CredentialStore`, looks up credentials, refreshes if expired, and returns headers. This is non-interactive and fast:

```ts
function resolveCredentials(
  url: string,
  store: CredentialStore,
  logger?: Logger,
): Promise<Record<string, string>>
```

**Layer 2: Auth orchestration** (what `handleAuth()` does today). A function that takes a 401/403 response and runs the full interactive OAuth flow — discovery, consent, browser auth or device code, token exchange, credential storage, retry. The consumer calls this explicitly when they decide to handle an auth challenge:

```ts
function handleAuthChallenge(options: {
  response: Response
  url: string
  baseHeaders: Record<string, string>
  signal: AbortSignal
  store: CredentialStore
  interaction: Interaction
  callbackServer?: CallbackServer
  client?: ClientRegistration
  logger?: Logger
}): Promise<Response | undefined>
```

The retry fetch at `orchestrate.ts:163` stays inside `handleAuthChallenge`. It's the package's responsibility to verify that the obtained credentials actually work before returning.

The 401-vs-403 distinction (only auth on 403 if `www-authenticate` is present, per `tool/webfetch.ts:89-91`) stays in the consumer. The consumer decides when to call `handleAuthChallenge` — the package doesn't intercept arbitrary responses.

#### In opencode

`tool/webfetch.ts` keeps its current structure but calls the package's two functions instead of importing the internal modules:

```ts
// Layer 1: attach stored credentials
const auth = await resolveCredentials(params.url, store, logger)
const response = await fetch(params.url, { signal, headers: { ...headers, ...auth } })

// Consumer decides when to trigger auth (401 always, 403 only with www-authenticate)
if (!response.ok && tryAuth) {
  clearTimeout()
  const authed = await handleAuthChallenge({
    response, url: params.url, baseHeaders: headers,
    signal: ctx.abort, store, interaction, callbackServer, logger,
  })
  if (authed) response = authed
}
```

The Cloudflare retry logic (`tool/webfetch.ts:76-79`) and signal management (`tool/webfetch.ts:93`) stay in the consumer — they're webfetch-specific concerns.


## 5. Client Registration Metadata

### Current state

`flow.ts:133-139` hardcodes opencode's identity in dynamic client registration:

```ts
body: JSON.stringify({
  redirect_uris: [redirectUri],
  client_name: "OpenCode",
  client_uri: "https://opencode.ai",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
}),
```

`orchestrate.ts:155` has an error message referencing opencode config: `"Register a client at ${docs} and configure it in opencode.json."`

### Plan

#### In the auth package

Accept client registration metadata as configuration:

```ts
interface ClientRegistration {
  name: string            // e.g. "OpenCode", "My CLI Tool"
  uri?: string            // e.g. "https://opencode.ai"
  clientId?: string       // pre-registered client, skip dynamic registration
  clientSecret?: string
}
```

The package uses `name` and `uri` in dynamic registration requests. If `clientId` is provided, skip registration entirely.

Error messages should be generic: "No client_id is configured and dynamic registration is not available. Register a client at {docs_url}." No mention of opencode.json or any specific config file.

#### In opencode

Pass `{ name: "OpenCode", uri: "https://opencode.ai" }` as the client registration config.


## 6. Logging

### Current state

Every module imports opencode's structured logger:

- `orchestrate.ts:17` — `import { Log } from "../util/log"`
- `flow.ts:27` — `import { Log } from "../util/log"`
- `discovery.ts:19` — `import { Log } from "../util/log"`
- `webfetch-auth.ts:14` — `import { Log } from "../util/log"`

Each creates a service-tagged logger instance and uses `log.info()`, `log.warn()`, `log.error()` throughout.

### Plan

#### In the auth package

Accept an optional logger at initialization:

```ts
interface Logger {
  info(message: string, data?: Record<string, unknown>): void
  warn(message: string, data?: Record<string, unknown>): void
  error(message: string, data?: Record<string, unknown>): void
}
```

Default to a no-op logger if none is provided.

#### In opencode

Pass `Log.create({ service: "webfetch.auth" })` as the logger when initializing the auth package. No behavior change.


## 7. What stays in the package

These modules are already general-purpose:

- **`www-authenticate.ts`** — RFC 9110 parser. Only internal dependency is `isLoopback` from `discovery.ts`. No `Log`, no `Global`, no file I/O.
- **`discovery.ts`** — RFC 9728/8414 discovery. Only imports `Log` (addressed in section 6). All the SSRF protection, URL validation, metadata parsing, and field validation is standard OAuth infrastructure.
- **PKCE and state generation** — `flow.ts:74-85`. Pure crypto, no dependencies.
- **Dynamic client registration** — `flow.ts:113-166`. Imports `Log` and `requireHttps`. The hardcoded "OpenCode" metadata moves to the `ClientRegistration` config (section 5).
- **Authorization code flow** — `flow.ts:265-381`. The token exchange logic stays. The `callbackServer()` call and `Bun.spawn` are replaced by the `CallbackServer` and `Interaction` interfaces.
- **Device code flow** — `flow.ts:404-576`. Imports `Log` and discovery types. `Bun.sleep` at `flow.ts:509` must be replaced with `new Promise(r => setTimeout(r, interval))` for portability.
- **`expired()` and `headers()`** — `webfetch-auth.ts:141-246`. Pure functions on `Credential` values.
- **`refresh()`** — `webfetch-auth.ts:156-217`. Makes HTTP calls and writes to the store (line 215). Stays in the package but accepts `CredentialStore` as a parameter instead of calling the module-level `set()`.
- **`resolve()`** — `webfetch-auth.ts:252-266`. Reads from the store and may fetch AS metadata. Stays in the package but accepts `CredentialStore` as a parameter.
- **Authorization URL validation** — `flow.ts:691-699`. Blocks non-HTTPS, non-loopback authorization URLs. Stays in the package, runs before calling `interaction.openUrl()`.


## 8. What does NOT move into the package

- **`index.ts`** (the `Auth` namespace) — provider credential store for LLM API keys/OAuth. This is opencode-specific and stays in opencode.
- **`OAUTH_DUMMY_KEY`** — Codex plugin workaround.
- **`Global.Path.data`** — replaced by the `CredentialStore` interface.
- **`Log` from `../util/log`** — replaced by the `Logger` interface.
- **`Filesystem` from `../util/filesystem`** — only used in `index.ts` which isn't moving.
- **`Bun.spawn([open, authUrl])`** — replaced by `Interaction.openUrl`.
- **`Bun.serve`** — the default `LocalCallbackServer` uses `node:http` instead.
- **`Bun.sleep`** — replaced by `setTimeout`-based sleep in the device code poll loop.
- **Branded HTML** — the "OpenCode - Authorization Successful" pages. The default `LocalCallbackServer` ships generic HTML; consumers can override via `html` option.
- **opencode-specific error messages** — `orchestrate.ts:155` references "opencode.json". Replaced with generic messages.


## 9. Runtime dependencies

After extraction, the auth package's dependencies:

| Dependency | Used for | Portability |
|---|---|---|
| `crypto.subtle` | PKCE S256 challenge | Web Crypto API — Node 18+, Bun, Deno, browsers |
| `fetch` | All HTTP operations | Global in Node 18+, Bun, Deno |
| `node:dns` | SSRF protection in `discovery.ts:230-242` | Node/Bun (Deno has `Deno.resolveDns`) |
| `node:http` | Default `LocalCallbackServer` | Node/Bun |
| `setTimeout` | Device code poll sleep (replacing `Bun.sleep`) | Universal |

The `node:http` and `node:dns` dependencies mean the default implementation targets Node/Bun. The interfaces (`CredentialStore`, `CallbackServer`, `Interaction`) are runtime-agnostic — a Deno consumer could provide their own implementations.

No npm dependencies.

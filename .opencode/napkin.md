# Repository Learning Memory

Last updated: 2026-02-23

## Hard Rules
- Tests cannot run from repo root; run from package dirs like `packages/opencode`
- Default branch is `dev`, not `main`
- Local `main` ref may not exist; use `dev` or `origin/dev` for diffs
- Prefer automation: execute actions without confirmation unless blocked

## User Preferences
- Prefer single-word variable names per AGENTS.md style guide
- Avoid destructuring; use dot notation
- Prefer `const` over `let`; use ternaries/early returns
- Avoid `try/catch`, `any` type, and `else` statements
- Use Bun APIs when possible

## Mistakes and Corrections
| Date | Source | What Went Wrong | What To Do Instead |
|------|--------|-----------------|--------------------|
| 2026-02-23 | self | `fetchResourceMetadata` rejects HTTP URLs; mock servers use HTTP on localhost | Added RFC 8252 §7.3 loopback exception to `requireHttps` — allows HTTP for localhost/127.0.0.1/[::1] |
| 2026-02-23 | self | `discover()` integration test: resource field in mock didn't match the `resource` arg | The `resource` field in mock metadata must exactly match the first arg to `discover()`, per RFC 9728 §3.3 |
| 2026-02-23 | self | `let port: number` then `port = s.port` triggers TS error (`number | undefined`) | Use `let port = 0` and `s.port as number` for Bun.serve port assignment |

## Manual Approval Log
| Date | Source | Pattern | Intent | Outcome | Recommendation |
|------|--------|---------|--------|---------|----------------|

## Winning Patterns
- The existing auth JSON file pattern (`0o600` permissions, zod schema) in `src/auth/index.ts` is the standard for credential storage
- MCP OAuth uses local callback server on port 19876 with PKCE; reuse this pattern for new OAuth flows
- Codex plugin has proven PKCE generation and device code flow patterns
- Tool.define framework handles input validation and output truncation automatically
- Mock server pattern for testing: `Bun.serve({ port: 0 })` with `let port = 0; port = s.port as number` to get dynamic port, using lazy reference in fetch handler
- RFC 8252 §7.3 loopback exception allows HTTP for localhost in HTTPS-only validation — enables testing without TLS

## Repo Facts
- webfetch tool: `packages/opencode/src/tool/webfetch.ts` (358 lines, auth orchestration + HTML processing)
- Auth modules: `src/auth/www-authenticate.ts`, `src/auth/discovery.ts`, `src/auth/flow.ts`, `src/auth/webfetch-auth.ts`
- Auth store: `packages/opencode/src/auth/index.ts` (JSON file at `$XDG_DATA_HOME/opencode/auth.json`)
- MCP OAuth: `packages/opencode/src/mcp/oauth-provider.ts` + `oauth-callback.ts`
- Tool registry: `packages/opencode/src/tool/registry.ts`
- Pre-existing TS errors (82 total) in `acp/agent.ts`, `permission/next.ts`, `plugin/index.ts`, `provider/provider.ts`, `drizzle.config.ts`, `script/build.ts` — unrelated to our work
- `Bun.serve().port` is typed `number | undefined`; needs `as number` cast

## Open Questions
- (none)

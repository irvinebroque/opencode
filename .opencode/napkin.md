# Repository Learning Memory

Last updated: 2026-02-23

## Hard Rules
- Tests cannot run from repo root; run from package dirs like `packages/opencode`.
- Default branch is `dev`, not `main`. Use `dev` or `origin/dev` for diffs.
- NEVER skip git hooks without explicit user request.

## User Preferences
- Prefer automation: execute actions without confirmation unless blocked.
- User prefers not to force-push or skip hooks; will push manually if environment blocks.

## Mistakes and Corrections
| Date | Source | What Went Wrong | What To Do Instead |
|------|--------|-----------------|--------------------|
| 2026-02-23 | self | `NODE_TLS_REJECT_UNAUTHORIZED=0` doesn't fix Bun's TLS errors | Bun has its own TLS stack; env var only affects Node |

## Manual Approval Log
| Date | Source | Pattern | Intent | Outcome | Recommendation |
|------|--------|---------|--------|---------|----------------|

## Winning Patterns
- Test files live in `packages/opencode/test/` mirroring `src/` structure (e.g. `test/auth/discovery.test.ts`).
- Tests use `bun:test` with `describe`/`test`/`expect`. Mock servers use `Bun.serve({ port: 0 })`.
- `isPrivateNetwork` is the public async API; `isPrivateIP` is the sync internal core.

## Repo Facts
- Monorepo using turbo. Pre-push hook runs `bun turbo typecheck` (builds + typechecks all packages).
- Build script in `packages/opencode` fetches `https://models.dev/api.json` at build time — fails with self-signed cert errors behind proxies/VPNs.
- `tsgo` is used for typechecking instead of `tsc` in most packages.
- Pre-existing tsgo type error: `Uint8Array[]` not assignable to `BlobPart[]` in `readJsonLimited`.

## Open Questions
- Is the `models.dev` SSL error specific to this dev machine or widespread?

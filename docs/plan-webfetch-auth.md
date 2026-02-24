# Plan: WebFetch Authentication via RFC 9728 and HTTP Authentication Framework

## Problem Statement

When `webfetch` fetches a URL protected by Cloudflare Access (or any service implementing standard HTTP authentication discovery), it currently fails with an opaque error or returns a login page. The tool has no ability to discover authentication requirements, negotiate credentials, or guide the user through an authorization flow.

**Proof of problem**: fetching `https://wiki.cfdata.org/spaces/EA/pages/...` returns a Cloudflare Access login page instead of content. The tool sees HTML for a sign-in page and has no way to proceed.

## Goal

When webfetch encounters a protected resource, it should:
1. Detect the authentication requirement via standard HTTP signals
2. Discover how to authenticate using RFC 9728 (Protected Resource Metadata) and the HTTP `WWW-Authenticate` framework (RFC 9110, successor to RFC 7235/2617)
3. Guide the user through the appropriate authorization flow
4. Store credentials and retry the request transparently
5. Reuse stored credentials for subsequent requests to the same resource

## RFC Landscape

A note on the RFC lineage since the user references RFC 2617:

| RFC | Title | Status | Role |
|-----|-------|--------|------|
| RFC 2617 | HTTP Authentication: Basic and Digest | **Obsoleted** | Original HTTP auth framework |
| RFC 7235 | HTTP/1.1: Authentication | **Obsoleted** | Replaced 2617, refined challenge-response |
| RFC 9110 | HTTP Semantics | **Current** | Section 11 defines the current auth framework (WWW-Authenticate, 401, 407) |
| RFC 9728 | OAuth 2.0 Protected Resource Metadata | **Current (Apr 2025)** | Discovery of OAuth auth requirements via `.well-known/oauth-protected-resource` |
| RFC 8414 | OAuth 2.0 AS Metadata | **Current** | Discovery of authorization server endpoints via `.well-known/oauth-authorization-server` |
| RFC 7591 | OAuth 2.0 Dynamic Client Registration | Current | Allows unknown clients to register with an AS |
| RFC 6750 | OAuth 2.0 Bearer Token Usage | Current | How to send bearer tokens (header, body, query) |

**We implement against the current RFCs (9110, 9728, 8414) but the behavior is backward-compatible with servers speaking older protocol versions, since the wire format (WWW-Authenticate headers, .well-known paths) is the same.**

## Detection Signals

When webfetch gets a response, these signals indicate authentication is required:

### Signal 1: HTTP 401 + WWW-Authenticate header (RFC 9110 Section 11.6.1)
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"
```
This is the primary RFC 9728 discovery mechanism. The `resource_metadata` parameter points directly to the protected resource metadata document.

### Signal 2: HTTP 401 + WWW-Authenticate without resource_metadata
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example"
WWW-Authenticate: Basic realm="example"
```
Traditional HTTP auth challenge. No RFC 9728 metadata URL, but we can still attempt `.well-known` discovery based on the request URL origin, and fall back to prompting for Basic auth credentials if that's all that's offered.

### Signal 3: HTTP 403 + Cloudflare Access indicators
```
HTTP/1.1 403 Forbidden
cf-mitigated: challenge
```
Or the response body is a Cloudflare Access login page (redirect to `*.cloudflareaccess.com`). The tool already detects `cf-mitigated: challenge` for bot detection, but does not handle the Access login case. CF Access apps that implement RFC 9728 will also return `WWW-Authenticate` with `resource_metadata`, but we should detect the CF-specific signals as a fallback.

### Signal 4: HTTP 302 redirect to auth domain
Some services (including CF Access without RFC 9728) redirect to an authentication domain. If we follow the redirect and land on a login page, we should detect this and try `.well-known` discovery on the original URL's origin.

## Architecture

### New modules

```
packages/opencode/src/auth/
  index.ts              -- existing, extend with new credential type
  webfetch.ts           -- NEW: credential store for webfetch (per-origin tokens)
  discovery.ts          -- NEW: RFC 9728 + RFC 8414 metadata fetching and parsing
  www-authenticate.ts   -- NEW: WWW-Authenticate header parser
  flow.ts               -- NEW: OAuth flow executor (authorization code + PKCE, device code)
```

### Module responsibilities

#### 1. `www-authenticate.ts` -- Header Parser

Parses `WWW-Authenticate` header values per RFC 9110 Section 11.6.1 grammar:

```
WWW-Authenticate = 1#challenge
challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
auth-param = token BWS "=" BWS ( token / quoted-string )
```

Returns structured data:
```ts
type Challenge = {
  scheme: string               // "Bearer", "Basic", "DPoP", etc.
  params: Record<string, string>  // realm, resource_metadata, error, etc.
  token68?: string             // for schemes using token68 format
}

function parse(header: string): Challenge[]
```

Key considerations:
- Multiple challenges can appear in a single header value, comma-separated
- Multiple `WWW-Authenticate` headers can appear in a single response
- The `resource_metadata` parameter is the RFC 9728 signal
- The `realm` parameter defines the protection space
- Must handle both `token` and `quoted-string` parameter values

#### 2. `discovery.ts` -- Metadata Fetcher

Implements RFC 9728 Section 3 (Protected Resource Metadata) and RFC 8414 Section 3 (AS Metadata):

```ts
// RFC 9728: Protected Resource Metadata
type ResourceMetadata = {
  resource: string                    // REQUIRED: resource identifier
  authorization_servers?: string[]    // AS issuer identifiers
  scopes_supported?: string[]
  bearer_methods_supported?: string[] // "header", "body", "query"
  resource_name?: string
  // ... other optional fields
}

// RFC 8414: Authorization Server Metadata  
type ASMetadata = {
  issuer: string                          // REQUIRED
  authorization_endpoint?: string         // REQUIRED for auth code
  token_endpoint?: string                 // REQUIRED for most grant types
  registration_endpoint?: string          // for dynamic client registration
  scopes_supported?: string[]
  response_types_supported: string[]      // REQUIRED
  grant_types_supported?: string[]        // default: ["authorization_code", "implicit"]
  code_challenge_methods_supported?: string[]
  device_authorization_endpoint?: string  // for device code flow
  // ... other optional fields
}
```

**Protected Resource Metadata Request** (RFC 9728 Section 3.1):

URL construction: insert `/.well-known/oauth-protected-resource` between the host and path components.
- `https://resource.example.com` -> `https://resource.example.com/.well-known/oauth-protected-resource`
- `https://resource.example.com/resource1` -> `https://resource.example.com/.well-known/oauth-protected-resource/resource1`

**Validation** (RFC 9728 Section 3.3):
- The `resource` value in the response MUST match the resource identifier used to construct the well-known URL
- If fetched via `WWW-Authenticate` `resource_metadata` URL, the `resource` value MUST match the URL the client originally requested

**AS Metadata Request** (RFC 8414 Section 3.1):

URL construction: insert `/.well-known/oauth-authorization-server` between the host and path components of the issuer identifier.
- `https://as.example.com` -> `https://as.example.com/.well-known/oauth-authorization-server`

Fallback: also try `/.well-known/openid-configuration` (OpenID Connect Discovery 1.0 compatible).

**Validation** (RFC 8414 Section 3.3):
- The `issuer` value in the response MUST match the issuer identifier used to construct the well-known URL

#### 3. `webfetch-auth.ts` -- Credential Store

Per-origin/resource credential storage. Extends the pattern from `src/auth/index.ts` but stores webfetch-specific tokens separately to avoid conflating with provider auth:

```ts
type WebFetchCredential = {
  resource: string           // resource identifier (origin or full URL)
  scheme: "bearer" | "basic" | "service-token"
  // For bearer:
  access_token?: string
  refresh_token?: string
  expires_at?: number         // epoch seconds
  scope?: string
  // For basic:
  username?: string
  password?: string
  // For CF Access service tokens:
  client_id?: string
  client_secret?: string
  // OAuth client registration (if dynamic)
  oauth_client_id?: string
  oauth_client_secret?: string
  // Which AS issued the token
  issuer?: string
}
```

Storage location: `$XDG_DATA_HOME/opencode/webfetch-auth.json` with mode `0o600`.

Functions:
- `get(resource: string)` -- find credentials for a resource URL (match by origin, then by longest-prefix)
- `set(resource: string, cred: WebFetchCredential)` -- store credentials
- `remove(resource: string)` -- delete credentials
- `expired(cred: WebFetchCredential)` -- check if token has expired
- `refresh(cred: WebFetchCredential, asMetadata: ASMetadata)` -- refresh using refresh_token grant

#### 4. `flow.ts` -- OAuth Flow Executor

Executes the OAuth flow to obtain tokens. Two flow types:

**Authorization Code + PKCE** (preferred for interactive use):
1. Generate PKCE code_verifier and code_challenge (SHA-256)
2. Generate random state parameter
3. Build authorization URL with: response_type=code, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method
4. Start local HTTP callback server (reuse existing pattern from MCP OAuth)
5. Open browser to authorization URL
6. Receive callback with authorization code
7. Exchange code for tokens at token_endpoint
8. Store tokens

**Device Authorization Grant** (RFC 8628, for headless/SSH):
1. POST to device_authorization_endpoint with client_id and scope
2. Display user_code and verification_uri to user
3. Poll token_endpoint until user completes authorization
4. Store tokens

**Dynamic Client Registration** (RFC 7591, when no client_id is pre-configured):
1. POST to registration_endpoint with client metadata
2. Receive client_id (and optionally client_secret)
3. Store for future use
4. Proceed with authorization code flow

The flow executor should reuse patterns from:
- `src/mcp/oauth-provider.ts` (PKCE, client metadata, token storage)
- `src/mcp/oauth-callback.ts` (local callback server)
- `src/plugin/codex.ts` (PKCE generation, device code flow)

#### 5. Integration into `webfetch.ts`

The core change: after the initial fetch, check for auth signals before throwing on non-OK responses.

```
Current flow:
  fetch(url) -> if !ok, throw error

New flow:
  fetch(url)
  -> if ok, return content (unchanged)
  -> if 401/403 with auth signals:
       1. Check credential store for existing valid credentials
          - If found and not expired, retry with credentials
          - If found and expired, attempt refresh, retry
       2. If no stored credentials:
          a. Parse WWW-Authenticate headers
          b. If resource_metadata URL present, fetch it (RFC 9728)
          c. Else, try .well-known/oauth-protected-resource on origin
          d. If resource metadata found:
             - Fetch AS metadata for each authorization_server (RFC 8414)
             - Prompt user: "This URL requires authentication via {AS}. Authenticate?"
             - If yes, execute OAuth flow
             - Retry with obtained token
          e. If only Basic auth offered:
             - Prompt user for username/password
             - Retry with Basic credentials
          f. If CF Access service token configured (env vars):
             - Retry with CF-Access-Client-Id/CF-Access-Client-Secret headers
       3. If auth flow fails or user declines, throw descriptive error
```

### How credentials are applied per scheme

| Scheme | Header | Example |
|--------|--------|---------|
| Bearer | `Authorization: Bearer {token}` | Standard OAuth |
| Basic | `Authorization: Basic {base64(user:pass)}` | Traditional HTTP auth |
| DPoP | `Authorization: DPoP {token}` + `DPoP: {proof}` | Proof of possession (future) |
| CF Service Token | `CF-Access-Client-Id: {id}` + `CF-Access-Client-Secret: {secret}` | Cloudflare Access M2M |

## End-to-End Flow (RFC 9728 Happy Path)

```
User asks LLM to fetch https://internal.example.com/api/docs

1. webfetch: GET https://internal.example.com/api/docs
   <- 401 Unauthorized
   <- WWW-Authenticate: Bearer resource_metadata="https://internal.example.com/.well-known/oauth-protected-resource"

2. webfetch: Check credential store for internal.example.com -> miss

3. webfetch: GET https://internal.example.com/.well-known/oauth-protected-resource
   <- 200 OK
   <- {
        "resource": "https://internal.example.com",
        "authorization_servers": ["https://auth.example.com"],
        "scopes_supported": ["read", "write"],
        "bearer_methods_supported": ["header"]
      }

4. webfetch: Validate resource == origin of original URL -> OK

5. webfetch: GET https://auth.example.com/.well-known/oauth-authorization-server
   <- 200 OK
   <- {
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "registration_endpoint": "https://auth.example.com/register",
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"]
      }

6. webfetch: Validate issuer == AS identifier -> OK

7. webfetch: No pre-configured client_id
   -> POST https://auth.example.com/register (Dynamic Client Registration)
   <- { "client_id": "abc123", "client_secret": "..." }

8. webfetch: Prompt user via ctx.ask():
   "https://internal.example.com requires authentication via https://auth.example.com.
    Authenticate in browser?"
   -> User approves

9. webfetch: Start local callback server, open browser to:
   https://auth.example.com/authorize?
     response_type=code&
     client_id=abc123&
     redirect_uri=http://127.0.0.1:19877/webfetch/oauth/callback&
     scope=read&
     state={random}&
     code_challenge={S256(verifier)}&
     code_challenge_method=S256

10. User authenticates in browser, AS redirects to callback

11. webfetch: Exchange code for tokens at token_endpoint

12. webfetch: Store tokens in webfetch-auth.json

13. webfetch: Retry GET https://internal.example.com/api/docs
    Authorization: Bearer {access_token}
    <- 200 OK, content returned

14. webfetch: Return content to LLM
```

## End-to-End Flow (CF Access with Service Token)

For machine-to-machine access to CF Access protected resources, service tokens are simplest:

```
1. webfetch: GET https://wiki.cfdata.org/spaces/EA/pages/...
   <- 403 + CF Access login page (or 401 with WWW-Authenticate)

2. webfetch: Check env vars CF_ACCESS_CLIENT_ID + CF_ACCESS_CLIENT_SECRET
   -> Found (user has configured these)

3. webfetch: Retry with:
   CF-Access-Client-Id: {id}
   CF-Access-Client-Secret: {secret}
   <- 200 OK, content returned
```

Alternatively, if RFC 9728 is available on the CF Access app:
```
1. webfetch: GET https://wiki.cfdata.org/...
   <- 401 + WWW-Authenticate: Bearer resource_metadata="..."

2. Follow full RFC 9728 flow (steps 2-14 from above)
```

## Configuration

New config fields in `opencode.json`:

```json
{
  "webfetch": {
    "auth": {
      // Pre-configured service tokens for specific origins
      "credentials": {
        "https://wiki.cfdata.org": {
          "type": "service-token",
          "headers": {
            "CF-Access-Client-Id": "${CF_ACCESS_CLIENT_ID}",
            "CF-Access-Client-Secret": "${CF_ACCESS_CLIENT_SECRET}"
          }
        },
        "https://api.example.com": {
          "type": "bearer",
          "token": "${API_TOKEN}"
        }
      },
      // Pre-configured OAuth client IDs for specific AS issuers
      "oauth_clients": {
        "https://auth.example.com": {
          "client_id": "my-app",
          "client_secret": "${CLIENT_SECRET}"
        }
      }
    }
  }
}
```

Environment variables for CF Access (zero-config):
- `CF_ACCESS_CLIENT_ID` -- checked automatically on CF Access 403
- `CF_ACCESS_CLIENT_SECRET` -- checked automatically on CF Access 403

## User Interaction Model

Authentication requires user consent. The flow uses the existing `ctx.ask()` permission mechanism:

1. **First encounter**: webfetch detects auth requirement, prompts:
   ```
   This URL requires authentication.
   Resource: https://internal.example.com
   Auth Server: https://auth.example.com
   Scopes: read
   
   [Authenticate in browser] [Skip] [Enter token manually]
   ```

2. **Browser flow**: Opens system browser, waits for callback
   ```
   Opened browser for authentication.
   Waiting for authorization... (timeout: 5 minutes)
   ```

3. **Success**: Token stored, request retried transparently

4. **Subsequent requests**: Same-origin requests reuse stored token without prompting
   - Permission can be set to `allow` for specific domains to skip the prompt entirely

## Security Considerations

### SSRF Protection (RFC 9728 Section 7.7)
The tool fetches URLs provided by an untrusted resource server (the `resource_metadata` URL, the `authorization_servers` URLs). Mitigations:
- Only follow HTTPS URLs for metadata and AS endpoints
- Validate that the `resource` field in metadata matches the original request origin
- Validate that the `issuer` field in AS metadata matches the AS identifier from resource metadata
- Block requests to private/loopback IP ranges for metadata fetches (except `127.0.0.1` for the local callback server)
- Limit redirect depth

### Phishing Protection (RFC 9728 Section 7.8)
A malicious resource server could point to a fake authorization server. Mitigations:
- Display the authorization server domain prominently in the user prompt
- Require explicit user consent before opening browser
- Only open browser to HTTPS URLs
- Never auto-submit credentials to a discovered AS -- always require user interaction

### Token Storage Security
- Stored in `webfetch-auth.json` with mode `0o600` (matching existing pattern)
- Tokens are per-resource, not global
- Token refresh is attempted before falling back to re-authentication
- No tokens stored in config files (env var expansion happens at runtime)

### Audience-Restricted Tokens (RFC 9728 Section 7.4)
When requesting tokens, include the `resource` parameter (RFC 8707) to request audience-restricted tokens, preventing token reuse across resources.

## Implementation Phases

### Phase 1: Detection and Static Credentials
**Files modified**: `webfetch.ts`
**Files created**: `www-authenticate.ts`, `webfetch-auth.ts`

- Parse `WWW-Authenticate` headers on 401/403 responses
- Support pre-configured credentials via config and env vars
- Support CF Access service tokens via env vars
- Retry with stored/configured credentials
- Return informative error messages when auth is required but no credentials are available

This phase alone solves the "CF Access with service token" use case.

### Phase 2: RFC 9728 Discovery
**Files created**: `discovery.ts`

- Fetch and parse `.well-known/oauth-protected-resource`
- Fetch and parse `.well-known/oauth-authorization-server`
- Validate metadata per the RFCs
- Cache metadata with HTTP cache headers

### Phase 3: OAuth Flow Execution
**Files created**: `flow.ts`
**Files modified**: `webfetch.ts` (integrate flow)

- Authorization code + PKCE flow
- Local callback server (separate port from MCP: `19877`)
- Dynamic client registration
- Token storage and refresh
- User prompt via `ctx.ask()`

### Phase 4: Device Code Flow and Headless Support
**Files modified**: `flow.ts`

- Device authorization grant (RFC 8628)
- Fallback when browser cannot be opened (SSH, containers)
- Polling with backoff

### Phase 5: Credential Management CLI
**Files modified**: `cli/cmd/auth.ts`

- `opencode auth webfetch list` -- show stored webfetch credentials
- `opencode auth webfetch remove <origin>` -- remove stored credentials
- `opencode auth webfetch add <origin>` -- manually add a bearer token or basic credentials

## Critique and Risks

### Risk: Not all protected resources implement RFC 9728
RFC 9728 was published April 2025. Adoption is early. Many services will return 401/403 without the `resource_metadata` parameter.

**Mitigation**: Phase 1 handles static credentials and env vars. The `.well-known` probe is attempted speculatively even without `resource_metadata` in the header. Basic auth challenges are handled without RFC 9728. The system degrades gracefully: if discovery fails, the user gets an informative error explaining what authentication is needed and how to configure credentials.

### Risk: Dynamic Client Registration may not be available
Many authorization servers do not support RFC 7591. Without a pre-configured `client_id`, the OAuth flow cannot proceed.

**Mitigation**: Support pre-configured `client_id` via config. When dynamic registration fails, prompt the user to configure a client_id manually and provide the AS's registration documentation URL (from AS metadata `service_documentation` field).

### Risk: OAuth callback port conflicts
The MCP OAuth system uses port `19876`. Using a different port (`19877`) avoids conflicts, but any port can conflict with other services.

**Mitigation**: Try a range of ports if the primary port is in use. The callback URL sent to the AS includes the actual port, so this is safe.

### Risk: Token scope mismatch
The resource metadata may advertise scopes the user doesn't have access to. Requesting too-broad scopes may cause authorization failure.

**Mitigation**: Request minimum scopes. If the resource metadata has `scopes_supported`, use those. If the AS returns a narrower scope than requested, accept it.

### Risk: Complexity budget
Adding OAuth flows to webfetch significantly increases the tool's complexity. The current implementation is ~200 lines; this could triple it.

**Mitigation**: All new logic lives in separate modules (`discovery.ts`, `flow.ts`, `www-authenticate.ts`, `webfetch-auth.ts`). The webfetch.ts changes are a thin integration layer (~50 lines of new code in the main function). The OAuth flow executor reuses patterns already proven in the MCP OAuth system. Consider extracting shared OAuth primitives (PKCE generation, callback server) into a common `auth/oauth` module used by both MCP and webfetch.

### Risk: Cloudflare Access may not expose WWW-Authenticate on all responses
CF Access apps that haven't enabled RFC 9728 return a 302 redirect to the login page, not a 401 with `WWW-Authenticate`.

**Mitigation**: Detect CF Access login pages by checking if the response redirected to `*.cloudflareaccess.com` or if the response body contains CF Access login markup. In this case, try `.well-known/oauth-protected-resource` on the original URL's origin speculatively. If that also fails, check for `CF_ACCESS_CLIENT_ID`/`CF_ACCESS_CLIENT_SECRET` env vars.

### Gap: Refresh token rotation
Some AS implementations rotate refresh tokens on each use. If a refresh fails, the user must re-authenticate.

**Mitigation**: On refresh failure, clear stored tokens and trigger re-authentication. Log the failure clearly so the user understands what happened.

### Gap: Multi-tenant resources
RFC 9728 supports path-based resource identifiers. A single host may have multiple resources with different auth requirements.

**Mitigation**: Store credentials keyed by the full resource identifier (not just origin). Look up credentials by longest-prefix match.

### Gap: mTLS / certificate-based auth
RFC 9728 metadata can indicate `tls_client_certificate_bound_access_tokens`. Supporting mTLS requires configuring client certificates.

**Mitigation**: Out of scope for initial implementation. Document that mTLS is not supported.

## Test Plan

1. **Unit tests for WWW-Authenticate parser**: various header formats, multiple challenges, edge cases
2. **Unit tests for .well-known URL construction**: with/without path components, trailing slashes
3. **Unit tests for metadata validation**: matching resource/issuer identifiers
4. **Integration test with mock server**: full 401 -> discovery -> token exchange -> retry flow
5. **Integration test for static credentials**: env var and config-based credential injection
6. **Integration test for credential caching**: second request reuses stored token
7. **Integration test for token refresh**: expired token triggers refresh grant

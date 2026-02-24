/**
 * WWW-Authenticate header parser per RFC 9110 Section 11.6.1
 *
 * Grammar:
 *   WWW-Authenticate = 1#challenge
 *   challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
 *   auth-param = token BWS "=" BWS ( token / quoted-string )
 */

export type Challenge = {
  scheme: string
  params: Record<string, string>
  token68?: string
}

const TOKEN_CHARS = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/
const TOKEN68_CHARS = /^[A-Za-z0-9\-._~+/]+=*$/

export function parse(header: string): Challenge[] {
  const challenges: Challenge[] = []
  let pos = 0

  function skip() {
    while (pos < header.length && (header[pos] === " " || header[pos] === "\t")) pos++
  }

  function token(): string {
    const start = pos
    while (pos < header.length && TOKEN_CHARS.test(header[pos])) pos++
    return header.slice(start, pos)
  }

  function quoted(): string {
    if (header[pos] !== '"') return ""
    pos++ // skip opening quote
    let result = ""
    while (pos < header.length) {
      if (header[pos] === "\\") {
        pos++
        if (pos < header.length) {
          result += header[pos]
          pos++
        }
        continue
      }
      if (header[pos] === '"') {
        pos++ // skip closing quote
        return result
      }
      result += header[pos]
      pos++
    }
    return result
  }

  function params(): Record<string, string> {
    const result: Record<string, string> = {}
    while (pos < header.length) {
      skip()
      if (pos >= header.length) break

      // Save position to backtrack if this is a new scheme
      const saved = pos
      const key = token()
      if (!key) break

      skip()
      if (pos >= header.length || header[pos] !== "=") {
        // No "=" means this could be a new challenge scheme
        // Check if there's a space+param or comma after this token
        // If what we read looks like a scheme name (followed by space+params or end), backtrack
        pos = saved
        break
      }
      pos++ // skip "="
      skip()

      const val = header[pos] === '"' ? quoted() : token()
      result[key.toLowerCase()] = val

      skip()
      if (pos < header.length && header[pos] === ",") {
        pos++
        // Peek ahead: if next non-whitespace is a token followed by "=", it's another param
        // Otherwise it could be a new challenge
        skip()
        const peek = pos
        const next = token()
        skip()
        if (next && pos < header.length && header[pos] === "=") {
          // It's another param, continue
          pos = peek
          continue
        }
        // It's a new challenge; backtrack to the start of this token
        pos = peek
        break
      }
    }
    return result
  }

  while (pos < header.length) {
    skip()
    if (pos >= header.length) break

    const scheme = token()
    if (!scheme) {
      pos++
      continue
    }

    skip()

    // Check for token68 (no "=" in auth-param sense)
    if (pos >= header.length || header[pos] === ",") {
      challenges.push({ scheme, params: {} })
      if (pos < header.length && header[pos] === ",") pos++
      continue
    }

    // Try to parse as params first by peeking ahead
    const saved = pos
    const first = token()
    skip()
    if (first && pos < header.length && header[pos] === "=") {
      // Looks like auth-params, backtrack and parse fully
      pos = saved
      const p = params()
      challenges.push({ scheme, params: p })
    } else if (first && TOKEN68_CHARS.test(first)) {
      // token68 format
      challenges.push({ scheme, params: {}, token68: first })
    } else {
      // Bare scheme with something unexpected; push what we have
      pos = saved
      challenges.push({ scheme, params: {} })
    }

    skip()
    if (pos < header.length && header[pos] === ",") pos++
  }

  return challenges
}

export function all(response: Response): Challenge[] {
  const result: Challenge[] = []
  const values: string[] = []
  response.headers.forEach((val, key) => {
    if (key.toLowerCase() === "www-authenticate") values.push(val)
  })
  for (const val of values) {
    result.push(...parse(val))
  }
  return result
}

export function resourceMetadataUrl(challenges: Challenge[]): string | undefined {
  for (const c of challenges) {
    if (c.scheme.toLowerCase() === "bearer" && c.params["resource_metadata"])
      return c.params["resource_metadata"]
  }
  return undefined
}

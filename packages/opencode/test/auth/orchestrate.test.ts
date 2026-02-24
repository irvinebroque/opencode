import { describe, expect, mock, test } from "bun:test"

mock.module("../../src/auth/discovery", () => ({
  discover: async () => ({
    resource: {
      resource: "https://resource.example.com/test",
      scopes_supported: ["read"],
      authentication_method: "cloudflared",
      authentication_method_description: "Use cloudflared access curl.",
      authentication_method_documentation: "https://developers.cloudflare.com/cloudflare-one/tutorials/cli/",
    },
    servers: [
      {
        issuer: "https://as.example.com",
        authorization_endpoint: "https://as.example.com/authorize",
        token_endpoint: "https://as.example.com/token",
        grant_types_supported: ["authorization_code"],
        response_types_supported: ["code"],
      },
    ],
  }),
}))

mock.module("../../src/auth/flow", () => ({
  authorizationCode: async () => {
    throw new Error("Authorization error: invalid_target: OAuth not enabled for the targeted resource")
  },
}))

const { handleAuthChallenge } = await import("../../src/auth/orchestrate")

describe("orchestrate auth errors", () => {
  test("surfaces authorization callback error with resource auth hint", async () => {
    const response = new Response("", {
      status: 302,
      headers: {
        "WWW-Authenticate":
          'Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource/test"',
      },
    })

    const store = {
      get: async () => undefined,
      set: async () => {},
      remove: async () => {},
      all: async () => ({}),
    }

    await expect(
      handleAuthChallenge({
        response,
        url: "https://resource.example.com/test",
        baseHeaders: {},
        signal: AbortSignal.any([]),
        store,
        interaction: {
          askConsent: async () => {},
          openUrl: async () => {},
          showDeviceCode: async () => {},
        },
        callbackServer: {
          start: async () => ({ redirectUri: "http://127.0.0.1:19877/oauth/callback" }),
          waitForCode: async () => "",
          stop: async () => {},
        },
      }),
    ).rejects.toThrow("invalid_target")

    await expect(
      handleAuthChallenge({
        response,
        url: "https://resource.example.com/test",
        baseHeaders: {},
        signal: AbortSignal.any([]),
        store,
        interaction: {
          askConsent: async () => {},
          openUrl: async () => {},
          showDeviceCode: async () => {},
        },
        callbackServer: {
          start: async () => ({ redirectUri: "http://127.0.0.1:19877/oauth/callback" }),
          waitForCode: async () => "",
          stop: async () => {},
        },
      }),
    ).rejects.toThrow('authentication_method="cloudflared"')
  })
})

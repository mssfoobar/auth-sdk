import { describe, it, expect, vi, beforeEach } from "vitest";
import { initializeOidc, exchangeCode } from "../src/core/oidc.js";
import type { AuthConfig } from "../src/core/types.js";

// Mock openid-client
vi.mock("openid-client", () => ({
  discovery: vi.fn(async () => ({ serverMetadata: () => ({ issuer: "https://keycloak.example.com" }) })),
  allowInsecureRequests: Symbol("allowInsecureRequests"),
  randomPKCECodeVerifier: vi.fn(() => "verifier"),
  calculatePKCECodeChallenge: vi.fn(async () => "challenge"),
  buildAuthorizationUrl: vi.fn(() => new URL("https://keycloak.example.com/auth")),
  buildEndSessionUrl: vi.fn(() => new URL("https://keycloak.example.com/logout")),
  authorizationCodeGrant: vi.fn(async () => ({
    access_token: "new-at",
    refresh_token: "new-rt",
    expires_in: 300,
  })),
  refreshTokenGrant: vi.fn(),
  fetchUserInfo: vi.fn(),
}));

import { discovery, allowInsecureRequests, authorizationCodeGrant } from "openid-client";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("initializeOidc", () => {
  it("should call discovery with issuer URL and client ID", async () => {
    const config: AuthConfig = {
      issuerUrl: "https://keycloak.example.com/realms/test",
      clientId: "my-client",
      origin: "https://app.com",
    };

    await initializeOidc(config);

    expect(discovery).toHaveBeenCalledWith(
      new URL("https://keycloak.example.com/realms/test"),
      "my-client",
      undefined,
      undefined,
      {},
    );
  });

  it("should pass client secret when provided", async () => {
    const config: AuthConfig = {
      issuerUrl: "https://keycloak.example.com/realms/test",
      clientId: "my-client",
      clientSecret: "my-secret",
      origin: "https://app.com",
    };

    await initializeOidc(config);

    expect(discovery).toHaveBeenCalledWith(
      expect.any(URL),
      "my-client",
      "my-secret",
      undefined,
      {},
    );
  });

  it("should enable insecure requests when configured", async () => {
    const config: AuthConfig = {
      issuerUrl: "https://keycloak.example.com/realms/test",
      clientId: "my-client",
      origin: "https://app.com",
      allowInsecureRequests: true,
    };

    const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    await initializeOidc(config, logger);

    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining("insecure"));
    const callArgs = (discovery as any).mock.calls[0];
    expect(callArgs[4].execute).toEqual([allowInsecureRequests]);
  });
});

describe("exchangeCode", () => {
  it("should call authorizationCodeGrant with code verifier", async () => {
    const mockConfig = {} as any;
    const callbackUrl = new URL("https://app.com/callback?code=abc&state=xyz");

    const result = await exchangeCode(mockConfig, callbackUrl, "my-verifier");

    expect(authorizationCodeGrant).toHaveBeenCalledWith(
      mockConfig,
      callbackUrl,
      { pkceCodeVerifier: "my-verifier" },
    );
    expect(result.access_token).toBe("new-at");
  });
});

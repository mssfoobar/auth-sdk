import { describe, it, expect, vi } from "vitest";
import { buildLoginUrl, buildLogoutUrl, pkce } from "../src/core/oidc.js";

// Mock openid-client
vi.mock("openid-client", () => ({
  discovery: vi.fn(),
  allowInsecureRequests: Symbol("allowInsecureRequests"),
  randomPKCECodeVerifier: vi.fn(() => "mock-verifier-123"),
  calculatePKCECodeChallenge: vi.fn(async () => "mock-challenge-456"),
  buildAuthorizationUrl: vi.fn((_config, params) => {
    const url = new URL("https://keycloak.example.com/auth");
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, v as string);
    }
    return url;
  }),
  buildEndSessionUrl: vi.fn((_config, params) => {
    const url = new URL("https://keycloak.example.com/logout");
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, v as string);
    }
    return url;
  }),
  authorizationCodeGrant: vi.fn(),
  refreshTokenGrant: vi.fn(),
  fetchUserInfo: vi.fn(),
}));

import type { Configuration } from "openid-client";
const mockConfig = {} as Configuration;

describe("buildLoginUrl", () => {
  it("should include PKCE parameters", () => {
    const url = buildLoginUrl(mockConfig, "https://app.com/callback", "challenge-abc");
    expect(url.searchParams.get("code_challenge")).toBe("challenge-abc");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.com/callback");
    expect(url.searchParams.get("scope")).toBe("openid");
  });

  it("should include state when provided", () => {
    const url = buildLoginUrl(mockConfig, "https://app.com/callback", "challenge-abc", "openid", "my-state-123");
    expect(url.searchParams.get("state")).toBe("my-state-123");
  });

  it("should omit state when not provided", () => {
    const url = buildLoginUrl(mockConfig, "https://app.com/callback", "challenge-abc");
    expect(url.searchParams.has("state")).toBe(false);
  });

  it("should use custom scope", () => {
    const url = buildLoginUrl(mockConfig, "https://app.com/callback", "challenge-abc", "openid profile");
    expect(url.searchParams.get("scope")).toBe("openid profile");
  });
});

describe("buildLogoutUrl", () => {
  it("should include post_logout_redirect_uri", () => {
    const url = buildLogoutUrl(mockConfig, "https://app.com/login");
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe("https://app.com/login");
  });

  it("should include id_token_hint when provided", () => {
    const url = buildLogoutUrl(mockConfig, "https://app.com/login", "my-id-token");
    expect(url.searchParams.get("id_token_hint")).toBe("my-id-token");
  });

  it("should omit id_token_hint when not provided", () => {
    const url = buildLogoutUrl(mockConfig, "https://app.com/login");
    expect(url.searchParams.has("id_token_hint")).toBe(false);
  });
});

describe("pkce", () => {
  it("should generate a verifier", () => {
    const verifier = pkce.generateVerifier();
    expect(verifier).toBe("mock-verifier-123");
  });

  it("should calculate a challenge", async () => {
    const challenge = await pkce.calculateChallenge("some-verifier");
    expect(challenge).toBe("mock-challenge-456");
  });
});

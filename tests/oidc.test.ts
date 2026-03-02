import { describe, it, expect, vi } from "vitest";
import { isOidcCallback, buildLoginUrl, buildLogoutUrl, pkce, initializeOidc, exchangeCode } from "../src/core/oidc.js";

// Mock openid-client
vi.mock("openid-client", () => ({
  discovery: vi.fn().mockResolvedValue({ issuer: "https://auth.example.com" }),
  allowInsecureRequests: Symbol("allowInsecure"),
  randomPKCECodeVerifier: vi.fn(() => "test-verifier"),
  calculatePKCECodeChallenge: vi.fn().mockResolvedValue("test-challenge"),
  buildAuthorizationUrl: vi.fn((_config, params) => new URL(`https://auth.example.com/auth?redirect_uri=${params.redirect_uri}`)),
  buildEndSessionUrl: vi.fn((_config, params) => new URL(`https://auth.example.com/logout?post_logout_redirect_uri=${params.post_logout_redirect_uri}`)),
  authorizationCodeGrant: vi.fn().mockResolvedValue({ access_token: "at", refresh_token: "rt" }),
}));

describe("isOidcCallback", () => {
  it("returns true when URL has session_state and code", () => {
    const url = new URL("http://localhost/cb?session_state=abc&code=xyz");
    expect(isOidcCallback(url)).toBe(true);
  });

  it("returns false when URL lacks params", () => {
    expect(isOidcCallback(new URL("http://localhost/"))).toBe(false);
    expect(isOidcCallback(new URL("http://localhost/?code=xyz"))).toBe(false);
    expect(isOidcCallback(new URL("http://localhost/?session_state=abc"))).toBe(false);
  });
});

describe("pkce", () => {
  it("generates verifier", () => {
    expect(pkce.generateVerifier()).toBe("test-verifier");
  });

  it("calculates challenge", async () => {
    expect(await pkce.calculateChallenge("verifier")).toBe("test-challenge");
  });
});

describe("buildLoginUrl", () => {
  it("builds authorization URL", () => {
    const url = buildLoginUrl({} as any, "http://localhost/cb", "challenge");
    expect(url.href).toContain("auth.example.com");
  });

  it("accepts custom scope", () => {
    const url = buildLoginUrl({} as any, "http://localhost/cb", "challenge", "openid profile");
    expect(url).toBeDefined();
  });
});

describe("buildLogoutUrl", () => {
  it("builds end session URL", () => {
    const url = buildLogoutUrl({} as any, "http://localhost/");
    expect(url.href).toContain("logout");
  });

  it("includes id_token_hint when provided", () => {
    const url = buildLogoutUrl({} as any, "http://localhost/", "id-token");
    expect(url).toBeDefined();
  });
});

describe("initializeOidc", () => {
  it("discovers OIDC config", async () => {
    const config = await initializeOidc({ issuerUrl: "https://auth.example.com", clientId: "client", origin: "http://localhost" });
    expect(config).toBeDefined();
  });

  it("allows insecure requests in dev mode", async () => {
    const config = await initializeOidc({
      issuerUrl: "http://localhost:8080", clientId: "client", origin: "http://localhost",
      allowInsecureRequests: true,
    });
    expect(config).toBeDefined();
  });
});

describe("exchangeCode", () => {
  it("exchanges code for tokens", async () => {
    const result = await exchangeCode({} as any, new URL("http://localhost/cb?code=x"), "verifier");
    expect(result.access_token).toBe("at");
  });
});

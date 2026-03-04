import { describe, it, expect, vi, beforeEach } from "vitest";
import { validateAccessToken } from "../src/core/tokens.js";
import type { Configuration } from "openid-client";

// Create a real-ish JWT for testing (not cryptographically valid, but structurally correct)
function createTestJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.fake-signature`;
}

// Mock jose
vi.mock("jose", () => ({
  createRemoteJWKSet: vi.fn(() => vi.fn()),
  jwtVerify: vi.fn(),
}));

// Mock openid-client fetchUserInfo
vi.mock("openid-client", () => ({
  fetchUserInfo: vi.fn(),
  refreshTokenGrant: vi.fn(),
}));

import * as jose from "jose";
import { fetchUserInfo } from "openid-client";

const mockConfig = {} as Configuration;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("validateAccessToken", () => {
  it("should return true when JWKS verification succeeds (offline)", async () => {
    (jose.jwtVerify as any).mockResolvedValue({ payload: { sub: "user-1" } });

    const token = createTestJwt({ sub: "user-1", iss: "https://keycloak.example.com/realms/test" });
    const result = await validateAccessToken(mockConfig, token);

    expect(result).toBe(true);
    expect(jose.jwtVerify).toHaveBeenCalled();
    expect(fetchUserInfo).not.toHaveBeenCalled(); // No fallback needed
  });

  it("should fall back to userinfo when JWKS fails", async () => {
    (jose.jwtVerify as any).mockRejectedValue(new Error("signature verification failed"));
    (fetchUserInfo as any).mockResolvedValue({ sub: "user-1" });

    const token = createTestJwt({ sub: "user-1", iss: "https://keycloak.example.com/realms/test" });
    const result = await validateAccessToken(mockConfig, token);

    expect(result).toBe(true);
    expect(jose.jwtVerify).toHaveBeenCalled();
    expect(fetchUserInfo).toHaveBeenCalled();
  });

  it("should return false when both JWKS and userinfo fail", async () => {
    (jose.jwtVerify as any).mockRejectedValue(new Error("bad signature"));
    (fetchUserInfo as any).mockRejectedValue(new Error("unauthorized"));

    const token = createTestJwt({ sub: "user-1", iss: "https://keycloak.example.com/realms/test" });
    const result = await validateAccessToken(mockConfig, token);

    expect(result).toBe(false);
  });

  it("should return false when token has no sub claim", async () => {
    const token = createTestJwt({ iss: "https://keycloak.example.com/realms/test" });
    const result = await validateAccessToken(mockConfig, token);

    expect(result).toBe(false);
  });

  it("should return false when token has no iss claim", async () => {
    const token = createTestJwt({ sub: "user-1" });
    // No iss → offline validation fails, falls back to userinfo
    (fetchUserInfo as any).mockRejectedValue(new Error("bad token"));
    
    const result = await validateAccessToken(mockConfig, token);
    expect(result).toBe(false);
  });

  it("should cache JWKS per issuer URL (reuses same key set)", async () => {
    (jose.jwtVerify as any).mockResolvedValue({ payload: { sub: "user-1" } });

    // Use a unique issuer to avoid cross-test cache hits
    const uniqueIssuer = "https://keycloak.example.com/realms/cache-test-" + Date.now();
    const token1 = createTestJwt({ sub: "user-1", iss: uniqueIssuer });
    const token2 = createTestJwt({ sub: "user-2", iss: uniqueIssuer });

    const callsBefore = (jose.createRemoteJWKSet as any).mock.calls.length;
    await validateAccessToken(mockConfig, token1);
    await validateAccessToken(mockConfig, token2);
    const callsAfter = (jose.createRemoteJWKSet as any).mock.calls.length;

    // Should only create one new JWKS for the same issuer
    expect(callsAfter - callsBefore).toBe(1);
  });
});

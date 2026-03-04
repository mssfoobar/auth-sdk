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

// Mock config with serverMetadata that returns jwks_uri and issuer
function createMockConfig(jwksUri?: string, issuer?: string): Configuration {
  return {
    serverMetadata: () => ({
      issuer: issuer ?? "https://keycloak.example.com/realms/test",
      jwks_uri: jwksUri ?? "https://keycloak.example.com/realms/test/protocol/openid-connect/certs",
    }),
  } as unknown as Configuration;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("validateAccessToken", () => {
  it("should return true when JWKS verification succeeds (offline)", async () => {
    (jose.jwtVerify as any).mockResolvedValue({ payload: { sub: "user-1" } });

    const token = createTestJwt({ sub: "user-1", iss: "https://keycloak.example.com/realms/test" });
    const result = await validateAccessToken(createMockConfig(), token);

    expect(result).toBe(true);
    expect(jose.jwtVerify).toHaveBeenCalled();
    expect(fetchUserInfo).not.toHaveBeenCalled(); // No fallback needed
  });

  it("should fall back to userinfo when JWKS fails", async () => {
    (jose.jwtVerify as any).mockRejectedValue(new Error("signature verification failed"));
    (fetchUserInfo as any).mockResolvedValue({ sub: "user-1" });

    const token = createTestJwt({ sub: "user-1", iss: "https://keycloak.example.com/realms/test" });
    const result = await validateAccessToken(createMockConfig(), token);

    expect(result).toBe(true);
    expect(jose.jwtVerify).toHaveBeenCalled();
    expect(fetchUserInfo).toHaveBeenCalled();
  });

  it("should return false when both JWKS and userinfo fail", async () => {
    (jose.jwtVerify as any).mockRejectedValue(new Error("bad signature"));
    (fetchUserInfo as any).mockRejectedValue(new Error("unauthorized"));

    const token = createTestJwt({ sub: "user-1", iss: "https://keycloak.example.com/realms/test" });
    const result = await validateAccessToken(createMockConfig(), token);

    expect(result).toBe(false);
  });

  it("should fall back to userinfo when no jwks_uri in metadata", async () => {
    (fetchUserInfo as any).mockResolvedValue({ sub: "user-1" });

    const configNoJwks = createMockConfig(undefined);
    (configNoJwks.serverMetadata as any) = () => ({ issuer: "https://keycloak.example.com", jwks_uri: undefined });

    const token = createTestJwt({ sub: "user-1" });
    const result = await validateAccessToken(configNoJwks, token);

    expect(result).toBe(true);
    expect(fetchUserInfo).toHaveBeenCalled();
  });

  it("should return false when token has no sub claim (userinfo fallback)", async () => {
    (jose.jwtVerify as any).mockRejectedValue(new Error("bad"));
    (fetchUserInfo as any).mockRejectedValue(new Error("bad token"));

    const token = createTestJwt({ iss: "https://keycloak.example.com/realms/test" });
    const result = await validateAccessToken(createMockConfig(), token);

    expect(result).toBe(false);
  });

  it("should verify with issuer from server metadata", async () => {
    (jose.jwtVerify as any).mockResolvedValue({ payload: { sub: "user-1" } });

    const token = createTestJwt({ sub: "user-1" });
    await validateAccessToken(createMockConfig(undefined, "https://my-issuer.com"), token);

    expect(jose.jwtVerify).toHaveBeenCalledWith(
      token,
      expect.any(Function),
      { issuer: "https://my-issuer.com" },
    );
  });

  it("should cache JWKS per jwks_uri from metadata", async () => {
    (jose.jwtVerify as any).mockResolvedValue({ payload: { sub: "user-1" } });

    const config = createMockConfig("https://keycloak.example.com/realms/cache-test/certs");
    const token1 = createTestJwt({ sub: "user-1" });
    const token2 = createTestJwt({ sub: "user-2" });

    const callsBefore = (jose.createRemoteJWKSet as any).mock.calls.length;
    await validateAccessToken(config, token1);
    await validateAccessToken(config, token2);
    const callsAfter = (jose.createRemoteJWKSet as any).mock.calls.length;

    // Should only create one new JWKS for the same jwks_uri
    expect(callsAfter - callsBefore).toBe(1);
  });
});

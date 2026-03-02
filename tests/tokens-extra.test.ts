import { describe, it, expect, vi } from "vitest";
import { validateAccessToken, refreshTokens } from "../src/core/tokens.js";

// Mock openid-client
vi.mock("openid-client", () => ({
  refreshTokenGrant: vi.fn(),
  fetchUserInfo: vi.fn(),
}));

import { refreshTokenGrant, fetchUserInfo } from "openid-client";
const mockRefreshGrant = vi.mocked(refreshTokenGrant);
const mockFetchUserInfo = vi.mocked(fetchUserInfo);

const createTestToken = (payload: Record<string, unknown>): string => {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.test-signature`;
};

describe("validateAccessToken", () => {
  it("returns true for valid token", async () => {
    const token = createTestToken({ sub: "user-123" });
    mockFetchUserInfo.mockResolvedValue({} as any);

    const result = await validateAccessToken({} as any, token);
    expect(result).toBe(true);
  });

  it("returns false when fetchUserInfo fails", async () => {
    const token = createTestToken({ sub: "user-123" });
    mockFetchUserInfo.mockRejectedValue(new Error("unauthorized"));

    const result = await validateAccessToken({} as any, token);
    expect(result).toBe(false);
  });

  it("returns false when token has no sub", async () => {
    const token = createTestToken({});

    const result = await validateAccessToken({} as any, token);
    expect(result).toBe(false);
  });

  it("returns false for invalid JWT", async () => {
    const result = await validateAccessToken({} as any, "not-a-jwt");
    expect(result).toBe(false);
  });
});

describe("refreshTokens", () => {
  it("returns new tokens on success", async () => {
    const tokens = { access_token: "new", refresh_token: "new-rt" };
    mockRefreshGrant.mockResolvedValue(tokens as any);

    const result = await refreshTokens({} as any, "old-rt");
    expect(result).toEqual(tokens);
  });

  it("returns undefined on failure", async () => {
    mockRefreshGrant.mockRejectedValue(new Error("failed"));

    const result = await refreshTokens({} as any, "old-rt");
    expect(result).toBeUndefined();
  });
});

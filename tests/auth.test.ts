import { describe, it, expect, vi, beforeEach } from "vitest";
import { authenticate, handleAuthSuccess, handleAuthFailure } from "../src/core/auth.js";
import type { CookieAdapter, CookieNames, CookieSerializeOptions } from "../src/core/types.js";

// Mock external deps
vi.mock("../src/core/tokens.js", () => ({
  validateAccessToken: vi.fn(),
  refreshTokens: vi.fn(),
  decodeAccessToken: vi.fn(() => ({ sub: "user-123", active_tenant: {}, all_tenants: [], realm_access: { roles: [] } })),
}));

vi.mock("../src/core/oidc.js", () => ({
  isOidcCallback: vi.fn(),
  exchangeCode: vi.fn(),
}));

import { validateAccessToken, refreshTokens } from "../src/core/tokens.js";
import { isOidcCallback, exchangeCode } from "../src/core/oidc.js";

const mockValidate = vi.mocked(validateAccessToken);
const mockRefresh = vi.mocked(refreshTokens);
const mockIsCallback = vi.mocked(isOidcCallback);
const mockExchangeCode = vi.mocked(exchangeCode);

function createMockCookies(store: Record<string, string> = {}): CookieAdapter {
  return {
    get: vi.fn((name: string) => store[name]),
    set: vi.fn((name: string, value: string) => { store[name] = value; }),
    delete: vi.fn((name: string) => { delete store[name]; }),
  };
}

const cookieNames: CookieNames = {
  accessToken: "at",
  refreshToken: "rt",
  codeVerifier: "cv",
  tempSessionId: "ts",
  authSessionId: "as",
};

const cookieOptions: CookieSerializeOptions = { path: "/", secure: true };
const oidcConfig = {} as any;

describe("authenticate", () => {
  beforeEach(() => vi.clearAllMocks());

  it("returns success when access token is valid", async () => {
    const cookies = createMockCookies({ at: "access", rt: "refresh" });
    mockValidate.mockResolvedValue(true);

    const result = await authenticate({
      oidcConfig, cookies, url: new URL("http://localhost/"), origin: "http://localhost",
      cookieNames, cookieOptions,
    });

    expect(result.success).toBe(true);
  });

  it("refreshes when access token is invalid", async () => {
    const cookies = createMockCookies({ at: "access", rt: "refresh" });
    mockValidate.mockResolvedValue(false);
    mockRefresh.mockResolvedValue({ access_token: "new_at", refresh_token: "new_rt", expires_in: 300 } as any);

    const result = await authenticate({
      oidcConfig, cookies, url: new URL("http://localhost/"), origin: "http://localhost",
      cookieNames, cookieOptions,
    });

    expect(result.success).toBe(true);
  });

  it("returns failure when refresh fails", async () => {
    const cookies = createMockCookies({ at: "access", rt: "refresh" });
    mockValidate.mockResolvedValue(false);
    mockRefresh.mockResolvedValue(undefined);

    const result = await authenticate({
      oidcConfig, cookies, url: new URL("http://localhost/"), origin: "http://localhost",
      cookieNames, cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("refreshes when only refresh token exists", async () => {
    const cookies = createMockCookies({ rt: "refresh" });
    mockRefresh.mockResolvedValue({ access_token: "new_at", refresh_token: "new_rt", expires_in: 300 } as any);

    const result = await authenticate({
      oidcConfig, cookies, url: new URL("http://localhost/"), origin: "http://localhost",
      cookieNames, cookieOptions,
    });

    expect(result.success).toBe(true);
  });

  it("handles OIDC callback", async () => {
    const cookies = createMockCookies({ cv: "verifier" });
    mockIsCallback.mockReturnValue(true);
    mockExchangeCode.mockResolvedValue({ access_token: "at", refresh_token: "rt", expires_in: 300 } as any);

    const result = await authenticate({
      oidcConfig, cookies, url: new URL("http://localhost/cb?code=x&session_state=y"), origin: "http://localhost",
      cookieNames, cookieOptions,
    });

    expect(result.success).toBe(true);
  });

  it("fails OIDC callback without code verifier", async () => {
    const cookies = createMockCookies({});
    mockIsCallback.mockReturnValue(true);

    const result = await authenticate({
      oidcConfig, cookies, url: new URL("http://localhost/cb?code=x&session_state=y"), origin: "http://localhost",
      cookieNames, cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("handles OIDC callback invalid_grant error", async () => {
    const cookies = createMockCookies({ cv: "verifier" });
    mockIsCallback.mockReturnValue(true);
    const err: any = new Error("invalid_grant");
    err.error = "invalid_grant";
    mockExchangeCode.mockRejectedValue(err);

    const result = await authenticate({
      oidcConfig, cookies, url: new URL("http://localhost/cb?code=x&session_state=y"), origin: "http://localhost",
      cookieNames, cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("throws on unauthorized_client error", async () => {
    const cookies = createMockCookies({ cv: "verifier" });
    mockIsCallback.mockReturnValue(true);
    const err: any = new Error("unauthorized_client");
    err.error = "unauthorized_client";
    mockExchangeCode.mockRejectedValue(err);

    await expect(authenticate({
      oidcConfig, cookies, url: new URL("http://localhost/cb?code=x&session_state=y"), origin: "http://localhost",
      cookieNames, cookieOptions,
    })).rejects.toThrow("Invalid client credentials");
  });

  it("returns failure when no tokens and not callback", async () => {
    const cookies = createMockCookies({});
    mockIsCallback.mockReturnValue(false);

    const result = await authenticate({
      oidcConfig, cookies, url: new URL("http://localhost/"), origin: "http://localhost",
      cookieNames, cookieOptions,
    });

    expect(result.success).toBe(false);
  });
});

describe("handleAuthSuccess", () => {
  it("sets cookies and returns success", () => {
    const cookies = createMockCookies();
    const result = handleAuthSuccess(cookies, cookieNames, cookieOptions, "at", "rt", 300);

    expect(result.success).toBe(true);
    expect(result.accessToken).toBe("at");
    expect(cookies.set).toHaveBeenCalledTimes(2);
    expect(cookies.delete).toHaveBeenCalledTimes(1);
  });

  it("works without refresh token", () => {
    const cookies = createMockCookies();
    const result = handleAuthSuccess(cookies, cookieNames, cookieOptions, "at");

    expect(result.success).toBe(true);
    expect(cookies.set).toHaveBeenCalledTimes(0); // no expiresIn, no refreshToken
  });
});

describe("handleAuthFailure", () => {
  it("clears all cookies", () => {
    const cookies = createMockCookies();
    const result = handleAuthFailure(cookies, cookieNames, cookieOptions);

    expect(result.success).toBe(false);
    expect(cookies.delete).toHaveBeenCalledTimes(5);
  });
});

import { describe, it, expect, vi, beforeEach } from "vitest";
import { authenticate } from "../src/core/auth.js";
import type { CookieAdapter, CookieNames, CookieSerializeOptions } from "../src/core/types.js";
import type { Configuration } from "openid-client";

// Mock tokens and oidc modules
vi.mock("../src/core/tokens.js", () => ({
  validateAccessToken: vi.fn(),
  refreshTokens: vi.fn(),
  decodeAccessToken: vi.fn((token: string) => ({
    sub: "user-1",
    active_tenant: {},
    all_tenants: [],
    realm_access: { roles: [] },
  })),
}));

vi.mock("../src/core/oidc.js", () => ({
  isOidcCallback: vi.fn(),
  exchangeCode: vi.fn(),
}));

import { validateAccessToken, refreshTokens } from "../src/core/tokens.js";
import { isOidcCallback, exchangeCode } from "../src/core/oidc.js";

function createMockCookies(): CookieAdapter & { _store: Map<string, string>; _deleted: string[] } {
  const store = new Map<string, string>();
  const deleted: string[] = [];
  return {
    get: (name: string) => store.get(name),
    set: (name: string, value: string, _opts: any) => store.set(name, value),
    delete: (name: string, _opts: any) => { store.delete(name); deleted.push(name); },
    _store: store,
    _deleted: deleted,
  };
}

const cookieNames: CookieNames = {
  accessToken: "t_access_token",
  refreshToken: "t_refresh_token",
  codeVerifier: "t_code_verifier",
  tempSessionId: "t_temp_session_id",
  authSessionId: "t_auth_session_id",
  oauthState: "t_oauth_state",
};

const cookieOptions: CookieSerializeOptions = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
};

const mockOidcConfig = {} as Configuration;

beforeEach(() => {
  vi.clearAllMocks();
  (isOidcCallback as any).mockReturnValue(false);
});

describe("authenticate", () => {
  it("Case 1: valid access token + refresh token → success", async () => {
    const cookies = createMockCookies();
    cookies._store.set("t_access_token", "valid-at");
    cookies._store.set("t_refresh_token", "valid-rt");
    (validateAccessToken as any).mockResolvedValue(true);

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/page"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(true);
    expect(validateAccessToken).toHaveBeenCalled();
  });

  it("Case 1: invalid access token → tries refresh", async () => {
    const cookies = createMockCookies();
    cookies._store.set("t_access_token", "bad-at");
    cookies._store.set("t_refresh_token", "valid-rt");
    (validateAccessToken as any).mockResolvedValue(false);
    (refreshTokens as any).mockResolvedValue({
      access_token: "new-at",
      refresh_token: "new-rt",
      expires_in: 300,
    });

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/page"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(true);
    expect(refreshTokens).toHaveBeenCalled();
  });

  it("Case 2: only refresh token → tries refresh", async () => {
    const cookies = createMockCookies();
    cookies._store.set("t_refresh_token", "valid-rt");
    (refreshTokens as any).mockResolvedValue({
      access_token: "new-at",
      refresh_token: "new-rt",
      expires_in: 300,
    });

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/page"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(true);
  });

  it("Case 2: refresh fails → failure", async () => {
    const cookies = createMockCookies();
    cookies._store.set("t_refresh_token", "expired-rt");
    (refreshTokens as any).mockResolvedValue(undefined);

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/page"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("Case 3: OIDC callback with code verifier → exchanges code", async () => {
    const cookies = createMockCookies();
    cookies._store.set("t_code_verifier", "verifier-123");
    (isOidcCallback as any).mockReturnValue(true);
    (exchangeCode as any).mockResolvedValue({
      access_token: "new-at",
      refresh_token: "new-rt",
      expires_in: 300,
    });

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/callback?code=abc"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(true);
    expect(exchangeCode).toHaveBeenCalled();
  });

  it("Case 3: OIDC callback without code verifier → failure", async () => {
    const cookies = createMockCookies();
    (isOidcCallback as any).mockReturnValue(true);

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/callback?code=abc"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("Case 3: OIDC callback with state mismatch → failure (CSRF)", async () => {
    const cookies = createMockCookies();
    cookies._store.set("t_code_verifier", "verifier-123");
    cookies._store.set("t_oauth_state", "correct-state");
    (isOidcCallback as any).mockReturnValue(true);

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/callback?code=abc&state=wrong-state"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(false);
    expect(exchangeCode).not.toHaveBeenCalled();
  });

  it("Case 3: OIDC callback with matching state → proceeds", async () => {
    const cookies = createMockCookies();
    cookies._store.set("t_code_verifier", "verifier-123");
    cookies._store.set("t_oauth_state", "correct-state");
    (isOidcCallback as any).mockReturnValue(true);
    (exchangeCode as any).mockResolvedValue({
      access_token: "new-at",
      refresh_token: "new-rt",
      expires_in: 300,
    });

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/callback?code=abc&state=correct-state"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(true);
    // State cookie should be cleaned up
    expect(cookies._store.has("t_oauth_state")).toBe(false);
  });

  it("Case 4: no tokens, not callback → failure", async () => {
    const cookies = createMockCookies();

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/page"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("Case 3: OIDC callback with unauthorized_client → throws", async () => {
    const cookies = createMockCookies();
    cookies._store.set("t_code_verifier", "verifier-123");
    (isOidcCallback as any).mockReturnValue(true);
    (exchangeCode as any).mockRejectedValue({ error: "unauthorized_client" });

    await expect(authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/callback?code=abc"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    })).rejects.toThrow("Invalid client credentials");
  });

  it("Case 3: OIDC callback with invalid_grant → failure (no throw)", async () => {
    const cookies = createMockCookies();
    cookies._store.set("t_code_verifier", "verifier-123");
    (isOidcCallback as any).mockReturnValue(true);
    (exchangeCode as any).mockRejectedValue({ error: "invalid_grant", message: "bad grant" });

    const result = await authenticate({
      oidcConfig: mockOidcConfig,
      cookies,
      url: new URL("https://app.com/callback?code=abc"),
      origin: "https://app.com",
      cookieNames,
      cookieOptions,
    });

    expect(result.success).toBe(false);
  });
});

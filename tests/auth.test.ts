import { describe, it, expect } from "vitest";
import { handleAuthSuccess, handleAuthFailure } from "../src/core/auth.js";
import type { CookieAdapter, CookieNames, CookieSerializeOptions } from "../src/core/types.js";
import { DEFAULT_REFRESH_TOKEN_MAX_AGE } from "../src/core/config.js";

function createMockCookies(): CookieAdapter & { _store: Map<string, { value: string; options: any }> } {
  const store = new Map<string, { value: string; options: any }>();
  return {
    get: (name: string) => store.get(name)?.value,
    set: (name: string, value: string, options: any) => store.set(name, { value, options }),
    delete: (name: string, options: any) => store.delete(name),
    _store: store,
  };
}

const cookieNames: CookieNames = {
  accessToken: "test_access_token",
  refreshToken: "test_refresh_token",
  codeVerifier: "test_code_verifier",
  tempSessionId: "test_temp_session_id",
  authSessionId: "test_auth_session_id",
  oauthState: "test_oauth_state",
};

const cookieOptions: CookieSerializeOptions = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
};

const createTestToken = (payload: Record<string, unknown>): string => {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.test-signature`;
};

describe("handleAuthSuccess", () => {
  it("should use default refresh token max age (30 days)", () => {
    const cookies = createMockCookies();
    const token = createTestToken({
      sub: "user-1",
      active_tenant: {},
      all_tenants: [],
      realm_access: { roles: [] },
    });

    handleAuthSuccess(cookies, cookieNames, cookieOptions, token, "refresh-token", 300);

    const refreshCookie = cookies._store.get("test_refresh_token");
    expect(refreshCookie?.options.maxAge).toBe(DEFAULT_REFRESH_TOKEN_MAX_AGE);
    expect(DEFAULT_REFRESH_TOKEN_MAX_AGE).toBe(60 * 60 * 24 * 30); // 30 days
  });

  it("should use custom refresh token max age", () => {
    const cookies = createMockCookies();
    const token = createTestToken({
      sub: "user-1",
      active_tenant: {},
      all_tenants: [],
      realm_access: { roles: [] },
    });

    handleAuthSuccess(cookies, cookieNames, cookieOptions, token, "refresh-token", 300, 86400);

    const refreshCookie = cookies._store.get("test_refresh_token");
    expect(refreshCookie?.options.maxAge).toBe(86400);
  });
});

describe("handleAuthFailure", () => {
  it("should clear all auth cookies", () => {
    const cookies = createMockCookies();
    cookies.set("test_access_token", "at", cookieOptions);
    cookies.set("test_refresh_token", "rt", cookieOptions);

    handleAuthFailure(cookies, cookieNames, cookieOptions);

    expect(cookies._store.has("test_access_token")).toBe(false);
    expect(cookies._store.has("test_refresh_token")).toBe(false);
  });
});

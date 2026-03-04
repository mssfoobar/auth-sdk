import { describe, it, expect, vi, beforeEach } from "vitest";
import { createAuthRoutes } from "../src/adapters/sveltekit/routes.js";

// Mock @sveltejs/kit
vi.mock("@sveltejs/kit", () => ({
  json: (body: any, init?: any) => ({ body, status: init?.status ?? 200, headers: init?.headers }),
  redirect: (status: number, location: string) => {
    throw { status, location, _redirect: true };
  },
}));

// Mock openid-client
vi.mock("openid-client", () => ({
  refreshTokenGrant: vi.fn(),
}));

// Mock oidc module
vi.mock("../src/core/oidc.js", () => ({
  pkce: {
    generateVerifier: vi.fn(() => "test-verifier"),
    calculateChallenge: vi.fn(async () => "test-challenge"),
  },
  buildLoginUrl: vi.fn((_config, redirectUri, challenge, _scope, state) => {
    const url = new URL("https://keycloak.example.com/auth");
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("code_challenge", challenge);
    if (state) url.searchParams.set("state", state);
    return url;
  }),
  buildLogoutUrl: vi.fn((_config, postLogoutUri) => {
    return new URL(`https://keycloak.example.com/logout?post_logout_redirect_uri=${encodeURIComponent(postLogoutUri)}`);
  }),
}));

import { refreshTokenGrant } from "openid-client";

function createMockCookies() {
  const store = new Map<string, string>();
  return {
    get: (name: string) => store.get(name),
    set: (name: string, value: string, _opts?: any) => store.set(name, value),
    delete: (name: string, _opts?: any) => store.delete(name),
    _store: store,
  };
}

const mockOidcConfig = {} as any;

describe("login handler", () => {
  const routes = createAuthRoutes({
    origin: "https://app.com",
    cookie: { prefix: "test" },
  });

  it("should redirect to OIDC provider", async () => {
    const cookies = createMockCookies();
    const result = await routes.login({
      cookies,
      locals: { clients: { oidc_config: mockOidcConfig } },
    });

    expect(result.status).toBe(307);
    expect(result.headers?.Location).toContain("keycloak.example.com/auth");
  });

  it("should store code verifier in cookie", async () => {
    const cookies = createMockCookies();
    await routes.login({
      cookies,
      locals: { clients: { oidc_config: mockOidcConfig } },
    });

    expect(cookies._store.get("test_code_verifier")).toBe("test-verifier");
  });

  it("should store oauth state in cookie", async () => {
    const cookies = createMockCookies();
    await routes.login({
      cookies,
      locals: { clients: { oidc_config: mockOidcConfig } },
    });

    // State cookie should be set
    expect(cookies._store.has("test_oauth_state")).toBe(true);
  });

  it("should throw when OIDC config not in locals", async () => {
    const cookies = createMockCookies();
    await expect(routes.login({
      cookies,
      locals: {},
    })).rejects.toThrow("OIDC config not found");
  });
});

describe("logout handler", () => {
  it("should clear cookies and redirect (cookie-based)", async () => {
    const routes = createAuthRoutes({
      origin: "https://app.com",
      cookie: { prefix: "test" },
    });

    const cookies = createMockCookies();
    cookies._store.set("test_access_token", "at");
    cookies._store.set("test_refresh_token", "rt");
    let locationHeader = "";

    const result = await routes.logout({
      cookies,
      locals: { clients: { oidc_config: mockOidcConfig } },
      setHeaders: (headers: any) => { locationHeader = headers.Location; },
    });

    expect(result.status).toBe(307);
    expect(cookies._store.has("test_access_token")).toBe(false);
    expect(cookies._store.has("test_refresh_token")).toBe(false);
  });

  it("should destroy SDS session on logout", async () => {
    const mockSdsClient = {
      authSessionDestroy: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
    };

    const routes = createAuthRoutes({
      origin: "https://app.com",
      cookie: { prefix: "test" },
      createSdsClient: async () => mockSdsClient as any,
    });

    const cookies = createMockCookies();
    cookies._store.set("test_auth_session_id", "session-123");
    let locationHeader = "";

    await routes.logout({
      cookies,
      locals: {},
      setHeaders: (headers: any) => { locationHeader = headers.Location; },
    });

    expect(mockSdsClient.authSessionDestroy).toHaveBeenCalledWith("session-123");
    expect(mockSdsClient.close).toHaveBeenCalled();
  });
});

describe("refresh handler", () => {
  it("should refresh tokens (cookie-based)", async () => {
    (refreshTokenGrant as any).mockResolvedValue({
      access_token: "new-at",
      refresh_token: "new-rt",
      expires_in: 300,
    });

    const routes = createAuthRoutes({
      origin: "https://app.com",
      cookie: { prefix: "test" },
    });

    const cookies = createMockCookies();
    cookies._store.set("test_refresh_token", "old-rt");

    const result = await routes.refresh({
      cookies,
      locals: { clients: { oidc_config: mockOidcConfig } },
    });

    expect(result.status).toBe(200);
    expect(cookies._store.get("test_access_token")).toBe("new-at");
  });

  it("should return 401 when no refresh token", async () => {
    const routes = createAuthRoutes({
      origin: "https://app.com",
      cookie: { prefix: "test" },
    });

    const cookies = createMockCookies();
    const result = await routes.refresh({
      cookies,
      locals: { clients: { oidc_config: mockOidcConfig } },
    });

    expect(result.status).toBe(401);
  });

  it("should return 401 when refresh fails", async () => {
    (refreshTokenGrant as any).mockRejectedValue(new Error("token expired"));

    const routes = createAuthRoutes({
      origin: "https://app.com",
      cookie: { prefix: "test" },
    });

    const cookies = createMockCookies();
    cookies._store.set("test_refresh_token", "expired-rt");

    const result = await routes.refresh({
      cookies,
      locals: { clients: { oidc_config: mockOidcConfig } },
    });

    expect(result.status).toBe(401);
  });

  it("should refresh via SDS", async () => {
    const mockSdsClient = {
      authSessionGetAccessToken: vi.fn().mockResolvedValue("sds-at"),
      close: vi.fn().mockResolvedValue(undefined),
    };

    const routes = createAuthRoutes({
      origin: "https://app.com",
      cookie: { prefix: "test" },
      createSdsClient: async () => mockSdsClient as any,
    });

    const cookies = createMockCookies();
    cookies._store.set("test_auth_session_id", "session-123");

    const result = await routes.refresh({
      cookies,
      locals: {},
    });

    expect(result.status).toBe(200);
    expect(mockSdsClient.close).toHaveBeenCalled();
  });
});

describe("getContext handler", () => {
  it("should return current context value", async () => {
    const routes = createAuthRoutes({
      origin: "https://app.com",
      cookie: { prefix: "test" },
    });

    const cookies = createMockCookies();
    cookies._store.set("context_value", "tenant-abc");

    const result = await routes.getContext({ cookies });
    expect(result.body).toEqual({ context: "tenant-abc" });
  });

  it("should return undefined when no context set", async () => {
    const routes = createAuthRoutes({
      origin: "https://app.com",
      cookie: { prefix: "test" },
    });

    const cookies = createMockCookies();
    const result = await routes.getContext({ cookies });
    expect(result.body).toEqual({ context: undefined });
  });
});

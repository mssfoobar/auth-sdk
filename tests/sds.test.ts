import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  authenticateWithSds,
  handleSdsAuthSuccess,
  handleSdsAuthFailure,
  storeCodeVerifierInSds,
  destroySdsSession,
  SDS_SESSION_KEYS,
} from "../src/core/sds.js";
import type { CookieAdapter, CookieNames, CookieSerializeOptions } from "../src/core/types.js";

vi.mock("../src/core/oidc.js", () => ({
  isOidcCallback: vi.fn(),
  exchangeCode: vi.fn(),
}));

vi.mock("../src/core/tokens.js", () => ({
  decodeAccessToken: vi.fn(() => ({ sub: "user-123", active_tenant: {}, all_tenants: [], realm_access: { roles: [] } })),
}));

import { isOidcCallback, exchangeCode } from "../src/core/oidc.js";
const mockIsCallback = vi.mocked(isOidcCallback);
const mockExchangeCode = vi.mocked(exchangeCode);

const cookieNames: CookieNames = {
  accessToken: "at", refreshToken: "rt", codeVerifier: "cv",
  tempSessionId: "ts", authSessionId: "as",
};
const cookieOptions: CookieSerializeOptions = { path: "/" };

function createMockCookies(store: Record<string, string> = {}): CookieAdapter {
  return {
    get: vi.fn((name: string) => store[name]),
    set: vi.fn((name: string, value: string) => { store[name] = value; }),
    delete: vi.fn((name: string) => { delete store[name]; }),
  };
}

function createMockSdsClient(overrides: Record<string, any> = {}) {
  return {
    connect: vi.fn(),
    close: vi.fn(),
    on: vi.fn(),
    tempSessionNew: vi.fn().mockResolvedValue("temp-123"),
    tempSessionGet: vi.fn().mockResolvedValue("verifier"),
    tempSessionSet: vi.fn(),
    authSessionNew: vi.fn().mockResolvedValue("auth-456"),
    authSessionGetAccessToken: vi.fn().mockResolvedValue("access-token"),
    authSessionDestroy: vi.fn(),
    ...overrides,
  };
}

describe("authenticateWithSds", () => {
  beforeEach(() => vi.clearAllMocks());

  it("returns success when auth session exists", async () => {
    const cookies = createMockCookies({ as: "session-id" });
    const sds = createMockSdsClient();

    const result = await authenticateWithSds({
      oidcConfig: {} as any, cookies, url: new URL("http://localhost/"),
      origin: "http://localhost", sdsClient: sds, cookieNames, cookieOptions,
    });

    expect(result.success).toBe(true);
  });

  it("returns failure when SDS session is invalid", async () => {
    const cookies = createMockCookies({ as: "bad-session" });
    const sds = createMockSdsClient({
      authSessionGetAccessToken: vi.fn().mockRejectedValue(new Error("not found")),
    });

    const result = await authenticateWithSds({
      oidcConfig: {} as any, cookies, url: new URL("http://localhost/"),
      origin: "http://localhost", sdsClient: sds, cookieNames, cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("handles OIDC callback with SDS", async () => {
    const cookies = createMockCookies({ ts: "temp-123" });
    const sds = createMockSdsClient();
    mockIsCallback.mockReturnValue(true);
    mockExchangeCode.mockResolvedValue({ access_token: "at", refresh_token: "rt" } as any);

    const result = await authenticateWithSds({
      oidcConfig: {} as any, cookies, url: new URL("http://localhost/cb?code=x&session_state=y"),
      origin: "http://localhost", sdsClient: sds, cookieNames, cookieOptions,
    });

    expect(result.success).toBe(true);
    expect(sds.authSessionNew).toHaveBeenCalled();
  });

  it("fails callback without temp session", async () => {
    const cookies = createMockCookies({});
    const sds = createMockSdsClient();
    mockIsCallback.mockReturnValue(true);

    const result = await authenticateWithSds({
      oidcConfig: {} as any, cookies, url: new URL("http://localhost/cb?code=x&session_state=y"),
      origin: "http://localhost", sdsClient: sds, cookieNames, cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("fails callback when code verifier retrieval fails", async () => {
    const cookies = createMockCookies({ ts: "temp-123" });
    const sds = createMockSdsClient({
      tempSessionGet: vi.fn().mockRejectedValue(new Error("not found")),
    });
    mockIsCallback.mockReturnValue(true);

    const result = await authenticateWithSds({
      oidcConfig: {} as any, cookies, url: new URL("http://localhost/cb?code=x&session_state=y"),
      origin: "http://localhost", sdsClient: sds, cookieNames, cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("handles invalid_grant on callback", async () => {
    const cookies = createMockCookies({ ts: "temp-123" });
    const sds = createMockSdsClient();
    mockIsCallback.mockReturnValue(true);
    const err: any = new Error("invalid_grant");
    err.error = "invalid_grant";
    mockExchangeCode.mockRejectedValue(err);

    const result = await authenticateWithSds({
      oidcConfig: {} as any, cookies, url: new URL("http://localhost/cb?code=x&session_state=y"),
      origin: "http://localhost", sdsClient: sds, cookieNames, cookieOptions,
    });

    expect(result.success).toBe(false);
  });

  it("throws on unauthorized_client", async () => {
    const cookies = createMockCookies({ ts: "temp-123" });
    const sds = createMockSdsClient();
    mockIsCallback.mockReturnValue(true);
    const err: any = new Error("unauthorized_client");
    err.error = "unauthorized_client";
    mockExchangeCode.mockRejectedValue(err);

    await expect(authenticateWithSds({
      oidcConfig: {} as any, cookies, url: new URL("http://localhost/cb?code=x&session_state=y"),
      origin: "http://localhost", sdsClient: sds, cookieNames, cookieOptions,
    })).rejects.toThrow("Invalid client credentials");
  });

  it("returns failure when no session and not callback", async () => {
    const cookies = createMockCookies({});
    const sds = createMockSdsClient();
    mockIsCallback.mockReturnValue(false);

    const result = await authenticateWithSds({
      oidcConfig: {} as any, cookies, url: new URL("http://localhost/"),
      origin: "http://localhost", sdsClient: sds, cookieNames, cookieOptions,
    });

    expect(result.success).toBe(false);
  });
});

describe("handleSdsAuthSuccess", () => {
  it("sets session cookie and returns success", () => {
    const cookies = createMockCookies();
    const result = handleSdsAuthSuccess(cookies, cookieNames, cookieOptions, "at", "sess-id");

    expect(result.success).toBe(true);
    expect(result.accessToken).toBe("at");
    expect(cookies.set).toHaveBeenCalled();
  });
});

describe("handleSdsAuthFailure", () => {
  it("clears cookies", () => {
    const cookies = createMockCookies();
    const result = handleSdsAuthFailure(cookies, cookieNames, cookieOptions);

    expect(result.success).toBe(false);
    expect(cookies.delete).toHaveBeenCalledTimes(2);
  });
});

describe("storeCodeVerifierInSds", () => {
  it("stores code verifier in temp session", async () => {
    const cookies = createMockCookies();
    const sds = createMockSdsClient();

    await storeCodeVerifierInSds(sds, cookies, cookieNames, cookieOptions, "verifier");

    expect(sds.tempSessionNew).toHaveBeenCalled();
    expect(sds.tempSessionSet).toHaveBeenCalledWith("temp-123", SDS_SESSION_KEYS.CODE_VERIFIER, "verifier");
    expect(cookies.set).toHaveBeenCalled();
  });

  it("throws when SDS fails", async () => {
    const cookies = createMockCookies();
    const sds = createMockSdsClient({
      tempSessionNew: vi.fn().mockRejectedValue(new Error("SDS down")),
    });

    await expect(storeCodeVerifierInSds(sds, cookies, cookieNames, cookieOptions, "verifier"))
      .rejects.toThrow("SDS down");
  });
});

describe("destroySdsSession", () => {
  it("destroys session when present", async () => {
    const cookies = createMockCookies({ as: "sess-id" });
    const sds = createMockSdsClient();

    await destroySdsSession(sds, cookies, cookieNames, cookieOptions);

    expect(sds.authSessionDestroy).toHaveBeenCalledWith("sess-id");
    expect(cookies.delete).toHaveBeenCalled();
  });

  it("handles missing session gracefully", async () => {
    const cookies = createMockCookies({});
    const sds = createMockSdsClient();

    await destroySdsSession(sds, cookies, cookieNames, cookieOptions);

    expect(sds.authSessionDestroy).not.toHaveBeenCalled();
    expect(cookies.delete).toHaveBeenCalled();
  });

  it("handles destroy error gracefully", async () => {
    const cookies = createMockCookies({ as: "sess-id" });
    const sds = createMockSdsClient({
      authSessionDestroy: vi.fn().mockRejectedValue(new Error("fail")),
    });

    await destroySdsSession(sds, cookies, cookieNames, cookieOptions);
    // Should not throw
    expect(cookies.delete).toHaveBeenCalled();
  });
});

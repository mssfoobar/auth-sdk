import { describe, it, expect, vi } from "vitest";
import { createAuthRoutes } from "../src/adapters/sveltekit/routes.js";

// Mock @sveltejs/kit
vi.mock("@sveltejs/kit", () => ({
  json: (body: any, init?: any) => ({ body, status: init?.status ?? 200, headers: init?.headers }),
  redirect: (status: number, location: string) => {
    throw { status, location };
  },
}));

function createMockCookies() {
  const store = new Map<string, string>();
  return {
    get: (name: string) => store.get(name),
    set: (name: string, value: string, _opts?: any) => store.set(name, value),
    delete: (name: string, _opts?: any) => store.delete(name),
    _store: store,
  };
}

describe("callback - open redirect prevention", () => {
  const routes = createAuthRoutes({
    origin: "https://example.com",
    cookie: { prefix: "test" },
  });

  it("should redirect to relative URL", async () => {
    const cookies = createMockCookies();
    cookies.set("aoh_redirect_after_auth", "/dashboard");

    try {
      await routes.callback({ cookies });
      expect.fail("Should have thrown redirect");
    } catch (e: any) {
      expect(e.status).toBe(307);
      expect(e.location).toBe("/dashboard");
    }
  });

  it("should NOT redirect to absolute URL (open redirect)", async () => {
    const cookies = createMockCookies();
    cookies.set("aoh_redirect_after_auth", "https://evil.com");

    try {
      await routes.callback({ cookies });
      expect.fail("Should have thrown redirect");
    } catch (e: any) {
      // Should redirect to default destination, not evil.com
      expect(e.status).toBe(307);
      expect(e.location).toBe("/");
    }
  });

  it("should NOT redirect to protocol-relative URL", async () => {
    const cookies = createMockCookies();
    cookies.set("aoh_redirect_after_auth", "//evil.com");

    try {
      await routes.callback({ cookies });
      expect.fail("Should have thrown redirect");
    } catch (e: any) {
      expect(e.status).toBe(307);
      expect(e.location).toBe("/");
    }
  });
});

describe("setContext - input validation", () => {
  const routes = createAuthRoutes({
    origin: "https://example.com",
    cookie: { prefix: "test" },
  });

  it("should accept valid context value", async () => {
    const cookies = createMockCookies();
    const result = await routes.setContext({
      cookies,
      setHeaders: () => {},
      params: { value: "my-context_123" },
    });
    expect(result.status).toBe(307);
  });

  it("should reject empty context value", async () => {
    const cookies = createMockCookies();
    const result = await routes.setContext({
      cookies,
      setHeaders: () => {},
      params: { value: "" },
    });
    expect(result.status).toBe(400);
  });

  it("should reject context value exceeding 128 chars", async () => {
    const cookies = createMockCookies();
    const result = await routes.setContext({
      cookies,
      setHeaders: () => {},
      params: { value: "a".repeat(129) },
    });
    expect(result.status).toBe(400);
  });

  it("should reject context value with special characters", async () => {
    const cookies = createMockCookies();
    const result = await routes.setContext({
      cookies,
      setHeaders: () => {},
      params: { value: "hello world!" },
    });
    expect(result.status).toBe(400);
  });

  it("should accept UUID-like value", async () => {
    const cookies = createMockCookies();
    const result = await routes.setContext({
      cookies,
      setHeaders: () => {},
      params: { value: "550e8400-e29b-41d4-a716-446655440000" },
    });
    expect(result.status).toBe(307);
  });
});

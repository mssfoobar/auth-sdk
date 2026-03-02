import { describe, it, expect, vi } from "vitest";
import { sveltekitCookieAdapter } from "../src/adapters/sveltekit/cookies.js";

describe("sveltekitCookieAdapter", () => {
  function createMockSvelteKitCookies() {
    return {
      get: vi.fn((name: string) => name === "test" ? "value" : undefined),
      set: vi.fn(),
      delete: vi.fn(),
      getAll: vi.fn(),
      serialize: vi.fn(),
    };
  }

  it("get delegates to SvelteKit cookies", () => {
    const skCookies = createMockSvelteKitCookies();
    const adapter = sveltekitCookieAdapter(skCookies as any);

    expect(adapter.get("test")).toBe("value");
    expect(adapter.get("missing")).toBeUndefined();
  });

  it("set delegates with proper options", () => {
    const skCookies = createMockSvelteKitCookies();
    const adapter = sveltekitCookieAdapter(skCookies as any);

    adapter.set("name", "val", { domain: "example.com", path: "/app", secure: true, httpOnly: true, sameSite: "strict", maxAge: 3600 });

    expect(skCookies.set).toHaveBeenCalledWith("name", "val", {
      domain: "example.com", path: "/app", secure: true, httpOnly: true, sameSite: "strict", maxAge: 3600,
    });
  });

  it("set uses default path when not specified", () => {
    const skCookies = createMockSvelteKitCookies();
    const adapter = sveltekitCookieAdapter(skCookies as any);

    adapter.set("name", "val", {});

    expect(skCookies.set).toHaveBeenCalledWith("name", "val", expect.objectContaining({ path: "/" }));
  });

  it("delete delegates with proper options", () => {
    const skCookies = createMockSvelteKitCookies();
    const adapter = sveltekitCookieAdapter(skCookies as any);

    adapter.delete("name", { domain: "example.com", path: "/app", secure: true, httpOnly: true, sameSite: "lax" });

    expect(skCookies.delete).toHaveBeenCalledWith("name", {
      domain: "example.com", path: "/app", secure: true, httpOnly: true, sameSite: "lax",
    });
  });
});

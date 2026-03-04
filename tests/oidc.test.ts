import { describe, it, expect } from "vitest";
import { isOidcCallback } from "../src/core/oidc.js";

describe("isOidcCallback", () => {
  it("should return true when URL has code parameter", () => {
    const url = new URL("https://example.com/callback?code=abc123");
    expect(isOidcCallback(url)).toBe(true);
  });

  it("should return true when URL has code and session_state", () => {
    const url = new URL("https://example.com/callback?code=abc123&session_state=xyz");
    expect(isOidcCallback(url)).toBe(true);
  });

  it("should return false when URL has no code parameter", () => {
    const url = new URL("https://example.com/callback?session_state=xyz");
    expect(isOidcCallback(url)).toBe(false);
  });

  it("should return false for plain URL", () => {
    const url = new URL("https://example.com/callback");
    expect(isOidcCallback(url)).toBe(false);
  });
});

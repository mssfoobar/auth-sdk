import { describe, it, expect } from "vitest";
import {
  getCookieNames,
  buildCookieOptions,
  withExpiry,
  validateAuthConfig,
} from "../src/core/config.js";

describe("getCookieNames", () => {
  it("should generate cookie names with prefix", () => {
    const names = getCookieNames("myapp");
    
    expect(names.accessToken).toBe("myapp_access_token");
    expect(names.refreshToken).toBe("myapp_refresh_token");
    expect(names.codeVerifier).toBe("myapp_code_verifier");
    expect(names.tempSessionId).toBe("myapp_temp_session_id");
    expect(names.authSessionId).toBe("myapp_auth_session_id");
  });
});

describe("buildCookieOptions", () => {
  it("should set secure=true for HTTPS origin", () => {
    const options = buildCookieOptions(
      { prefix: "test", domain: "example.com" },
      "https://example.com"
    );
    
    expect(options.secure).toBe(true);
    expect(options.httpOnly).toBe(true);
    expect(options.sameSite).toBe("lax");
  });
  
  it("should set secure=false for HTTP origin", () => {
    const options = buildCookieOptions(
      { prefix: "test" },
      "http://localhost:3000"
    );
    
    expect(options.secure).toBe(false);
  });
  
  it("should respect custom sameSite setting", () => {
    const options = buildCookieOptions(
      { prefix: "test", sameSite: "strict" },
      "https://example.com"
    );
    
    expect(options.sameSite).toBe("strict");
  });
});

describe("withExpiry", () => {
  it("should add maxAge to options", () => {
    const baseOptions = { path: "/", secure: true };
    const withMaxAge = withExpiry(baseOptions, 3600);
    
    expect(withMaxAge.maxAge).toBe(3600);
    expect(withMaxAge.path).toBe("/");
    expect(withMaxAge.secure).toBe(true);
  });
});

describe("validateAuthConfig", () => {
  it("should return empty array for valid config", () => {
    const missing = validateAuthConfig({
      issuerUrl: "https://auth.example.com",
      clientId: "my-client",
      origin: "https://app.example.com",
    });
    
    expect(missing).toEqual([]);
  });
  
  it("should return missing fields", () => {
    const missing = validateAuthConfig({
      clientId: "my-client",
    });
    
    expect(missing).toContain("issuerUrl");
    expect(missing).toContain("origin");
    expect(missing).not.toContain("clientId");
  });
  
  it("should return all missing fields for empty config", () => {
    const missing = validateAuthConfig({});
    
    expect(missing).toContain("issuerUrl");
    expect(missing).toContain("clientId");
    expect(missing).toContain("origin");
  });
});

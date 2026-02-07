import { describe, it, expect } from "vitest";
import {
  decodeAccessToken,
  isTenantAdmin,
  getTenantIds,
  getActiveTenantId,
  getRealmRoles,
  hasRealmRole,
} from "../src/core/tokens.js";

// Sample JWT with multi-tenant claims (base64 encoded payload)
const createTestToken = (payload: Record<string, unknown>): string => {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = "test-signature";
  return `${header}.${body}.${signature}`;
};

describe("decodeAccessToken", () => {
  it("should decode claims from JWT", () => {
    const token = createTestToken({
      sub: "user-123",
      active_tenant: { tenant_id: "t1", tenant_name: "Tenant 1", roles: ["admin"] },
      all_tenants: [{ tenant_id: "t1", tenant_name: "Tenant 1" }],
      realm_access: { roles: ["user"] },
    });
    
    const claims = decodeAccessToken(token);
    
    expect(claims.sub).toBe("user-123");
    expect(claims.active_tenant.tenant_id).toBe("t1");
  });
});

describe("isTenantAdmin", () => {
  it("should return true when user has tenant-admin role", () => {
    const token = createTestToken({
      sub: "user-123",
      active_tenant: { tenant_id: "t1", roles: ["tenant-admin", "user"] },
      all_tenants: [],
      realm_access: { roles: [] },
    });
    
    expect(isTenantAdmin(token)).toBe(true);
  });
  
  it("should return false when user lacks tenant-admin role", () => {
    const token = createTestToken({
      sub: "user-123",
      active_tenant: { tenant_id: "t1", roles: ["user"] },
      all_tenants: [],
      realm_access: { roles: [] },
    });
    
    expect(isTenantAdmin(token)).toBe(false);
  });
  
  it("should return false for invalid token", () => {
    expect(isTenantAdmin("invalid")).toBe(false);
  });
});

describe("getTenantIds", () => {
  it("should return all tenant IDs", () => {
    const token = createTestToken({
      sub: "user-123",
      active_tenant: { tenant_id: "t1" },
      all_tenants: [
        { tenant_id: "t1", tenant_name: "Tenant 1" },
        { tenant_id: "t2", tenant_name: "Tenant 2" },
      ],
      realm_access: { roles: [] },
    });
    
    expect(getTenantIds(token)).toEqual(["t1", "t2"]);
  });
  
  it("should return empty array for invalid token", () => {
    expect(getTenantIds("invalid")).toEqual([]);
  });
});

describe("getActiveTenantId", () => {
  it("should return active tenant ID", () => {
    const token = createTestToken({
      sub: "user-123",
      active_tenant: { tenant_id: "t1", tenant_name: "Tenant 1" },
      all_tenants: [],
      realm_access: { roles: [] },
    });
    
    expect(getActiveTenantId(token)).toBe("t1");
  });
  
  it("should return undefined for invalid token", () => {
    expect(getActiveTenantId("invalid")).toBeUndefined();
  });
});

describe("getRealmRoles", () => {
  it("should return realm roles", () => {
    const token = createTestToken({
      sub: "user-123",
      active_tenant: {},
      all_tenants: [],
      realm_access: { roles: ["admin", "user", "moderator"] },
    });
    
    expect(getRealmRoles(token)).toEqual(["admin", "user", "moderator"]);
  });
  
  it("should return empty array for invalid token", () => {
    expect(getRealmRoles("invalid")).toEqual([]);
  });
});

describe("hasRealmRole", () => {
  it("should return true when user has role", () => {
    const token = createTestToken({
      sub: "user-123",
      active_tenant: {},
      all_tenants: [],
      realm_access: { roles: ["admin", "user"] },
    });
    
    expect(hasRealmRole(token, "admin")).toBe(true);
  });
  
  it("should return false when user lacks role", () => {
    const token = createTestToken({
      sub: "user-123",
      active_tenant: {},
      all_tenants: [],
      realm_access: { roles: ["user"] },
    });
    
    expect(hasRealmRole(token, "admin")).toBe(false);
  });
});

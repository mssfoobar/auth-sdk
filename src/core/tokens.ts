import {
  type Configuration,
  refreshTokenGrant,
  fetchUserInfo,
  type TokenEndpointResponse,
  type TokenEndpointResponseHelpers,
} from "openid-client";
import { jwtDecode } from "jwt-decode";
import * as jose from "jose";
import type { AuthClaims, Logger } from "./types.js";

/**
 * Cached JWKS remote key set (per JWKS URI)
 */
const jwksCache = new Map<string, ReturnType<typeof jose.createRemoteJWKSet>>();

/**
 * Get or create a cached JWKS key set for the given issuer
 */
function getJwks(issuerUrl: string): ReturnType<typeof jose.createRemoteJWKSet> {
  const jwksUri = issuerUrl.replace(/\/$/, "") + "/protocol/openid-connect/certs";
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = jose.createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
}

/**
 * Default no-op logger
 */
const noopLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

/**
 * Validate an access token using offline JWKS-based verification.
 * Falls back to the userinfo endpoint if local validation fails.
 * 
 * @param config - OIDC configuration
 * @param accessToken - Access token to validate
 * @param logger - Optional logger
 * @returns Whether the token is valid
 */
export async function validateAccessToken(
  config: Configuration,
  accessToken: string,
  logger: Logger = noopLogger
): Promise<boolean> {
  // Try offline (local) JWT validation first
  try {
    const decoded = jwtDecode(accessToken);
    
    if (!decoded.sub) {
      throw new Error("No sub claim in access token");
    }
    
    if (!decoded.iss) {
      throw new Error("No iss claim in access token");
    }
    
    const jwks = getJwks(decoded.iss);
    await jose.jwtVerify(accessToken, jwks, {
      issuer: decoded.iss,
    });
    
    // Token is valid (signature verified, exp checked by jose)
    logger.debug("Access token validated offline via JWKS");
    return true;
  } catch (error) {
    logger.debug("Offline JWT validation failed, falling back to userinfo", { message: (error as Error)?.message });
  }
  
  // Fallback: validate via userinfo endpoint
  try {
    const claims = jwtDecode(accessToken);
    
    if (!claims.sub) {
      throw new Error("No sub claim in access token");
    }
    
    await fetchUserInfo(config, accessToken, claims.sub);
    return true;
  } catch (error) {
    logger.error("Invalid access token detected", { message: (error as Error)?.message, code: (error as any)?.code });
    return false;
  }
}

/**
 * Refresh tokens using the refresh token
 * 
 * @param config - OIDC configuration
 * @param refreshToken - Refresh token
 * @param logger - Optional logger
 * @returns New token set or undefined if refresh failed
 */
export async function refreshTokens(
  config: Configuration,
  refreshToken: string,
  logger: Logger = noopLogger
): Promise<(TokenEndpointResponse & TokenEndpointResponseHelpers) | undefined> {
  logger.debug("Attempting to refresh tokens...");
  
  try {
    return await refreshTokenGrant(config, refreshToken);
  } catch (error) {
    logger.error("Token refresh failed", { message: (error as Error)?.message, code: (error as any)?.code });
    return undefined;
  }
}

/**
 * Decode claims from an access token
 * 
 * @param accessToken - JWT access token
 * @returns Decoded claims
 */
export function decodeAccessToken(accessToken: string): AuthClaims {
  return jwtDecode<AuthClaims>(accessToken);
}

/**
 * Check if the user has the tenant-admin role
 * 
 * @param accessToken - JWT access token
 * @param logger - Optional logger
 * @returns Whether user is a tenant admin
 */
export function isTenantAdmin(
  accessToken: string,
  logger: Logger = noopLogger
): boolean {
  try {
    const claims = decodeAccessToken(accessToken);
    return claims.active_tenant?.roles?.includes("tenant-admin") ?? false;
  } catch (error) {
    logger.error("Failed to decode access token", { message: (error as Error)?.message, code: (error as any)?.code });
    return false;
  }
}

/**
 * Get all tenant IDs from claims
 * 
 * @param accessToken - JWT access token
 * @returns Array of tenant IDs
 */
export function getTenantIds(accessToken: string): string[] {
  try {
    const claims = decodeAccessToken(accessToken);
    return claims.all_tenants
      ?.map((t) => t.tenant_id)
      .filter((id): id is string => id !== undefined) ?? [];
  } catch {
    return [];
  }
}

/**
 * Get the active tenant ID
 * 
 * @param accessToken - JWT access token
 * @returns Active tenant ID or undefined
 */
export function getActiveTenantId(accessToken: string): string | undefined {
  try {
    const claims = decodeAccessToken(accessToken);
    return claims.active_tenant?.tenant_id;
  } catch {
    return undefined;
  }
}

/**
 * Get user roles from the realm
 * 
 * @param accessToken - JWT access token
 * @returns Array of realm roles
 */
export function getRealmRoles(accessToken: string): string[] {
  try {
    const claims = decodeAccessToken(accessToken);
    return claims.realm_access?.roles ?? [];
  } catch {
    return [];
  }
}

/**
 * Check if user has a specific realm role
 * 
 * @param accessToken - JWT access token
 * @param role - Role to check
 * @returns Whether user has the role
 */
export function hasRealmRole(accessToken: string, role: string): boolean {
  return getRealmRoles(accessToken).includes(role);
}

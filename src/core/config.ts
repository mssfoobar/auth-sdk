import type { CookieConfig, CookieNames, CookieSerializeOptions, AuthConfig } from "./types.js";

/**
 * Default refresh token expiry (1 year in seconds)
 */
export const REFRESH_TOKEN_EXPIRY = 60 * 60 * 24 * 365; // 1 year

/**
 * Default context cookie max age (7 days)
 */
export const CONTEXT_COOKIE_MAX_AGE = 60 * 60 * 24 * 7;

/**
 * Generate cookie names with the configured prefix
 */
export function getCookieNames(prefix: string): CookieNames {
  return {
    accessToken: `${prefix}_access_token`,
    refreshToken: `${prefix}_refresh_token`,
    codeVerifier: `${prefix}_code_verifier`,
    tempSessionId: `${prefix}_temp_session_id`,
    authSessionId: `${prefix}_auth_session_id`,
  };
}

/**
 * Build default cookie options from config
 */
export function buildCookieOptions(
  config: CookieConfig,
  origin: string
): CookieSerializeOptions {
  return {
    domain: config.domain,
    path: config.path ?? "/",
    secure: origin.toLowerCase().startsWith("https://"),
    httpOnly: config.httpOnly ?? true,
    sameSite: config.sameSite ?? "lax",
  };
}

/**
 * Cookie options with custom expiry
 */
export function withExpiry(
  options: CookieSerializeOptions,
  maxAge: number
): CookieSerializeOptions {
  return { ...options, maxAge };
}

/**
 * Validate required auth configuration
 */
export function validateAuthConfig(config: Partial<AuthConfig>): string[] {
  const missing: string[] = [];
  
  if (!config.issuerUrl) missing.push("issuerUrl");
  if (!config.clientId) missing.push("clientId");
  if (!config.origin) missing.push("origin");
  
  return missing;
}

/**
 * @mssfoobar/auth-sdk
 * 
 * Authentication and Authorization SDK for OIDC/Keycloak with SDS support
 */

// Types
export type {
  Tenant,
  AuthClaims,
  AuthConfig,
  CookieConfig,
  CookieNames,
  CookieSerializeOptions,
  CookieAdapter,
  AuthResult,
  AuthResultSuccess,
  AuthResultFail,
  Logger,
} from "./core/types.js";

// Config utilities
export {
  REFRESH_TOKEN_EXPIRY,
  CONTEXT_COOKIE_MAX_AGE,
  getCookieNames,
  buildCookieOptions,
  withExpiry,
  validateAuthConfig,
} from "./core/config.js";

// Token utilities
export {
  validateAccessToken,
  refreshTokens,
  decodeAccessToken,
  isTenantAdmin,
  getTenantIds,
  getActiveTenantId,
  getRealmRoles,
  hasRealmRole,
} from "./core/tokens.js";

// OIDC utilities
export {
  initializeOidc,
  pkce,
  buildLoginUrl,
  buildLogoutUrl,
  exchangeCode,
  isOidcCallback,
} from "./core/oidc.js";

// Auth flow
export {
  authenticate,
  handleAuthSuccess,
  handleAuthFailure,
  type AuthenticateOptions,
} from "./core/auth.js";

// SDS integration
export {
  authenticateWithSds,
  handleSdsAuthSuccess,
  handleSdsAuthFailure,
  storeCodeVerifierInSds,
  destroySdsSession,
  SDS_SESSION_KEYS,
  type SdsClient,
  type SdsClientFactory,
  type SdsAuthenticateOptions,
} from "./core/sds.js";

/**
 * Tenant information from Keycloak claims
 */
export interface Tenant {
  tenant_name?: string;
  tenant_id?: string;
  roles?: string[];
}

/**
 * Extended claims with multi-tenant support
 * Note: Uses partial IDToken structure to avoid index signature conflicts
 */
export interface AuthClaims {
  // Core OIDC claims
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nonce?: string;
  auth_time?: number;
  
  // Profile claims
  name?: string;
  email?: string;
  preferred_username?: string;
  
  // Multi-tenant claims
  all_tenants: Tenant[];
  active_tenant: Tenant;
  realm_access: {
    roles: string[];
  };
  
  // Allow additional claims
  [key: string]: unknown;
}

/**
 * Auth configuration for OIDC setup
 */
export interface AuthConfig {
  /** IAM/Keycloak URL (issuer) */
  issuerUrl: string;
  /** OAuth client ID */
  clientId: string;
  /** Client secret (if using confidential client) */
  clientSecret?: string;
  /** Application origin URL */
  origin: string;
  /** Allow insecure requests (development only) */
  allowInsecureRequests?: boolean;
  /** Session Data Store URL (optional) */
  sdsUrl?: string;
}

/**
 * Cookie configuration
 */
export interface CookieConfig {
  /** Cookie domain */
  domain?: string;
  /** Cookie path (default: "/") */
  path?: string;
  /** Use secure cookies (HTTPS only) */
  secure?: boolean;
  /** HTTP-only flag */
  httpOnly?: boolean;
  /** SameSite attribute */
  sameSite?: "lax" | "strict" | "none";
  /** Cookie name prefix */
  prefix: string;
}

/**
 * Cookie names used by the auth SDK
 */
export interface CookieNames {
  accessToken: string;
  refreshToken: string;
  codeVerifier: string;
  tempSessionId: string;
  authSessionId: string;
}

/**
 * Successful authentication result
 */
export interface AuthResultSuccess {
  success: true;
  claims: AuthClaims;
  accessToken: string;
}

/**
 * Failed authentication result
 */
export interface AuthResultFail {
  success: false;
}

/**
 * Authentication result (union type)
 */
export type AuthResult = AuthResultSuccess | AuthResultFail;

/**
 * Generic cookie interface for framework-agnostic usage
 */
export interface CookieAdapter {
  get(name: string): string | undefined;
  set(name: string, value: string, options: CookieSerializeOptions): void;
  delete(name: string, options: CookieSerializeOptions): void;
}

/**
 * Cookie serialization options (matches 'cookie' package)
 */
export interface CookieSerializeOptions {
  domain?: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: "lax" | "strict" | "none";
  maxAge?: number;
}

/**
 * Logger interface for optional logging integration
 */
export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

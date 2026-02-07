import type { Handle, RequestEvent } from "@sveltejs/kit";
import type { Configuration } from "openid-client";
import {
  initializeOidc,
  authenticate,
  authenticateWithSds,
  getCookieNames,
  buildCookieOptions,
  type AuthConfig,
  type CookieConfig,
  type AuthResult,
  type Logger,
  type SdsClient,
} from "../../index.js";
import { sveltekitCookieAdapter } from "./cookies.js";

/**
 * Auth hooks configuration
 */
export interface AuthHooksConfig {
  /** Auth configuration */
  auth: AuthConfig;
  /** Cookie configuration */
  cookie: CookieConfig;
  /** Optional logger */
  logger?: Logger;
  /** SDS client factory (if using SDS) */
  createSdsClient?: () => Promise<SdsClient>;
  /** Paths to exclude from auth (e.g., public routes) */
  excludePaths?: string[];
  /** Custom frame ancestors for CSP */
  frameAncestors?: string;
  /** X-Frame-Options header value */
  xFrameOptions?: string;
}

/**
 * Extended locals for auth
 */
export interface AuthLocals {
  oidcConfig: Configuration;
  authResult: AuthResult;
  originalUrl?: string;
}

/**
 * Create SvelteKit handle hook with auth
 */
export function createAuthHooks(config: AuthHooksConfig): {
  handle: Handle;
  oidcConfig: Promise<Configuration>;
} {
  const cookieNames = getCookieNames(config.cookie.prefix);
  const cookieOptions = buildCookieOptions(config.cookie, config.auth.origin);
  const logger = config.logger ?? createNoopLogger();
  
  // Initialize OIDC once at startup
  const oidcConfigPromise = initializeOidc(config.auth, logger);
  
  const handle: Handle = async ({ event, resolve }) => {
    const oidcConfig = await oidcConfigPromise;
    let sdsClient: SdsClient | undefined;
    
    try {
      // Skip auth for excluded paths
      if (isExcludedPath(event.url.pathname, config.excludePaths)) {
        return await resolve(event);
      }
      
      const cookies = sveltekitCookieAdapter(event.cookies);
      let authResult: AuthResult;
      
      if (config.createSdsClient) {
        // SDS authentication flow
        sdsClient = await config.createSdsClient();
        authResult = await authenticateWithSds({
          oidcConfig,
          cookies,
          url: event.url,
          origin: config.auth.origin,
          sdsClient,
          cookieNames,
          cookieOptions,
          logger,
        });
      } else {
        // Basic authentication flow
        authResult = await authenticate({
          oidcConfig,
          cookies,
          url: event.url,
          origin: config.auth.origin,
          cookieNames,
          cookieOptions,
          logger,
        });
      }
      
      // Store in locals
      setAuthLocals(event, oidcConfig, authResult);
      
      // Store original URL for redirect after auth
      if (!authResult.success && !isAuthApiPath(event.url.pathname)) {
        (event.locals as Record<string, unknown>).originalUrl = 
          event.url.pathname + event.url.search;
      }
    } catch (err) {
      logger.error("Critical authentication failure", err);
      
      // In dev, throw to show error
      if (process.env.NODE_ENV === "development") {
        throw err;
      }
    } finally {
      if (sdsClient) {
        await sdsClient.close();
      }
    }
    
    const response = await resolve(event);
    
    // Set security headers
    if (config.frameAncestors) {
      response.headers.set(
        "Content-Security-Policy",
        `frame-ancestors ${config.frameAncestors};`
      );
    }
    
    if (config.xFrameOptions) {
      response.headers.set("X-Frame-Options", config.xFrameOptions);
    }
    
    return response;
  };
  
  return { handle, oidcConfig: oidcConfigPromise };
}

/**
 * Set auth data in SvelteKit locals
 */
function setAuthLocals(
  event: RequestEvent,
  oidcConfig: Configuration,
  authResult: AuthResult
): void {
  const locals = event.locals as Record<string, unknown>;
  locals.clients = { oidc_config: oidcConfig };
  locals.authResult = authResult;
}

/**
 * Check if path should skip auth
 */
function isExcludedPath(pathname: string, excludePaths?: string[]): boolean {
  if (!excludePaths) return false;
  return excludePaths.some((path) => pathname.startsWith(path));
}

/**
 * Check if path is an auth API endpoint
 */
function isAuthApiPath(pathname: string): boolean {
  return pathname.startsWith("/aoh/api/auth/");
}

/**
 * Create no-op logger
 */
function createNoopLogger(): Logger {
  return {
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
  };
}

import type { Configuration, ResponseBodyError } from "openid-client";
import type {
  AuthResult,
  AuthResultSuccess,
  AuthResultFail,
  CookieAdapter,
  CookieSerializeOptions,
  Logger,
  CookieNames,
} from "./types.js";
import { validateAccessToken, refreshTokens, decodeAccessToken } from "./tokens.js";
import { isOidcCallback, exchangeCode } from "./oidc.js";
import { REFRESH_TOKEN_EXPIRY, withExpiry } from "./config.js";

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
 * Authentication options
 */
export interface AuthenticateOptions {
  /** OIDC configuration */
  oidcConfig: Configuration;
  /** Cookie adapter */
  cookies: CookieAdapter;
  /** Current request URL */
  url: URL;
  /** Expected origin for callback validation */
  origin: string;
  /** Cookie names */
  cookieNames: CookieNames;
  /** Default cookie options */
  cookieOptions: CookieSerializeOptions;
  /** Optional logger */
  logger?: Logger;
}

/**
 * Main authentication handler
 * 
 * Validates access token, refreshes if needed, handles OIDC callback
 */
export async function authenticate(
  options: AuthenticateOptions
): Promise<AuthResult> {
  const {
    oidcConfig,
    cookies,
    url,
    origin,
    cookieNames,
    cookieOptions,
    logger = noopLogger,
  } = options;
  
  const accessToken = cookies.get(cookieNames.accessToken);
  const refreshToken = cookies.get(cookieNames.refreshToken);
  const codeVerifier = cookies.get(cookieNames.codeVerifier);
  
  // Case 1: Have both tokens - validate access token
  if (accessToken && refreshToken) {
    const isValid = await validateAccessToken(oidcConfig, accessToken, logger);
    
    if (isValid) {
      return handleAuthSuccess(cookies, cookieNames, cookieOptions, accessToken);
    }
    
    // Access token invalid, try refresh
    return await doRefresh(
      oidcConfig,
      refreshToken,
      cookies,
      cookieNames,
      cookieOptions,
      logger
    );
  }
  
  // Case 2: Only refresh token - try refresh
  if (refreshToken) {
    return await doRefresh(
      oidcConfig,
      refreshToken,
      cookies,
      cookieNames,
      cookieOptions,
      logger
    );
  }
  
  // Case 3: OIDC callback - exchange code for tokens
  if (isOidcCallback(url)) {
    return await handleOidcCallback(
      oidcConfig,
      url,
      origin,
      codeVerifier,
      cookies,
      cookieNames,
      cookieOptions,
      logger
    );
  }
  
  // Case 4: No auth - return failure
  return handleAuthFailure(cookies, cookieNames, cookieOptions);
}

/**
 * Perform token refresh
 */
async function doRefresh(
  oidcConfig: Configuration,
  refreshToken: string,
  cookies: CookieAdapter,
  cookieNames: CookieNames,
  cookieOptions: CookieSerializeOptions,
  logger: Logger
): Promise<AuthResult> {
  const newTokens = await refreshTokens(oidcConfig, refreshToken, logger);
  
  if (newTokens) {
    logger.debug("Tokens refreshed successfully");
    return handleAuthSuccess(
      cookies,
      cookieNames,
      cookieOptions,
      newTokens.access_token,
      newTokens.refresh_token,
      newTokens.expires_in
    );
  }
  
  logger.debug("Token refresh failed");
  return handleAuthFailure(cookies, cookieNames, cookieOptions);
}

/**
 * Handle OIDC callback (authorization code exchange)
 */
async function handleOidcCallback(
  oidcConfig: Configuration,
  url: URL,
  origin: string,
  codeVerifier: string | undefined,
  cookies: CookieAdapter,
  cookieNames: CookieNames,
  cookieOptions: CookieSerializeOptions,
  logger: Logger
): Promise<AuthResult> {
  if (!codeVerifier) {
    logger.error("No code verifier found for OIDC callback");
    return handleAuthFailure(cookies, cookieNames, cookieOptions);
  }
  
  const callbackUrl = new URL(origin + url.pathname + url.search);
  
  try {
    const tokenSet = await exchangeCode(oidcConfig, callbackUrl, codeVerifier);
    
    return handleAuthSuccess(
      cookies,
      cookieNames,
      cookieOptions,
      tokenSet.access_token,
      tokenSet.refresh_token,
      tokenSet.expires_in
    );
  } catch (err) {
    const error = err as ResponseBodyError;
    
    if (error.error === "invalid_grant") {
      logger.error("Invalid grant - check cookie forwarding and PUBLIC_DOMAIN");
    } else if (error.error === "unauthorized_client") {
      throw new Error("Invalid client credentials");
    }
    
    logger.error("OIDC callback failed", err);
    return handleAuthFailure(cookies, cookieNames, cookieOptions);
  }
}

/**
 * Set cookies and return success result
 */
export function handleAuthSuccess(
  cookies: CookieAdapter,
  cookieNames: CookieNames,
  cookieOptions: CookieSerializeOptions,
  accessToken: string,
  refreshToken?: string,
  expiresIn?: number
): AuthResultSuccess {
  // Set access token cookie
  if (expiresIn) {
    cookies.set(
      cookieNames.accessToken,
      accessToken,
      withExpiry(cookieOptions, expiresIn)
    );
  }
  
  // Set refresh token cookie
  if (refreshToken) {
    cookies.set(
      cookieNames.refreshToken,
      refreshToken,
      withExpiry(cookieOptions, REFRESH_TOKEN_EXPIRY)
    );
  }
  
  // Clear code verifier
  cookies.delete(cookieNames.codeVerifier, withExpiry(cookieOptions, 0));
  
  return {
    success: true,
    claims: decodeAccessToken(accessToken),
    accessToken,
  };
}

/**
 * Clear cookies and return failure result
 */
export function handleAuthFailure(
  cookies: CookieAdapter,
  cookieNames: CookieNames,
  cookieOptions: CookieSerializeOptions
): AuthResultFail {
  const expiredOptions = withExpiry(cookieOptions, 0);
  
  cookies.delete(cookieNames.accessToken, expiredOptions);
  cookies.delete(cookieNames.refreshToken, expiredOptions);
  cookies.delete(cookieNames.codeVerifier, expiredOptions);
  cookies.delete(cookieNames.authSessionId, expiredOptions);
  cookies.delete(cookieNames.tempSessionId, expiredOptions);
  
  return { success: false };
}

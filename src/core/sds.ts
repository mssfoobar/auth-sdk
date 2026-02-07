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
import { isOidcCallback, exchangeCode } from "./oidc.js";
import { decodeAccessToken } from "./tokens.js";
import { withExpiry } from "./config.js";

/**
 * Session data keys for SDS
 */
export const SDS_SESSION_KEYS = {
  CODE_VERIFIER: "code_verifier",
} as const;

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
 * SDS Client interface (matches @mssfoobar/sds-client)
 */
export interface SdsClient {
  connect(): Promise<void>;
  close(): Promise<void>;
  on(event: string, callback: (err: Error) => void): void;
  
  // Temp session methods
  tempSessionNew(): Promise<string>;
  tempSessionGet(sessionId: string, key: string): Promise<string>;
  tempSessionSet(sessionId: string, key: string, value: string): Promise<void>;
  
  // Auth session methods
  authSessionNew(accessToken: string, refreshToken: string): Promise<string>;
  authSessionGetAccessToken(sessionId: string): Promise<string>;
  authSessionDestroy(sessionId: string): Promise<void>;
}

/**
 * Create and connect SDS client
 */
export type SdsClientFactory = (url: string) => Promise<SdsClient>;

/**
 * SDS authentication options
 */
export interface SdsAuthenticateOptions {
  /** OIDC configuration */
  oidcConfig: Configuration;
  /** Cookie adapter */
  cookies: CookieAdapter;
  /** Current request URL */
  url: URL;
  /** Expected origin for callback validation */
  origin: string;
  /** SDS client */
  sdsClient: SdsClient;
  /** Cookie names */
  cookieNames: CookieNames;
  /** Default cookie options */
  cookieOptions: CookieSerializeOptions;
  /** Optional logger */
  logger?: Logger;
}

/**
 * SDS-backed authentication handler
 * 
 * Stores tokens server-side in SDS instead of browser cookies
 */
export async function authenticateWithSds(
  options: SdsAuthenticateOptions
): Promise<AuthResult> {
  const {
    oidcConfig,
    cookies,
    url,
    origin,
    sdsClient,
    cookieNames,
    cookieOptions,
    logger = noopLogger,
  } = options;
  
  const authSessionId = cookies.get(cookieNames.authSessionId);
  
  // Case 1: Have auth session - validate via SDS
  if (authSessionId) {
    try {
      const accessToken = await sdsClient.authSessionGetAccessToken(authSessionId);
      return handleSdsAuthSuccess(
        cookies,
        cookieNames,
        cookieOptions,
        accessToken,
        authSessionId
      );
    } catch (err) {
      logger.warn("Invalid SDS session", err);
      return handleSdsAuthFailure(cookies, cookieNames, cookieOptions);
    }
  }
  
  // Case 2: OIDC callback - exchange code and create SDS session
  if (isOidcCallback(url)) {
    return await handleSdsOidcCallback(
      oidcConfig,
      url,
      origin,
      sdsClient,
      cookies,
      cookieNames,
      cookieOptions,
      logger
    );
  }
  
  // Case 3: No auth
  return handleSdsAuthFailure(cookies, cookieNames, cookieOptions);
}

/**
 * Handle OIDC callback with SDS storage
 */
async function handleSdsOidcCallback(
  oidcConfig: Configuration,
  url: URL,
  origin: string,
  sdsClient: SdsClient,
  cookies: CookieAdapter,
  cookieNames: CookieNames,
  cookieOptions: CookieSerializeOptions,
  logger: Logger
): Promise<AuthResult> {
  const tempSessionId = cookies.get(cookieNames.tempSessionId);
  
  if (!tempSessionId) {
    logger.warn("No temp session ID for OIDC callback");
    return handleSdsAuthFailure(cookies, cookieNames, cookieOptions);
  }
  
  let codeVerifier: string;
  try {
    codeVerifier = await sdsClient.tempSessionGet(
      tempSessionId,
      SDS_SESSION_KEYS.CODE_VERIFIER
    );
  } catch (err) {
    logger.warn("Failed to retrieve code verifier from SDS", err);
    return handleSdsAuthFailure(cookies, cookieNames, cookieOptions);
  }
  
  const callbackUrl = new URL(origin + url.pathname + url.search);
  
  try {
    const tokenSet = await exchangeCode(oidcConfig, callbackUrl, codeVerifier);
    
    const newAuthSessionId = await sdsClient.authSessionNew(
      tokenSet.access_token,
      tokenSet.refresh_token!
    );
    
    return handleSdsAuthSuccess(
      cookies,
      cookieNames,
      cookieOptions,
      tokenSet.access_token,
      newAuthSessionId
    );
  } catch (err) {
    const error = err as ResponseBodyError;
    
    if (error.error === "invalid_grant") {
      logger.error("Invalid grant - check cookie forwarding");
    } else if (error.error === "unauthorized_client") {
      throw new Error("Invalid client credentials");
    }
    
    logger.error("SDS OIDC callback failed", err);
    return handleSdsAuthFailure(cookies, cookieNames, cookieOptions);
  }
}

/**
 * Set SDS session cookie and return success
 */
export function handleSdsAuthSuccess(
  cookies: CookieAdapter,
  cookieNames: CookieNames,
  cookieOptions: CookieSerializeOptions,
  accessToken: string,
  authSessionId: string
): AuthResultSuccess {
  cookies.set(cookieNames.authSessionId, authSessionId, cookieOptions);
  cookies.delete(cookieNames.tempSessionId, withExpiry(cookieOptions, 0));
  
  return {
    success: true,
    claims: decodeAccessToken(accessToken),
    accessToken,
  };
}

/**
 * Clear SDS-related cookies and return failure
 */
export function handleSdsAuthFailure(
  cookies: CookieAdapter,
  cookieNames: CookieNames,
  cookieOptions: CookieSerializeOptions
): AuthResultFail {
  const expiredOptions = withExpiry(cookieOptions, 0);
  
  cookies.delete(cookieNames.authSessionId, expiredOptions);
  cookies.delete(cookieNames.tempSessionId, expiredOptions);
  
  return { success: false };
}

/**
 * Store code verifier in SDS temp session
 */
export async function storeCodeVerifierInSds(
  sdsClient: SdsClient,
  cookies: CookieAdapter,
  cookieNames: CookieNames,
  cookieOptions: CookieSerializeOptions,
  codeVerifier: string,
  logger: Logger = noopLogger
): Promise<void> {
  try {
    const tempSessionId = await sdsClient.tempSessionNew();
    await sdsClient.tempSessionSet(
      tempSessionId,
      SDS_SESSION_KEYS.CODE_VERIFIER,
      codeVerifier
    );
    cookies.set(cookieNames.tempSessionId, tempSessionId, cookieOptions);
  } catch (err) {
    logger.error("Failed to store code verifier in SDS", err);
    throw err;
  }
}

/**
 * Destroy SDS auth session on logout
 */
export async function destroySdsSession(
  sdsClient: SdsClient,
  cookies: CookieAdapter,
  cookieNames: CookieNames,
  cookieOptions: CookieSerializeOptions,
  logger: Logger = noopLogger
): Promise<void> {
  const authSessionId = cookies.get(cookieNames.authSessionId);
  
  if (authSessionId) {
    try {
      await sdsClient.authSessionDestroy(authSessionId);
    } catch (err) {
      logger.error("Failed to destroy SDS session", err);
    }
  }
  
  cookies.delete(cookieNames.authSessionId, withExpiry(cookieOptions, 0));
}

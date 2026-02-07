import {
  discovery,
  type Configuration,
  type DiscoveryRequestOptions,
  allowInsecureRequests,
  randomPKCECodeVerifier,
  calculatePKCECodeChallenge,
  buildAuthorizationUrl,
  buildEndSessionUrl,
  authorizationCodeGrant,
  type TokenEndpointResponse,
  type TokenEndpointResponseHelpers,
} from "openid-client";
import type { AuthConfig, Logger } from "./types.js";

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
 * Initialize OIDC client configuration via discovery
 * 
 * @param config - Auth configuration
 * @param logger - Optional logger
 * @returns OIDC Configuration
 */
export async function initializeOidc(
  config: AuthConfig,
  logger: Logger = noopLogger
): Promise<Configuration> {
  const discoveryOptions: DiscoveryRequestOptions = {};
  
  if (config.allowInsecureRequests) {
    logger.warn("Allowing insecure OIDC requests (development mode)");
    discoveryOptions.execute = [allowInsecureRequests];
  }
  
  logger.info(`Discovering OIDC configuration from ${config.issuerUrl}`);
  
  return await discovery(
    new URL(config.issuerUrl),
    config.clientId,
    config.clientSecret,
    undefined,
    discoveryOptions
  );
}

/**
 * PKCE (Proof Key for Code Exchange) utilities
 */
export const pkce = {
  /**
   * Generate a new PKCE code verifier
   */
  generateVerifier(): string {
    return randomPKCECodeVerifier();
  },
  
  /**
   * Calculate the code challenge from a verifier
   */
  async calculateChallenge(verifier: string): Promise<string> {
    return calculatePKCECodeChallenge(verifier);
  },
};

/**
 * Build authorization URL for login redirect
 * 
 * @param config - OIDC configuration
 * @param redirectUri - URI to redirect after auth
 * @param codeChallenge - PKCE code challenge
 * @param scope - OAuth scopes (default: "openid")
 * @returns Authorization URL
 */
export function buildLoginUrl(
  config: Configuration,
  redirectUri: string,
  codeChallenge: string,
  scope: string = "openid"
): URL {
  return buildAuthorizationUrl(config, {
    scope,
    resource: redirectUri,
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
}

/**
 * Build end session URL for logout redirect
 * 
 * @param config - OIDC configuration
 * @param postLogoutRedirectUri - URI to redirect after logout
 * @param idTokenHint - ID token for logout hint
 * @returns End session URL
 */
export function buildLogoutUrl(
  config: Configuration,
  postLogoutRedirectUri: string,
  idTokenHint?: string
): URL {
  const params: Record<string, string> = {
    post_logout_redirect_uri: postLogoutRedirectUri,
  };
  
  if (idTokenHint) {
    params.id_token_hint = idTokenHint;
  }
  
  return buildEndSessionUrl(config, params);
}

/**
 * Exchange authorization code for tokens
 * 
 * @param config - OIDC configuration
 * @param callbackUrl - Full callback URL with code and state
 * @param codeVerifier - PKCE code verifier
 * @returns Token response
 */
export async function exchangeCode(
  config: Configuration,
  callbackUrl: URL,
  codeVerifier: string
): Promise<TokenEndpointResponse & TokenEndpointResponseHelpers> {
  return authorizationCodeGrant(config, callbackUrl, {
    pkceCodeVerifier: codeVerifier,
  });
}

/**
 * Check if URL contains OAuth callback parameters
 * 
 * @param url - URL to check
 * @returns Whether URL is from OIDC issuer callback
 */
export function isOidcCallback(url: URL): boolean {
  return Boolean(
    url.searchParams.has("session_state") && url.searchParams.has("code")
  );
}

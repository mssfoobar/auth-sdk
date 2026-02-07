import { json, redirect } from "@sveltejs/kit";
import type { Configuration } from "openid-client";
import { refreshTokenGrant } from "openid-client";
import {
  pkce,
  buildLoginUrl,
  buildLogoutUrl,
  getCookieNames,
  buildCookieOptions,
  withExpiry,
  REFRESH_TOKEN_EXPIRY,
  type CookieConfig,
  type Logger,
  type SdsClient,
} from "../../index.js";

/**
 * Auth routes configuration
 */
export interface AuthRoutesConfig {
  /** Application origin */
  origin: string;
  /** Cookie configuration */
  cookie: CookieConfig;
  /** Login destination after auth (default: "/") */
  loginDestination?: string;
  /** Login page path (default: "/aoh/api/auth/login") */
  loginPage?: string;
  /** Callback path (default: "/aoh/api/auth/callback") */
  callbackPath?: string;
  /** Optional logger */
  logger?: Logger;
  /** SDS client factory (if using SDS) */
  createSdsClient?: () => Promise<SdsClient>;
  /** Context cookie name (default: "context_value") */
  contextCookieName?: string;
  /** Context cookie max age in seconds (default: 7 days) */
  contextCookieMaxAge?: number;
}

/**
 * Create auth route handlers for SvelteKit
 */
export function createAuthRoutes(config: AuthRoutesConfig) {
  const cookieNames = getCookieNames(config.cookie.prefix);
  const cookieOptions = buildCookieOptions(config.cookie, config.origin);
  const logger = config.logger ?? createNoopLogger();
  const loginDestination = config.loginDestination ?? "/";
  const loginPage = config.loginPage ?? "/aoh/api/auth/login";
  const callbackPath = config.callbackPath ?? "/aoh/api/auth/callback";
  const contextCookieName = config.contextCookieName ?? "context_value";
  const contextCookieMaxAge = config.contextCookieMaxAge ?? 60 * 60 * 24 * 7;
  
  return {
    /**
     * Login handler - redirects to OIDC provider
     */
    login: async ({ cookies, locals }: { cookies: any; locals: any }) => {
      const oidcConfig: Configuration = locals.clients?.oidc_config;
      if (!oidcConfig) {
        throw new Error("OIDC config not found in locals");
      }
      
      const codeVerifier = pkce.generateVerifier();
      const codeChallenge = await pkce.calculateChallenge(codeVerifier);
      const redirectUri = config.origin + callbackPath;
      
      const authUrl = buildLoginUrl(oidcConfig, redirectUri, codeChallenge);
      
      // Store code verifier
      if (config.createSdsClient) {
        const sdsClient = await config.createSdsClient();
        try {
          const tempSessionId = await sdsClient.tempSessionNew();
          await sdsClient.tempSessionSet(tempSessionId, "code_verifier", codeVerifier);
          cookies.set(cookieNames.tempSessionId, tempSessionId, cookieOptions);
        } finally {
          await sdsClient.close();
        }
      } else {
        cookies.set(cookieNames.codeVerifier, codeVerifier, cookieOptions);
      }
      
      return json(null, {
        status: 307,
        headers: { Location: authUrl.href },
      });
    },
    
    /**
     * Logout handler - clears session and redirects
     */
    logout: async ({ cookies, locals, setHeaders }: { cookies: any; locals: any; setHeaders: any }) => {
      const oidcConfig: Configuration = locals.clients?.oidc_config;
      const postLogoutUri = config.origin + ("/" + loginPage).replace("//", "/");
      
      if (config.createSdsClient) {
        // SDS logout
        const authSessionId = cookies.get(cookieNames.authSessionId);
        cookies.delete(cookieNames.authSessionId, cookieOptions);
        
        if (authSessionId) {
          const sdsClient = await config.createSdsClient();
          try {
            await sdsClient.authSessionDestroy(authSessionId);
          } catch (err) {
            logger.error("Failed to destroy SDS session", err);
          } finally {
            await sdsClient.close();
          }
        }
      } else {
        // Cookie-based logout
        const refreshToken = cookies.get(cookieNames.refreshToken);
        const expiredOpts = withExpiry(cookieOptions, 0);
        
        cookies.delete(cookieNames.accessToken, expiredOpts);
        cookies.delete(cookieNames.refreshToken, expiredOpts);
        cookies.delete(contextCookieName, expiredOpts);
        
        // Get ID token for logout hint
        if (refreshToken && oidcConfig) {
          try {
            const tokens = await refreshTokenGrant(oidcConfig, refreshToken);
            if (tokens.id_token) {
              const endSessionUrl = buildLogoutUrl(
                oidcConfig,
                postLogoutUri,
                tokens.id_token
              );
              setHeaders({ Location: endSessionUrl.toString() });
              return json(null, { status: 307 });
            }
          } catch (err) {
            logger.error("Error refreshing tokens during logout", err);
          }
        }
      }
      
      setHeaders({ Location: postLogoutUri });
      return json(null, { status: 307 });
    },
    
    /**
     * Callback handler - handles redirect after OIDC auth
     */
    callback: async ({ cookies }: { cookies: any }) => {
      const redirectDestination = cookies.get("aoh_redirect_after_auth");
      
      if (redirectDestination) {
        cookies.delete("aoh_redirect_after_auth", { path: "/" });
        redirect(307, redirectDestination);
      }
      
      const defaultDestination = ("/" + loginDestination).replace("//", "/");
      redirect(307, defaultDestination);
    },
    
    /**
     * Refresh handler - refreshes tokens
     */
    refresh: async ({ cookies, locals }: { cookies: any; locals: any }) => {
      if (config.createSdsClient) {
        const authSessionId = cookies.get(cookieNames.authSessionId);
        
        if (authSessionId) {
          const sdsClient = await config.createSdsClient();
          try {
            await sdsClient.authSessionGetAccessToken(authSessionId);
            return json(null, { status: 200 });
          } catch (err) {
            logger.error("SDS token refresh failed", err);
            cookies.delete(cookieNames.authSessionId, withExpiry(cookieOptions, 0));
          } finally {
            await sdsClient.close();
          }
        }
      } else {
        const oidcConfig: Configuration = locals.clients?.oidc_config;
        const refreshToken = cookies.get(cookieNames.refreshToken);
        
        if (refreshToken && oidcConfig) {
          try {
            const tokens = await refreshTokenGrant(oidcConfig, refreshToken);
            cookies.set(
              cookieNames.accessToken,
              tokens.access_token,
              withExpiry(cookieOptions, tokens.expires_in!)
            );
            cookies.set(
              cookieNames.refreshToken,
              tokens.refresh_token!,
              withExpiry(cookieOptions, REFRESH_TOKEN_EXPIRY)
            );
            cookies.delete(cookieNames.codeVerifier, withExpiry(cookieOptions, 0));
            return json(null, { status: 200 });
          } catch (err) {
            logger.error("Token refresh failed", err);
            cookies.delete(cookieNames.accessToken, withExpiry(cookieOptions, 0));
            cookies.delete(cookieNames.refreshToken, withExpiry(cookieOptions, 0));
          }
        }
      }
      
      return json(
        { message: "Unable to refresh tokens", sent_at: new Date().toISOString() },
        { status: 401 }
      );
    },
    
    /**
     * Context handler - get current context value
     */
    getContext: async ({ cookies }: { cookies: any }) => {
      const currentContext = cookies.get(contextCookieName);
      return json({ context: currentContext }, { status: 200 });
    },
    
    /**
     * Set context handler - set context value
     */
    setContext: async ({ cookies, setHeaders, params }: { cookies: any; setHeaders: any; params: { value: string } }) => {
      cookies.set(
        contextCookieName,
        params.value,
        withExpiry(cookieOptions, contextCookieMaxAge)
      );
      setHeaders({ Location: config.origin });
      return json(null, { status: 307 });
    },
  };
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

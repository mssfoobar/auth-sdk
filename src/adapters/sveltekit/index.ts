/**
 * SvelteKit adapter for @mssfoobar/auth-sdk
 * 
 * Provides drop-in replacement for web-base auth implementation
 */

export { createAuthHooks, type AuthHooksConfig } from "./hooks.js";
export { createAuthRoutes, type AuthRoutesConfig } from "./routes.js";
export { sveltekitCookieAdapter } from "./cookies.js";

import type { Cookies as SvelteKitCookies } from "@sveltejs/kit";
import type { CookieAdapter, CookieSerializeOptions } from "../../core/types.js";

/**
 * Adapt SvelteKit Cookies to CookieAdapter interface
 */
export function sveltekitCookieAdapter(cookies: SvelteKitCookies): CookieAdapter {
  return {
    get(name: string): string | undefined {
      return cookies.get(name);
    },
    
    set(name: string, value: string, options: CookieSerializeOptions): void {
      cookies.set(name, value, {
        domain: options.domain,
        path: options.path ?? "/",
        secure: options.secure,
        httpOnly: options.httpOnly,
        sameSite: options.sameSite,
        maxAge: options.maxAge,
      });
    },
    
    delete(name: string, options: CookieSerializeOptions): void {
      cookies.delete(name, {
        domain: options.domain,
        path: options.path ?? "/",
        secure: options.secure,
        httpOnly: options.httpOnly,
        sameSite: options.sameSite,
      });
    },
  };
}

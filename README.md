# @mssfoobar/auth-sdk

Authentication and Authorization SDK for OIDC/Keycloak with multi-tenant support and optional SDS (Session Data Store) integration.

## Features

- 🔐 **OIDC Authentication** - Full OpenID Connect flow with PKCE
- 🏢 **Multi-tenant Support** - Built-in tenant claims parsing
- 🍪 **Cookie Management** - Secure, framework-agnostic cookie handling
- 💾 **SDS Integration** - Optional server-side token storage
- ⚡ **SvelteKit Adapter** - Drop-in replacement for web-base auth
- 📦 **TypeScript First** - Full type definitions included

## Installation

```bash
npm install @mssfoobar/auth-sdk

# Optional peer dependencies
npm install @mssfoobar/sds-client  # For SDS support
```

## Quick Start

### Core SDK (Framework-agnostic)

```typescript
import {
  initializeOidc,
  authenticate,
  getCookieNames,
  buildCookieOptions,
  type CookieAdapter,
} from "@mssfoobar/auth-sdk";

// Initialize OIDC config (do this once at startup)
const oidcConfig = await initializeOidc({
  issuerUrl: "https://keycloak.example.com/realms/myrealm",
  clientId: "my-app",
  origin: "https://app.example.com",
});

// Create cookie names and options
const cookieNames = getCookieNames("myapp");
const cookieOptions = buildCookieOptions(
  { prefix: "myapp", domain: "example.com" },
  "https://app.example.com"
);

// Authenticate a request
const result = await authenticate({
  oidcConfig,
  cookies: myCookieAdapter, // Implement CookieAdapter interface
  url: requestUrl,
  origin: "https://app.example.com",
  cookieNames,
  cookieOptions,
});

if (result.success) {
  console.log("User:", result.claims.sub);
  console.log("Active tenant:", result.claims.active_tenant);
}
```

### SvelteKit Adapter

```typescript
// hooks.server.ts
import { createAuthHooks } from "@mssfoobar/auth-sdk/sveltekit";
import SdsClient from "@mssfoobar/sds-client";

export const { handle } = createAuthHooks({
  auth: {
    issuerUrl: env.IAM_URL,
    clientId: env.IAM_CLIENT_ID,
    origin: env.ORIGIN,
  },
  cookie: {
    prefix: env.PUBLIC_COOKIE_PREFIX,
    domain: env.PUBLIC_DOMAIN,
  },
  // Optional: Enable SDS for server-side token storage
  createSdsClient: async () => {
    const client = new SdsClient(env.SDS_URL);
    await client.connect();
    return client;
  },
  frameAncestors: env.FRAME_ANCESTORS,
  xFrameOptions: env.X_FRAME_OPTIONS,
});
```

```typescript
// routes/aoh/api/auth/login/+server.ts
import { createAuthRoutes } from "@mssfoobar/auth-sdk/sveltekit";
import { env } from "$env/dynamic/private";

const routes = createAuthRoutes({
  origin: env.ORIGIN,
  cookie: {
    prefix: env.PUBLIC_COOKIE_PREFIX,
  },
  loginDestination: env.LOGIN_DESTINATION,
});

export const GET = routes.login;
```

## Token Utilities

```typescript
import {
  decodeAccessToken,
  isTenantAdmin,
  getTenantIds,
  getActiveTenantId,
  getRealmRoles,
  hasRealmRole,
} from "@mssfoobar/auth-sdk";

// Decode claims from access token
const claims = decodeAccessToken(accessToken);

// Check tenant admin status
if (isTenantAdmin(accessToken)) {
  // User can manage tenant
}

// Get all tenants user belongs to
const tenants = getTenantIds(accessToken);

// Get active tenant
const activeTenant = getActiveTenantId(accessToken);

// Check realm roles
if (hasRealmRole(accessToken, "admin")) {
  // User has admin role
}
```

## OIDC Utilities

```typescript
import {
  pkce,
  buildLoginUrl,
  buildLogoutUrl,
  isOidcCallback,
} from "@mssfoobar/auth-sdk";

// Generate PKCE credentials
const verifier = pkce.generateVerifier();
const challenge = await pkce.calculateChallenge(verifier);

// Build login URL
const loginUrl = buildLoginUrl(oidcConfig, redirectUri, challenge);

// Build logout URL
const logoutUrl = buildLogoutUrl(oidcConfig, postLogoutUri, idToken);

// Check if URL is OIDC callback
if (isOidcCallback(requestUrl)) {
  // Handle callback
}
```

## Configuration

### Auth Config

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `issuerUrl` | string | ✅ | OIDC issuer URL (Keycloak realm URL) |
| `clientId` | string | ✅ | OAuth client ID |
| `clientSecret` | string | ❌ | Client secret (confidential clients) |
| `origin` | string | ✅ | Application origin URL |
| `allowInsecureRequests` | boolean | ❌ | Allow HTTP (dev only) |
| `sdsUrl` | string | ❌ | SDS server URL |

### Cookie Config

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `prefix` | string | ✅ | Cookie name prefix |
| `domain` | string | ❌ | Cookie domain |
| `path` | string | ❌ | Cookie path (default: "/") |
| `sameSite` | string | ❌ | SameSite attribute (default: "lax") |
| `httpOnly` | boolean | ❌ | HttpOnly flag (default: true) |

## Multi-tenant Claims

The SDK parses Keycloak tokens with multi-tenant claims:

```typescript
interface AuthClaims {
  // Standard OIDC claims
  sub: string;
  // ...
  
  // Multi-tenant claims
  active_tenant: {
    tenant_id?: string;
    tenant_name?: string;
    roles?: string[];
  };
  all_tenants: Array<{
    tenant_id?: string;
    tenant_name?: string;
    roles?: string[];
  }>;
  realm_access: {
    roles: string[];
  };
}
```

## SDS (Session Data Store)

For enhanced security, tokens can be stored server-side using SDS:

```typescript
import { authenticateWithSds, type SdsClient } from "@mssfoobar/auth-sdk";

const result = await authenticateWithSds({
  oidcConfig,
  cookies,
  url,
  origin,
  sdsClient, // Connected SDS client
  cookieNames,
  cookieOptions,
});
```

Benefits:
- Tokens never stored in browser cookies
- Server-side token refresh
- Centralized session management

## API Reference

See [API Documentation](./docs/api.md) for full details.

## Migration from web-base

Replace imports:

```diff
- import { authenticate, type AuthResult } from "$lib/aoh/core/provider/auth/auth";
+ import { authenticate, type AuthResult } from "@mssfoobar/auth-sdk";
```

Update hooks.server.ts to use `createAuthHooks()`.

Update auth routes to use `createAuthRoutes()`.

## Security

### Rate Limiting

The auth SDK does **not** include built-in rate limiting. It is strongly recommended that consumers add rate limiting middleware to the following auth endpoints to prevent brute-force and denial-of-service attacks:

- **`/login`** — Limit login attempts per IP (e.g., 10 requests/minute)
- **`/refresh`** — Limit token refresh requests (e.g., 30 requests/minute)
- **`/logout`** — Limit logout requests (e.g., 10 requests/minute)

Example with a SvelteKit rate limiter:

```typescript
// hooks.server.ts
import { RateLimiter } from 'your-rate-limiter';

const authLimiter = new RateLimiter({ windowMs: 60_000, max: 10 });

export const handle = sequence(
  async ({ event, resolve }) => {
    if (event.url.pathname.startsWith('/aoh/api/auth/')) {
      const ip = event.getClientAddress();
      if (authLimiter.isLimited(ip)) {
        return new Response('Too Many Requests', { status: 429 });
      }
    }
    return resolve(event);
  },
  // ... your auth hooks
);
```

### Cookie-based vs SDS Flow

The cookie-based authentication flow stores raw JWTs in browser cookies and should only be used for development or when SDS is unavailable. For production deployments, use the SDS-backed flow (`authenticateWithSds`) which stores tokens server-side.

## License

MIT

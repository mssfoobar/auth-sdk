# AGENTS.md - @mssfoobar/auth-sdk

## Overview

Authentication and Authorization SDK for OIDC/Keycloak with SDS (Session Data Store) support. Extracted from `mssfoobar/web-base`.

## Tech Stack

- **TypeScript** (strict mode)
- **Vite 8** (with Rolldown bundler)
- **Vitest 4** for testing
- **Node.js 24 LTS** (always use even/LTS versions)
- **openid-client** for OIDC
- **jwt-decode** for token parsing

## Project Structure

```
src/
  index.ts          — Core exports (config, tokens, types)
  sveltekit.ts      — SvelteKit adapter (hooks, auth routes)
  sds.ts            — SDS client integration
tests/
  config.test.ts    — Configuration tests
  tokens.test.ts    — Token utility tests
```

## Build & Test

```bash
npm run build     # Vite build + TypeScript declarations
npm test          # Vitest run
npm run test:watch
npm run test:coverage
```

## Conventions

- **Dual output**: ESM (`dist/*.js`) + CJS (`dist/*.cjs`)
- **Type declarations**: Generated via `vite-plugin-dts`
- **Peer deps**: `@sveltejs/kit` and `@mssfoobar/sds-client` are optional peers
- **Always use latest stable/LTS versions** of dependencies
- **Even Node.js versions only** (odd versions are experimental)
- **All changes via Pull Request** (no direct pushes to main)
- **OpenSpec** initialized for spec-driven development

## OpenSpec

This project uses [OpenSpec](https://github.com/Fission-AI/OpenSpec) for spec-driven development. See `openspec/` directory for specs and changes.

## Related Repos

- `mssfoobar/web-base` — Original source of the auth implementation
- `mssfoobar/agentic` — Agentic C2 platform (consumer of this SDK)

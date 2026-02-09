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
- **All changes via Pull Request** (no direct pushes to `main` or `develop`)
- **OpenSpec** initialized for spec-driven development
- **Changesets** for versioning (`@changesets/cli`)

## Branching Strategy

| Branch | Purpose |
|--------|---------|
| `develop` | Default branch. Day-to-day development happens here. |
| `YYYYMMDD/rc` | Release candidate branches. Created from `develop` when preparing a release. |
| `main` | Release-only branch. RC branches merge here to trigger a release. |

### Workflow

1. Develop features on `develop` (via PRs)
2. When ready to release, create a branch named `YYYYMMDD/rc` from `develop`
3. Push the RC branch — CI runs typecheck, tests, and build
4. Merge the RC branch into `main` via PR
5. The Release workflow automatically: versions via changesets, publishes to GitHub Packages, creates a GitHub Release, and opens a PR to sync `main` back to `develop`

## CI/CD Workflows

### CI (`.github/workflows/ci.yml`)

Runs on:
- Push to `YYYYMMDD/rc` branches
- PRs targeting `develop`

Steps: install, typecheck, test, build

### Release (`.github/workflows/release.yml`)

Runs on push to `main`. Steps:
1. Check for pending changesets — skip if none
2. `npx changeset version` — bump version, generate changelog
3. Commit + tag `v{version}` on `main`
4. Build and publish to GitHub Packages (`npm.pkg.github.com`)
5. Create GitHub Release with changelog
6. Open PR from `main` to `develop` to sync version bump

## OpenSpec

This project uses [OpenSpec](https://github.com/Fission-AI/OpenSpec) for spec-driven development. See `openspec/` directory for specs and changes.

## Related Repos

- `mssfoobar/web-base` — Original source of the auth implementation
- `mssfoobar/agentic` — Agentic C2 platform (consumer of this SDK)

# @mssfoobar/auth-sdk

## 0.3.0

### Minor Changes

- adb35bc: Security hardening pass:
  - Fix open redirect vulnerability in callback handler
  - Add OAuth state parameter for CSRF protection
  - Implement offline JWT validation via JWKS (with userinfo fallback)
  - Make refresh token max age configurable (default changed from 1 year to 30 days)
  - Sanitize error objects in logs
  - Add input validation to setContext handler
  - Fix isOidcCallback to not require session_state
  - Improve SDS error handling (distinguish not-found vs unavailable)
  - Add rate limiting documentation

### Patch Changes

- 97b7755: Improve test coverage to >80% across all metrics. Added tests for auth, oidc, sds, tokens, and sveltekit cookie adapter modules.

## 0.2.0

### Minor Changes

- 102ca99: Add CI/CD workflows and branching strategy

  - CI workflow runs typecheck, tests, and build on RC branches and PRs to develop
  - Release workflow automates changeset versioning, npm publish to GitHub Packages, and GitHub Releases
  - Both workflows are reusable from mssfoobar/.github
  - Added @changesets/cli as devDependency

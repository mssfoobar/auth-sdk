---
"@mssfoobar/auth-sdk": minor
---

Add CI/CD workflows and branching strategy

- CI workflow runs typecheck, tests, and build on RC branches and PRs to develop
- Release workflow automates changeset versioning, npm publish to GitHub Packages, and GitHub Releases
- Both workflows are reusable from mssfoobar/.github
- Added @changesets/cli as devDependency

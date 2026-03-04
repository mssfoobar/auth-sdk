---
"@mssfoobar/auth-sdk": minor
---

Security hardening pass:
- Fix open redirect vulnerability in callback handler
- Add OAuth state parameter for CSRF protection
- Implement offline JWT validation via JWKS (with userinfo fallback)
- Make refresh token max age configurable (default changed from 1 year to 30 days)
- Sanitize error objects in logs
- Add input validation to setContext handler
- Fix isOidcCallback to not require session_state
- Improve SDS error handling (distinguish not-found vs unavailable)
- Add rate limiting documentation

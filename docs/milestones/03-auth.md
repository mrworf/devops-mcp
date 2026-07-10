# Milestone 03: Auth

## Context
Use the architecture in `00-architecture.md`. This milestone turns the server into an authenticated MCP resource server. It does not implement an OAuth authorization server.

OAuth must follow OpenAI/Codex best practices: protected resource metadata, `WWW-Authenticate` challenges, authorization-code + PKCE handled by the client/provider, and server-side JWT validation.

## Scope
- Implement OAuth/OIDC resource-server validation.
- Implement optional static bearer dev mode.
- Add protected resource metadata endpoint.
- Add `WWW-Authenticate` challenge behavior.
- Attach authenticated subject, session if available, and scopes to request context.
- Enforce tool scopes.

## Non-Scope
- No built-in authorization server.
- No user/group synchronization.
- No refresh token handling.
- No ChatGPT web/plugin integration.

## Interfaces And Config
Types:
- `AuthContext`
- `AuthMode = "oauth" | "bearer"`

Functions:
- `authenticateRequest(req, requiredScopes): Promise<AuthContext>`
- `buildAuthenticateChallenge(requiredScopes): string`

Config:
- `auth.mode`
- `auth.oauth.issuer`
- `auth.oauth.audience` or `resource`
- `auth.oauth.jwks_uri` or discovery document
- `auth.oauth.required_scopes`
- `auth.bearer.token_env` or `token_file`

## Likely Files
- `src/auth.ts`
- `src/oauthMetadata.ts`
- `src/server.ts`
- `test/auth.test.ts`

## Tests
Positive:
- Valid JWT from test JWKS is accepted.
- Required scopes are enforced.
- Bearer dev token is accepted in bearer mode.
- Protected resource metadata includes resource, authorization servers, and supported scopes.

Negative:
- Missing token returns `401` and `WWW-Authenticate`.
- Invalid signature, issuer, audience/resource, expiry, nbf, or scope is rejected.
- Bearer token is rejected in OAuth mode.
- OAuth JWT is rejected in bearer mode unless explicitly configured otherwise.

## Acceptance Criteria
- All MCP tool calls require authentication.
- `/health` and OAuth metadata remain unauthenticated.
- Auth failures contain no credential or token leakage.
- `npm test` passes.

## Completion Checklist
- [ ] OAuth metadata endpoint exists.
- [ ] JWT verification is implemented with `jose`.
- [ ] Bearer dev mode is implemented and documented in code comments/config only where needed.
- [ ] Tool scope enforcement is covered by tests.

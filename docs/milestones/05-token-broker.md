# Milestone 05: Token Broker

## Context
Use the architecture in `00-architecture.md`. This milestone implements opaque credential placeholders. Tokens are capabilities scoped to an authenticated subject/session, service, destination, and credential.

Token values are not raw credentials and must not be logged.

## Scope
- Implement `request_tokens`.
- Generate fully opaque, non-guessable token values.
- Store token records in memory with internal IDs and token hashes.
- Enforce subject, session if available, service, destination, credential, and reason binding.
- Enforce idle TTL and hard max TTL.
- Audit token issuance without raw token values.

## Non-Scope
- No downstream credential substitution yet.
- No persistent token store.
- No token revocation API beyond expiry/restart.

## Interfaces
- `issueTokens(auth, request): TokenIssueResult`
- `validateTokenUse(auth, target, tokenValue): TokenRecord`
- `TokenRecord`
- Token audit event shape.

## Likely Files
- `src/tokens.ts`
- `src/audit.ts`
- `src/mcp/tools.ts`
- `test/tokens.test.ts`

## Tests
Positive:
- Authorized token request succeeds with reason.
- Multiple requested credentials issue multiple tokens.
- Token use refreshes idle TTL without extending past max TTL.

Negative:
- Missing reason fails.
- Unknown credential fails.
- Expired token fails.
- Cross-user token use fails.
- Cross-service token use fails.
- Cross-destination token use fails.
- Audit event omits raw opaque token value.

## Acceptance Criteria
- `request_tokens` is functional.
- Token responses contain no raw downstream credential.
- Token stores and audit logs use internal token IDs/hashes, not raw token values.
- `npm test` passes.

## Completion Checklist
- [ ] Opaque token generation uses `crypto`.
- [ ] Token binding is enforced.
- [ ] TTL behavior is tested.
- [ ] Audit output is sanitized.

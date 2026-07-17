# Milestone 05: Token Broker

## Context
Use the architecture in `00-architecture.md`. This milestone implements opaque credential placeholders. Tokens are capabilities scoped to an authenticated subject/session, service, destination, and credential.

Token values are not raw credentials and must not be logged.

## Scope
- Implement `get_gateway_service_references`.
- Generate fully opaque, non-guessable token values.
- Store reference records in memory with internal IDs and reference hashes.
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
- Authorized reference request succeeds with reason.
- Multiple requested access methods issue multiple references.
- Reference use refreshes idle TTL without extending past max TTL.

Negative:
- Missing reason fails.
- Unknown access id fails.
- Expired reference fails.
- Cross-user reference use fails.
- Cross-service reference use fails.
- Cross-destination reference use fails.
- Audit event omits raw opaque reference value.

## Acceptance Criteria
- `get_gateway_service_references` is functional.
- Reference responses contain no raw downstream credential.
- Reference stores and audit logs use internal reference IDs/hashes, not raw reference values.
- `npm test` passes.

## Completion Checklist
- [ ] Opaque reference generation uses `crypto`.
- [ ] Reference binding is enforced.
- [ ] TTL behavior is tested.
- [ ] Audit output is sanitized.

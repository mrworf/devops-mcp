# Milestone 08: Redaction, Audit, And Denials

## Context
Use the architecture in `00-architecture.md`. This milestone completes response safety, audit logging, structured errors, and denial explanations.

Audit logs must be useful without containing secrets.

## Scope
- Redact exact plaintext and JSON-escaped credential values from response headers and body.
- Emit structured JSON audit events for token requests and service requests.
- Implement `explain_denial`.
- Ensure all errors are structured with PRD error codes and request IDs where relevant.
- Ensure response metadata includes redaction count and TLS verification mode.

## Non-Scope
- No URL-encoded, base64, derived secret, or private key scanning.
- No signed or append-only audit backend.
- No unsafe debug body logging.

## Interfaces
- `redactResponse(response, credentials): RedactedResponse`
- `audit(event): void`
- `explainDenial(auth, requestId): DenialExplanation`
- `GatewayError`

## Likely Files
- `src/redaction.ts`
- `src/audit.ts`
- `src/denials.ts`
- `src/errors.ts`
- `src/mcp/tools.ts`
- `test/redaction.test.ts`
- `test/audit.test.ts`
- `test/denials.test.ts`

## Tests
Positive:
- Raw credential is redacted from response headers.
- Raw credential is redacted from response body.
- JSON-escaped credential is redacted.
- Denied request returns request ID.
- `explain_denial` returns safe matched rule and suggestion.

Negative:
- Audit omits raw credentials.
- Audit omits raw opaque token values.
- Audit omits Authorization headers, cookies, request bodies, and response bodies.
- `explain_denial` does not expose denials for another subject/session.

## Acceptance Criteria
- Redaction, audit, and denial explanation satisfy the PRD acceptance criteria.
- All returned/logged structures are sanitized.
- `npm test` passes.

## Completion Checklist
- [ ] Redaction count and flag are accurate.
- [ ] Audit records are structured JSON.
- [ ] Denial explanations are safe and useful.
- [ ] Error codes match the PRD list.

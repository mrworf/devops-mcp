# Milestone 06: Policy Engine

## Context
Use the architecture in `00-architecture.md`. This milestone implements request policy decisions that later block or allow downstream HTTP requests before credential substitution.

Default policy mode is deny.

## Scope
- Implement service request policy evaluation.
- Support `mode: deny | allow`.
- Support rule `id`, `effect`, `priority`, `methods`, `hosts`, `paths`, and optional `reason`.
- Use regex path matching only for MVP.
- Apply highest priority matching rule.
- If priorities tie, deny wins.
- Store denial context suitable for `explain_denial`.

## Non-Scope
- No query-string-aware policy.
- No glob syntax.
- No semantic safety analysis of HTTP operations.

## Interfaces
- `evaluatePolicy(service, target, method): PolicyDecision`
- `PolicyDecision`: allowed, matched rule, policy mode, reason, suggestion.

## Likely Files
- `src/policy.ts`
- `src/denials.ts`
- `src/config.ts`
- `test/policy.test.ts`

## Tests
Positive:
- Allowed GET rule permits matching path.
- Unmatched request follows `mode: allow`.
- Host-specific rule matches normalized host.

Negative:
- DELETE deny rule blocks matching request.
- Unmatched request follows `mode: deny`.
- Priority tie chooses deny.
- Invalid policy regex fails config validation.

## Acceptance Criteria
- Policy can decide requests before token substitution or downstream HTTP.
- Denial results include safe explanation context.
- `npm test` passes.

## Completion Checklist
- [ ] Policy mode handling is implemented.
- [ ] Priority and tie-break behavior are tested.
- [ ] Denial context is available for milestone 08.

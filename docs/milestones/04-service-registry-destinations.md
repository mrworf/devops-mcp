# Milestone 04: Service Registry And Destination Validation

## Context
Use the architecture in `00-architecture.md`. This milestone makes configured services visible to authorized users and provides reusable destination validation for later token and HTTP milestones.

Destination validation must happen before credential substitution in later milestones.

## Scope
- Implement service listing filtered by authenticated subject.
- Implement service, destination, and credential lookup.
- Implement URL/path normalization.
- Implement destination validation for base URL, scheme, host, and port.
- Implement TLS verification flag resolution.
- Wire `list_services` to real registry behavior.

## Non-Scope
- No token issuance.
- No downstream HTTP execution.
- No policy engine beyond config validation already present.

## Interfaces
- `listVisibleServices(auth: AuthContext): ServiceSummary[]`
- `resolveDestination(service, destinationId, pathOrUrl): ResolvedTarget`
- Host matcher types: exact, suffix, regex.

`ServiceSummary` must not include raw credentials.

## Likely Files
- `src/registry.ts`
- `src/urlValidation.ts`
- `src/mcp/tools.ts`
- `test/registry.test.ts`
- `test/urlValidation.test.ts`

## Tests
Positive:
- Subject sees only services allowed by `access.users`.
- Exact host match works after normalization.
- Suffix and regex host match work.
- Relative paths resolve against destination base URL.
- `tls.verify: false` appears in service summary and target metadata.

Negative:
- Wrong scheme is denied.
- Wrong host is denied.
- Wrong port is denied.
- Absolute URL outside configured destination is denied.
- Unknown service, destination, and credential are denied with structured errors.

## Acceptance Criteria
- `list_services` returns safe summaries for the authenticated subject.
- Destination validation is reusable by token and gateway code.
- No raw credentials appear in output or logs.
- `npm test` passes.

## Completion Checklist
- [ ] Service registry filters by subject.
- [ ] Host normalization and matching are implemented.
- [ ] URL/path target resolution is tested.
- [ ] TLS metadata is surfaced safely.

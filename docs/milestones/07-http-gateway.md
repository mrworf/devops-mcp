# Milestone 07: HTTP Gateway

## Context
Use the architecture in `00-architecture.md`. This milestone implements the main service request execution flow. The critical safety order is auth, authorization, destination validation, policy, token validation, substitution, downstream request, response tokenization, and audit hooks.

Policy and destination validation must happen before credential substitution.

## Scope
- Implement `service_request`.
- Validate auth, service access, destination, scheme, host, port, policy, and tokens before substitution.
- Substitute recognized opaque references in headers, query, and JSON/string body.
- Execute downstream HTTP using Node global `fetch`.
- Disable redirects.
- Enforce request body size, response body size, response header size if represented, and timeout.

## Non-Scope
- No redirect allowlist.
- No custom CA bundles or certificate pinning.
- No query-aware policy.
- No persistent audit backend.

## Interfaces
- `executeServiceRequest(auth, input): ServiceResponse`
- `substituteTokens(input, tokenRecords): DownstreamRequest`
- `ServiceResponse`
- `DownstreamRequest`

## Likely Files
- `src/gateway.ts`
- `src/substitution.ts`
- `src/mcp/tools.ts`
- `test/gateway.test.ts`

## Tests
Positive:
- Allowed request reaches local test server with real credential.
- Token substitution works in headers, query, and body.
- TLS verification metadata is included in response.

Negative:
- Policy-denied request never reaches downstream server.
- Unknown token fails before downstream call.
- Token for wrong service or destination fails.
- Redirect is not followed.
- Timeout is reported as `downstream_timeout`.
- Oversized request is rejected.
- Oversized response is truncated by default.

## Acceptance Criteria
- `service_request` can safely call configured HTTP APIs through the gateway.
- Credential substitution occurs only after all validations pass.
- No raw credentials are returned to the MCP client.
- `npm test` passes.

## Completion Checklist
- [ ] Request execution order matches the PRD.
- [ ] Redirects are disabled.
- [ ] Limits and timeout are enforced.
- [ ] Downstream tests prove denied requests are not sent.

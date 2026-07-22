# Architecture Review 2026-07-22 Remediation Plan

## Source and objective

This plan remediates the findings in [`docs/audits/architecture-review-2026-07-22.md`](../audits/architecture-review-2026-07-22.md). It is intentionally limited to the architecture review's recommended hardening. It does not add a framework, database, queue, Redis, service-specific tools, profile packs, enterprise policy engine, multi-replica capability store, or broader OAuth product scope.

The target remains a small, self-hosted, single-process gateway that works from both ChatGPT and Codex. Each implementation slice below must be independently useful, reviewable, testable, and committed on its own.

## Current baseline

- Reviewed revision: `76e73a717f79032535598b4c84d3bf5b208957a4`.
- Review artifact commit: `11beb13` (`Add architecture review`).
- Review-time verification: `npm run build`, `npm test` (32 files, 333 tests), and `git diff --check` passed. The unchanged suite required loopback permission after a sandboxed `listen EPERM` failure.
- Canonical full test suite: `npm test` (`vitest run`).
- CI quality gates: `npm run build` followed by `npm test`.
- Planning-time worktree: clean.

Before beginning Slice 1, rerun `npm run build` and `npm test` to establish the implementation branch baseline. A baseline failure must be resolved or explicitly identified as pre-existing before remediation work begins.

## Mandatory delivery loop for every code slice

1. Restate the slice goal and keep the worktree limited to that slice. Do not mix later cleanup or opportunistic refactors into it.
2. Add or update tests with at least one positive and one negative case for every new external input or behavior. Include boundary, release/cleanup, and no-side-effect assertions where relevant.
3. Run the listed focused tests while developing.
4. Review the changed behavior against nearby tests. Add missing positive, negative, boundary, ordering, lifecycle, and sensitive-data assertions before declaring coverage sufficient.
5. Run `npm run build` and the unchanged full suite with `npm test`. If `npm test` fails with `listen EPERM` on `127.0.0.1`, rerun that same full-suite command with loopback/network permission; do not weaken listener tests.
6. Fix every slice-related failure and repeat both quality gates. An unrelated failure leaves the slice uncommitted unless the user explicitly directs otherwise.
7. Run `git diff --check` and review the staged diff for raw credentials, opaque references, authorization headers, cookies, response bodies, real internal hostnames, and unrelated files.
8. If testing reveals a generally reusable project lesson, add it to `AGENTS.md` in the same slice. Do not add one-off bug notes.
9. Commit only after all required gates pass, using the proposed concise imperative subject or an equivalent. One slice equals one commit.

Documentation-only Slice 19 is eligible for the user's test exception. It still requires `git diff --check` and manual link/example review. Running the full suite is preferred if documentation contract tests are changed or if any supposedly documentation-only edit touches executable files.

## Cross-cutting invariants

Every slice must preserve these invariants:

- Authenticate every MCP POST independently; never issue or trust `mcp-session-id`.
- Enforce authentication, service authorization, destination validation, and policy before credential substitution or downstream HTTP calls.
- Admission rejection must occur before reference redemption, credential substitution, downstream I/O, and response scanning.
- Never log or audit raw configured credentials, opaque token values, `Authorization` headers, cookies, request bodies, or downstream response bodies.
- Keep gateway references bound to authenticated subjects, services, destinations, and access entries rather than transport state.
- Use `example.org` stand-ins in all new documentation and tests that need hostnames.
- Preserve the current response-scanning limitation: it is defense in depth, not a universal non-exfiltration guarantee.
- Do not split large modules solely by line count. Move code only when a slice creates a natural ownership seam.

## Dependency-ordered remediation slices

### Slice 1 — Reject structurally unsafe OAuth trust URLs

**Outcome:** OAuth trust configuration rejects URL userinfo and fragments before startup for `server.resource`, external OAuth issuer, explicit external JWKS URL, and built-in OAuth issuer. Valid HTTPS and exact loopback HTTP values remain accepted.

**Likely files:** `src/config.ts`, `test/config.test.ts`, `test/config-diagnostics.test.ts`, `docs/config-reference.md`.

**Implementation boundary:** Add one reusable trust-URL validator and invoke it during configuration normalization. Do not change cleartext HTTP behavior yet; that is Slice 2. Diagnostics must identify the configuration field without echoing the URL or embedded userinfo.

**Coverage:**

- Positive: representative HTTPS and loopback HTTP values without userinfo/fragments load.
- Negative: each trust field rejects userinfo and fragments with source-located, sanitized `config_error` diagnostics.
- Negative: an explicit JWKS URL cannot bypass the checks applied to an issuer-derived JWKS URL.

**Focused tests:** `npm test -- test/config.test.ts test/config-diagnostics.test.ts`.

**Commit:** `Reject unsafe OAuth trust URLs`.

### Slice 2 — Require explicit acceptance of non-loopback OAuth HTTP

**Outcome:** Non-loopback cleartext OAuth trust URLs fail closed by default. A narrowly named boolean configuration override, `server.allow_insecure_oauth_http`, defaults to `false` and permits them only when explicitly set to `true`. Exact loopback HTTP remains supported without the override for local Codex and test workflows.

**Likely files:** `src/config.ts`, `src/types.ts`, `test/config.test.ts`, `test/config-diagnostics.test.ts`, `docs/config-reference.md`, `README.md`, `examples/config.yaml` if the documented shape needs an explicit value.

**Implementation boundary:** Replace warning-only handling for non-loopback HTTP on `server.resource`, external issuer/effective JWKS, and built-in issuer with one fail-closed validation path. Retain the missing-`server.resource` warning as a separate diagnostic. When the override is enabled, emit one sanitized startup warning that states the accepted risk without including configured URLs.

**Coverage:**

- Positive: HTTPS and exact loopback IPv4/IPv6/`localhost` trust URLs pass with the default.
- Positive: every non-loopback HTTP trust field passes only with the explicit override and produces a sanitized warning.
- Negative: every non-loopback HTTP trust field, including an issuer-derived JWKS URL, fails without the override.
- Negative: unknown or non-boolean override values fail strict configuration validation.
- Documentation tests continue to distinguish OAuth origins from the ChatGPT MCP URL containing `/mcp`.

**Focused tests:** `npm test -- test/config.test.ts test/config-diagnostics.test.ts test/docs-examples.test.ts test/server.test.ts`.

**Commit:** `Require explicit insecure OAuth HTTP opt-in`.

### Slice 3 — Bound downstream work globally and per subject

**Outcome:** Authenticated `service_request` work is limited by `limits.max_service_requests_inflight` and `limits.max_service_requests_inflight_per_subject`, with defaults of `32` and `4`. Capacity exhaustion returns the existing structured `capacity_exceeded` tool error.

**Likely files:** `src/config.ts`, `src/types.ts`, `src/inflightLimiter.ts` or a narrowly named downstream limiter module, `src/gateway.ts`, `src/errors.ts` only if error metadata changes, `test/config.test.ts`, `test/inflight-limiter.test.ts`, `test/gateway.test.ts`, `test/mcp-surface.test.ts`, `docs/config-reference.md`, `examples/config.yaml`.

**Implementation boundary:** Reuse or minimally extend the existing in-flight limiter. Acquire after service authorization, destination resolution, and policy approval, but before token/reference validation or substitution. Release exactly once in `finally` after success, timeout, connection error, body-limit failure, binary rejection, or scanner failure. Do not queue work in this slice.

**Coverage:**

- Positive: requests below both limits run concurrently and a released slot is reusable.
- Negative: global saturation rejects excess work with `capacity_exceeded` and does not contact downstream.
- Negative: one subject cannot consume another subject's reserved opportunity while the global limit still has room.
- Ordering: a saturated, otherwise authorized request containing an invalid reference is rejected for capacity before reference redemption/substitution, and downstream observes no request.
- Cleanup: a failing or timed-out downstream request releases its slot.
- Configuration: defaults, explicit valid values, zero/negative values, and per-subject-greater-than-global are tested.

**Focused tests:** `npm test -- test/config.test.ts test/inflight-limiter.test.ts test/gateway.test.ts test/mcp-surface.test.ts`.

**Commit:** `Bound downstream work by subject`.

### Slice 4 — Isolate slow services with a per-service limit

**Outcome:** `limits.max_service_requests_inflight_per_service` defaults to `8` and prevents one slow configured service from consuming all global capacity.

**Likely files:** the limiter introduced or extended in Slice 3, `src/config.ts`, `src/types.ts`, `src/gateway.ts`, `test/config.test.ts`, `test/inflight-limiter.test.ts`, `test/gateway.test.ts`, `docs/config-reference.md`, `examples/config.yaml`.

**Implementation boundary:** Add only the service dimension. Preserve the global and per-subject semantics from Slice 3 and use the canonical configured service ID as the key.

**Coverage:**

- Positive: service A at capacity does not block an authorized request to service B when subject/global capacity remains.
- Negative: excess work for service A returns `capacity_exceeded` without a downstream call.
- Cleanup: success and failure release the per-service slot.
- Configuration: zero/negative values and per-service-greater-than-global are rejected.

**Focused tests:** `npm test -- test/config.test.ts test/inflight-limiter.test.ts test/gateway.test.ts`.

**Commit:** `Isolate downstream service capacity`.

### Slice 5 — Sanitize all audit events at the sink

**Outcome:** The audit boundary sanitizes an event before either memory retention or durable writing, so producer mistakes cannot persist raw configured credentials, opaque `gref_`/`sec_` values or forged prefixes, canonical HTTP Basic credentials, or recognized credential patterns in caller-controlled text such as reference reasons.

**Likely files:** `src/audit.ts`, a small shared audit-text sanitizer if needed, `test/audit.test.ts`, `test/tokens.test.ts`, `docs/security-notes.md`.

**Implementation boundary:** Preserve typed structural fields and benign reasons. Apply the same sanitized event to memory and JSONL. Do not deserialize or rewrite downstream request/response bodies, and do not route audit data through the asynchronous response scanner. Keep raw event values out of error logs when sanitization itself fails.

**Coverage:**

- Positive: benign caller reasons remain useful and structural IDs remain intact.
- Negative: a reason containing an exact configured credential, complete/forged opaque references, a canonical Basic credential, and a supported credential-pattern example is redacted in both memory and file output.
- Negative: serialized audit output contains none of the original sensitive strings or secret-bearing field names.
- Regression: allowed, denied, invalid-reference, and tool-invocation events retain their required fields after sanitization.

**Focused tests:** `npm test -- test/audit.test.ts test/tokens.test.ts test/logger.test.ts`.

**Commit:** `Sanitize audit events at the sink`.

### Slice 6 — Own one durable audit writer and track degradation

**Outcome:** A per-application audit sink creates the configured directory once, opens one append-only file descriptor, creates new files with mode `0600`, writes complete JSONL records through that descriptor, exposes a sticky degraded state after open/write failure, and closes idempotently.

**Likely files:** `src/audit.ts`, `src/server.ts` for temporary lifecycle wiring, `test/audit.test.ts`, `test/server.test.ts`, `docs/config-reference.md`.

**Implementation boundary:** Choose the architecture review's deliberately synchronous open-file-descriptor option; do not introduce an asynchronous queue in this MVP slice. Keep the existing fail-open request behavior until readiness consumes the state in Slice 7. Initialize the sink at application startup so an unusable configured path is visible before the first privileged operation. Never log downstream response bodies, event bodies, credentials, or opaque values on failure.

**Coverage:**

- Positive: multiple events produce complete ordered JSONL entries without reopening the path per event; new file permissions are restrictive; close is idempotent.
- Negative: open failure and injected write failure set degraded state, preserve the bounded sanitized memory history, and emit only sanitized structural errors.
- Negative: writes after close do not leak data or throw uncaught exceptions.

**Focused tests:** `npm test -- test/audit.test.ts test/server.test.ts`.

**Commit:** `Own durable audit writer state`.

### Slice 7 — Expose audit durability through readiness

**Outcome:** `/health` returns the existing `200` ready payload when durable audit is healthy or not configured, and returns `503` with a stable sanitized audit-degraded check after durable audit initialization/write failure. Privileged operations remain fail-open in this MVP; no `audit.required` option is introduced.

**Likely files:** `src/server.ts`, `src/audit.ts`, `test/server.test.ts`, `test/audit.test.ts`, `README.md`, `docs/config-reference.md`, `docs/security-notes.md`.

**Implementation boundary:** Do not expose filesystem paths or raw error messages in health responses. Document that degradation is sticky until restart, that operators must monitor health and disk capacity, and that rename-based rotation requires restart/reopen while `copytruncate`-style rotation is compatible with an open descriptor.

**Coverage:**

- Positive: no-file and healthy-file configurations remain `200` and ready.
- Negative: initialization and later write failures produce `503` without exposing the audit path or sensitive content.
- Recovery contract: document and test the chosen sticky-until-restart behavior.

**Focused tests:** `npm test -- test/server.test.ts test/audit.test.ts test/docs-examples.test.ts`.

**Commit:** `Report audit durability degradation`.

### Slice 8 — Generate collision-resistant public request IDs

**Outcome:** One helper generates `req_<UUID>` identifiers for successful, denied, and capacity-rejected service requests. Logs, audits, denial explanations, tool results, and binary response resource URIs use the same request ID for one operation.

**Likely files:** a small request ID module, `src/gateway.ts`, `src/denials.ts`, `test/gateway.test.ts`, `test/denials.test.ts`, `test/mcp-surface.test.ts`, `test/audit.test.ts`.

**Implementation boundary:** Remove the timestamp-only ID path without changing subject binding or denial retention. Do not add process-global counters.

**Coverage:**

- Positive: allowed and denied IDs match the public format and correlate across response/audit/log/resource URI surfaces.
- Negative: many requests created under a fixed clock remain unique; a denial ID cannot expose another subject's denial.
- Regression: binary resources retain the matching collision-resistant URI component.

**Focused tests:** `npm test -- test/gateway.test.ts test/denials.test.ts test/mcp-surface.test.ts test/audit.test.ts`.

**Commit:** `Use collision-resistant request IDs`.

### Slice 9 — Introduce an idempotent application runtime lifecycle

**Outcome:** A `GatewayRuntime`/`Application` composition object is constructed once per server, owns configuration plus existing subsystem instances, and exposes an idempotent asynchronous `close()`. Server close now closes the secret scanner pool as well as maintenance and the audit descriptor.

**Likely files:** new runtime module, `src/server.ts`, `src/secretRuntime.ts`, `src/secretScannerPool.ts` only if its public lifecycle needs a narrow adapter, `src/audit.ts`, `src/maintenance.ts`, `test/server.test.ts`, `test/maintenance.test.ts`, `test/secret-scanner-pool.test.ts`.

**Implementation boundary:** Initially wrap existing constructors/getters rather than rewriting their internals. Preserve a narrow compatibility entry point for tests that currently call `createGatewayServer(config)`, but ensure production creates exactly one runtime. Do not migrate built-in OAuth internals yet.

**Coverage:**

- Positive: create/start/close releases maintenance, audit, and scanner resources; repeated close succeeds.
- Negative: partial initialization failure closes resources already created and does not leave timers/workers alive.
- Lifecycle: closing one runtime does not close another runtime built from a separate configuration.

**Focused tests:** `npm test -- test/server.test.ts test/maintenance.test.ts test/secret-scanner-pool.test.ts test/audit.test.ts`.

**Commit:** `Own gateway runtime lifecycle`.

### Slice 10 — Inject capability and admission state through the runtime

**Outcome:** Server, MCP handlers, tools, and gateway execution receive runtime-owned token broker, denial store, and downstream limiter dependencies. Their corresponding `WeakMap<GatewayConfig, ...>` lookups and test-only default broker mutation are removed.

**Likely files:** runtime module, `src/server.ts`, `src/mcp/server.ts`, `src/mcp/tools.ts`, `src/gateway.ts`, `src/tokens.ts`, `src/denials.ts`, the downstream limiter, and their nearby tests/helpers.

**Implementation boundary:** This is dependency wiring, not a behavior rewrite. Keep narrow domain classes and existing algorithms. Preserve ordering: authorization/destination/policy, then admission, then reference work/downstream I/O. Leave audit and response-scanner injection for Slice 11.

**Coverage:**

- Positive: two runtimes with similar configuration retain independent tokens, denials, and admission counts.
- Negative: a reference or denial created in runtime A is unusable/unexplainable in runtime B.
- Negative: saturating runtime A does not consume an admission slot in runtime B.
- Regression: reference issuance, service requests, and denial explanation continue working over independent stateless MCP requests.

**Focused tests:** `npm test -- test/tokens.test.ts test/denials.test.ts test/inflight-limiter.test.ts test/gateway.test.ts test/mcp-surface.test.ts test/server.test.ts`.

**Commit:** `Own capability state in gateway runtime`.

### Slice 11 — Inject audit and response protection through the runtime

**Outcome:** Gateway execution receives runtime-owned audit and response-protection dependencies. The configuration-keyed audit store and secret runtime registries are removed, and scanner statistics/closure refer to the runtime that handled the request.

**Likely files:** runtime module, `src/server.ts`, `src/mcp/server.ts`, `src/mcp/tools.ts`, `src/gateway.ts`, `src/audit.ts`, `src/secretRuntime.ts`, and their nearby tests/helpers.

**Implementation boundary:** Move only audit, tokenizer, scanner pool, resolved rules, and sensitive-name matcher ownership. Preserve the audit degradation behavior from Slices 5–7 and response-scanning behavior byte-for-byte. Do not move OAuth internals yet.

**Coverage:**

- Positive: two runtimes retain independent audit history, degradation state, scanner statistics, and scanner lifecycle.
- Negative: degrading or closing runtime A's audit/scanner does not degrade or close runtime B.
- Regression: exact credentials, sensitive names, HTTP Basic values, opaque prefixes, binary safeguards, and scanner overload/failure retain their current fail-closed behavior.

**Focused tests:** `npm test -- test/audit.test.ts test/response-token-guard.test.ts test/response-tokenizer.test.ts test/secret-scanner.test.ts test/secret-scanner-pool.test.ts test/binary-response.test.ts test/gateway.test.ts test/server.test.ts`.

**Commit:** `Own response protection in gateway runtime`.

### Slice 12 — Move OAuth and maintenance ownership into the runtime

**Outcome:** Built-in OAuth state, body/password/login limiters, OAuth client metadata fetcher/cache, and maintenance task registry are runtime-owned. The remaining configuration-keyed module registries are removed.

**Likely files:** runtime module, `src/builtinOAuth.ts`, `src/oauthClientMetadata.ts`, `src/maintenance.ts`, `src/server.ts`, relevant OAuth, limiter, metadata, maintenance, and server tests.

**Implementation boundary:** Move construction and ownership behind narrow interfaces without splitting OAuth behavior merely because the module is large. Preserve hash-only atomic refresh persistence, metadata SSRF controls, limiter identities, and all existing OAuth routes/contracts.

**Coverage:**

- Positive: separate runtimes isolate authorization codes, refresh families, limiter counts, metadata cache entries, and maintenance tasks.
- Negative: state issued in runtime A cannot be redeemed or replayed through runtime B.
- Cleanup: runtime close clears timers and closes/invalidates owned state without corrupting the configured refresh snapshot.
- Regression: all built-in and external OAuth positive/negative suites pass unchanged except for dependency construction.

**Focused tests:** `npm test -- test/auth.test.ts test/oauth-client-metadata.test.ts test/login-attempt-limiter.test.ts test/inflight-limiter.test.ts test/maintenance.test.ts test/server.test.ts test/mcp-surface.test.ts` plus any built-in OAuth tests matched by `rg --files test | rg 'oauth'`.

**Commit:** `Own OAuth state in gateway runtime`.

### Slice 13 — Gracefully close the runtime on process signals

**Outcome:** Production startup handles `SIGTERM` and `SIGINT` through one idempotent shutdown path that stops accepting traffic, waits for the HTTP server to close, closes the runtime, logs sanitized completion/failure, and exits with an appropriate status.

**Likely files:** `src/server.ts` or a small application entry module, runtime module, `test/server.test.ts` or a focused lifecycle test.

**Implementation boundary:** Keep signal registration at the executable composition root, not in reusable server constructors. Do not call `process.exit()` before cleanup completes. A second signal may force termination only if that behavior is explicit and tested.

**Coverage:**

- Positive: either signal invokes server/runtime close once in order.
- Negative: repeated signals or a close error do not double-close resources or log sensitive values.
- Regression: importing server modules in tests does not install process signal handlers.

**Focused tests:** `npm test -- test/server.test.ts test/maintenance.test.ts test/secret-scanner-pool.test.ts`.

**Commit:** `Close gateway runtime on signals`.

### Slice 14 — Use strict runtime schemas for MCP inputs

**Outcome:** Each tool's runtime argument validation uses a strict Zod schema, and its advertised input JSON Schema is generated from that same schema. Manual field readers no longer silently ignore unknown top-level fields.

**Likely files:** `src/mcp/schemas.ts`, `src/mcp/tools.ts`, `test/mcp-surface.test.ts`, `test/server.test.ts` if HTTP-level malformed calls are covered there.

**Implementation boundary:** Preserve existing tool names and stable error codes/messages where documented. Keep `query` and `body` extensible where intended while closing each tool's top-level object and typed header map. Do not build the full tool registry until Slice 15.

**Coverage:**

- Positive: representative valid arguments for all five tools parse and execute; intended arbitrary query/body values remain allowed.
- Negative: unknown top-level fields are rejected for every tool, including nominally empty input.
- Negative: malformed nested headers, access ID arrays, optional strings, and missing required fields fail before handler side effects.
- Contract: generated input schemas advertise `additionalProperties: false` wherever runtime validation is strict.

**Focused tests:** `npm test -- test/mcp-surface.test.ts test/server.test.ts test/tokens.test.ts test/gateway.test.ts`.

**Commit:** `Unify MCP input validation`.

### Slice 15 — Define tools in one typed registry

**Outcome:** One small registry owns each tool's name, required scope, annotations, input/output schema, parser, and handler. Tool listing, call dispatch, and pre-dispatch scope classification all consult that registry.

**Likely files:** `src/mcp/tools.ts`, `src/mcp/server.ts`, possibly a new registry module, `test/mcp-surface.test.ts`, `test/auth.test.ts`, `test/server.test.ts`.

**Implementation boundary:** Keep exactly the existing five generic tools. Do not add service-specific entries or a framework. Unknown tools must remain authenticated and return the established `not_implemented` result without accidentally receiving a privileged scope classification.

**Coverage:**

- Positive: every advertised tool dispatches to its registered handler and requests its registered scope for single and batch JSON-RPC calls.
- Negative: an unknown tool is not advertised, cannot alias a registered handler, and does not bypass authentication.
- Contract: descriptor scope, `_meta` scope, pre-dispatch scope, parser, and handler are mechanically identical for each entry.

**Focused tests:** `npm test -- test/mcp-surface.test.ts test/auth.test.ts test/server.test.ts`.

**Commit:** `Centralize MCP tool contracts`.

### Slice 16 — Fully specify and verify MCP output contracts

**Outcome:** Nested list, policy, service response, TLS, headers, and denial structures are fully described by shared output schemas. Representative successful and error results are validated against the same schemas used for advertisement.

**Likely files:** `src/mcp/schemas.ts`, the tool registry, `test/mcp-surface.test.ts`, `test/registry.test.ts`, `test/gateway.test.ts`.

**Implementation boundary:** Specify only stable client-visible fields. Keep intentionally arbitrary downstream response bodies as an unconstrained value. Do not expose internal reference IDs, credentials, scanner internals, or audit state.

**Coverage:**

- Positive: representative success output from each tool passes its registered schema.
- Positive: representative structured tool errors pass the shared error contract.
- Negative: removing a required nested field, adding an unadvertised field, or using a wrong nested type fails contract validation.
- Regression: ChatGPT/OpenAI-compatible tool metadata and MCP SDK initialization remain accepted.

**Focused tests:** `npm test -- test/mcp-surface.test.ts test/registry.test.ts test/gateway.test.ts`.

**Commit:** `Specify MCP output contracts`.

### Slice 17 — Distinguish downstream request and response size errors

**Outcome:** Oversized outbound request bodies return `request_too_large`; oversized downstream responses continue returning `response_too_large`. The new code is included in the public error union and documentation.

**Likely files:** `src/errors.ts`, `src/gateway.ts`, `test/gateway.test.ts`, `test/mcp-surface.test.ts`, `docs/config-reference.md`, `docs/prd.md` only if it is maintained as the active contract.

**Implementation boundary:** Change only the incorrect request-body code and its public documentation. Do not change inbound MCP/OAuth HTTP `413` handling or downstream response behavior.

**Coverage:**

- Positive: a body at the configured request limit is accepted and sent with recomputed length.
- Negative: a body one byte over is rejected with `request_too_large` before downstream I/O.
- Regression: declared and streamed oversized downstream responses still return `response_too_large`.

**Focused tests:** `npm test -- test/gateway.test.ts test/http-body.test.ts test/mcp-surface.test.ts`.

**Commit:** `Distinguish request body limit errors`.

### Slice 18 — Derive the MCP server version from package metadata

**Outcome:** MCP initialization reports the version from `package.json` through one validated version helper; the literal in `src/mcp/server.ts` is removed.

**Likely files:** a small version module, `src/mcp/server.ts`, `test/mcp-surface.test.ts`, possibly Docker/package tests if packaging assumptions are asserted.

**Implementation boundary:** Resolve metadata in both source tests and compiled Docker layout without adding a generation tool. Fail startup clearly if package metadata is missing or malformed, without dumping the file contents.

**Coverage:**

- Positive: initialized `serverInfo.version` equals `package.json` and the compiled/container path includes the required metadata.
- Negative: the version helper rejects a missing, empty, or non-string version through dependency injection or a fixture without exposing unrelated package content.

**Focused tests:** `npm test -- test/mcp-surface.test.ts test/docker-metadata.test.ts`.

**Commit:** `Derive MCP version from package metadata`.

### Slice 19 — Make the single-instance deployment contract prominent

**Outcome:** Deployment documentation explicitly states that gateway references and other runtime capability state are instance-local, the supported replica count is one, horizontal load balancing causes random reference failures, and sticky sessions are not a substitute for a shared atomic capability store.

**Likely files:** `README.md`, `docs/config-reference.md`, `docker-compose.example.yaml`, `docs/security-notes.md`.

**Implementation boundary:** Documentation only. Do not add Redis/database support or imply that stateless MCP makes all application state stateless. Include audit persistence, refresh-state single-writer, signing-key, and writable-storage implications where operators choose mounts.

**Review:** Verify all examples use `example.org` stand-ins, the Compose YAML remains valid, links resolve, and OAuth origin versus MCP path guidance remains correct. If a documentation contract test is added or changed, run the normal build/full-suite gate despite the documentation exception.

**Commit:** `Document single-instance deployment`.

## Coverage review matrix

| Review finding | Remediation slices | Required proof |
| --- | --- | --- |
| Non-loopback cleartext OAuth trust | 1–2 | Unsafe structure rejected; HTTPS/loopback allowed; cleartext requires explicit opt-in; derived JWKS covered |
| Unbounded authenticated downstream work | 3–4 | Global, subject, and service limits; no downstream/substitution on rejection; every terminal path releases |
| Audit sanitization, blocking ownership, and invisible degradation | 5–7 | Sink-level redaction; one owned restrictive descriptor; sanitized failure state; health becomes `503` |
| Colliding successful request IDs | 8 | Fixed-clock uniqueness and cross-surface correlation |
| Fragmented runtime ownership and scanner leak | 9–13 | One runtime, isolated dependencies, no config-keyed registries, idempotent close, signal cleanup |
| MCP schema/parser/scope drift | 14–16 | Strict shared schemas, one registry, unknown-field rejection, representative output validation |
| Request/response error-code drift | 17 | Exact boundary and no-downstream tests for `request_too_large`; response regression test |
| MCP version duplication | 18 | Initialization equals validated package version |
| Implicit single-instance topology | 19 | Prominent operator guidance without pretending sticky sessions solve capability state |

## Final completion gate

After Slice 19:

1. Confirm every slice is represented by exactly one focused commit and no commit contains unrelated user changes.
2. Run `npm run build`, `npm test`, and `git diff --check` from the final tree. Apply the documented loopback-permission rerun only if the unchanged suite reports `listen EPERM`.
3. Review test counts and the matrix above. Every new input and behavior must have positive and negative evidence; add a final test-only slice only if a real uncovered contract is found, and subject that slice to the same full-suite/commit gate.
4. Search logs, audit fixtures, docs, and examples for raw credentials, opaque references, authorization/cookie values, response bodies, and real deployment hostnames.
5. Confirm `AGENTS.md` contains only durable lessons learned during implementation/testing, not a transcript of slice-specific bugs.
6. Confirm the final implementation still supports stateless MCP use from ChatGPT and Codex and does not introduce any item listed as out of scope.

## Deferred decisions

The following are deliberately not part of this remediation sequence:

- `audit.required: true` or fail-closed privileged operations after audit failure. Readiness degradation is the selected minimum policy; a required-audit mode needs a separate product decision about availability.
- An asynchronous audit queue. The selected MVP design uses one deliberately synchronous open descriptor. Revisit only with measured event-loop or storage pressure and an explicit bounded-overload contract.
- Shared capability state, horizontal replicas, Redis, or sticky-session-based approximations.
- Additional tool types, service adapters, profile packs, web frameworks, databases, queues, enterprise IAM features, policy languages, or broad response-decoder catalogs.
- Large-file refactors that do not naturally follow runtime ownership seams.

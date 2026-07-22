# Software Architecture Review

## Scope

- **System:** SecretSauce (MCP)
- **Revision reviewed:** `76e73a717f79032535598b4c84d3bf5b208957a4`
- **Review date:** 2026-07-22
- **Scope:** TypeScript runtime and MCP surface under `src/`, configuration and data contracts, built-in and external OAuth, downstream HTTP transport, credential-reference lifecycle, response protection, audit/logging, tests, Docker packaging, CI, and operator documentation.
- **Method:** Source-assisted architecture review. I traced every public route through authentication, authorization, destination and policy enforcement, reference substitution, downstream I/O, response handling, and audit. I also reviewed representative positive and negative tests and the prior security audits/remediation records.
- **Deployment assumption:** The current product target is a small, self-hosted, single-process gateway. No production reverse proxy, identity provider, service configuration, DNS environment, or downstream service was available for validation.
- **Verification:** `npm run build`, `npm test` (32 files, 333 tests), and `git diff --check` passed. The initial sandboxed test run failed only because loopback listeners returned `EPERM`; the unchanged full suite passed with loopback permission as required by repository instructions.

This is an architecture review, not a claim that the implementation has been exhaustively penetration-tested. The repository's prior security reviews remain the more detailed source for vulnerability history.

## Executive Summary

SecretSauce has a strong architecture for its stated MVP. The important security decisions are encoded in server-side control flow rather than model instructions: MCP requests are authenticated independently, service access and destinations are checked, policy is evaluated, and only then are protected values substituted and sent downstream (`src/server.ts:59-75`, `src/gateway.ts:65-181`). That is the right foundation.

The implementation is also refreshingly honest about its limit: response scanning reduces accidental disclosure but cannot contain arbitrary computation performed by an approved downstream endpoint. That limitation is architectural, not a missing regex, and the documentation treats endpoint selection as part of the credential boundary.

My overall assessment is: **good single-instance MVP architecture, suitable for a carefully configured homelab or small administrative deployment; not yet an operationally complete general-purpose, multi-tenant internet gateway.** The gap is mostly workload governance and runtime ownership, not a need to replace the core design.

The highest-value changes are:

1. Bound authenticated downstream work globally and per subject/service.
2. Reject non-loopback cleartext OAuth trust URLs unless an explicit insecure-development override is configured.
3. Make the audit boundary sanitize caller-controlled values and expose durable-write degradation.
4. Give successful requests collision-resistant IDs.
5. Introduce one runtime/composition object before the next substantial feature expansion.

I would not add a web framework, database, queue, Redis, service-specific adapters, or an enterprise policy engine to solve current problems. Those would cost more than they return at this scale.

## What Is Good

### Good: the privileged request pipeline has the right ordering

Authentication happens before MCP body dispatch. Service ACL checks, destination resolution, and policy evaluation happen before opaque-reference redemption and before downstream I/O (`src/server.ts:59-75`, `src/gateway.ts:71-159`). Caller-controlled authority, forwarding, hop-by-hop, and cookie headers are rejected before the request is built (`src/gateway.ts:133-159`, `src/gateway.ts:375-407`).

**Justification:** This makes the highest-value security invariants structural. A client or model cannot bypass them by ignoring instructions, and future response-scanning improvements are not carrying the burden of request authorization.

### Good: stateless MCP is separated from durable capability semantics

Every MCP POST receives a short-lived SDK transport and is authenticated independently; no `mcp-session-id` is issued or trusted (`src/mcp/server.ts:58-80`, `src/server.ts:104-140`). Continuity comes from gateway references bound to subject, service, destination, and access entry (`src/tokens.ts:87-176`).

**Justification:** Transport state is a poor authorization boundary. The present design avoids stale session routing state while preserving multi-step agent workflows across Codex and ChatGPT clients.

### Good: destination and route canonicalization are centralized

Destination selection, scheme/host/port validation, base-path containment, and ambiguous path-escape rejection live in one resolver (`src/urlValidation.ts:18-35`, `src/urlValidation.ts:62-130`). Policy evaluates the same canonical pathname that is sent downstream (`src/policy.ts:13-35`).

**Justification:** Gateway security frequently fails when policy evaluates a different authority or pathname from the HTTP client. Centralizing this boundary substantially reduces that drift risk.

### Good: state is deliberately bounded

Opaque reference records have total and per-subject capacities and expiry sweeps (`src/tokens.ts:288-368`). Denial records are TTL- and capacity-bounded (`src/denials.ts:14-70`). Authorization codes, refresh records, unauthenticated body reads, password verification, OAuth client metadata fetches, and secret scans also have explicit limits.

**Justification:** Bounded state is unusually thorough for an MVP and directly addresses long-running process stability. The periodic maintenance registry is simple and adequate for one process (`src/maintenance.ts:7-34`).

### Good: response protection is a distinct, fail-closed subsystem

Responses remain byte-oriented through the downstream boundary. Text, binary, declared Base64, exact configured credentials, sensitive JSON names, HTTP Basic values, and forged opaque prefixes have explicit handling (`src/gateway.ts:181-323`, `src/responseTokenizer.ts:76-229`). Secretlint work runs in a bounded worker pool with per-subject fairness and queue timeouts (`src/secretScannerPool.ts:45-85`, `src/secretScannerPool.ts:122-168`).

**Justification:** This avoids coupling the event loop to CPU-heavy scanning and avoids corrupting binary or JSON-like responses through casual parse/reserialize logic. The repository also correctly documents that scanning is defense in depth, not universal non-exfiltration.

### Good: configuration is treated as an external contract

The configuration uses strict Zod schemas, rejects unknown fields, resolves secrets at startup, validates regexes and cross-field constraints, and maps failures back to YAML locations (`src/config.ts:33-217`, `src/config.ts:227-253`, `src/yamlConfig.ts:7-53`). Unsafe-but-supported settings such as broad destinations and disabled TLS verification produce visible metadata or warnings.

**Justification:** Failing startup with source-located errors is preferable to discovering a malformed security policy on the first privileged request. This is a strong operator experience without requiring a UI.

### Good: test depth is proportionate to the risk

The repository currently has 333 tests across 32 test files. They cover both success and denial paths around authentication, scopes, destination validation, policy, token binding, framing, cookies, TLS, binary responses, scanner overload/failure, OAuth state, logging, audit, configuration, MCP compatibility, Docker metadata, and documentation examples. CI gates image publication on install, build, and the full suite (`.github/workflows/ci.yml:14-66`).

**Justification:** The tests focus on boundaries and failure modes rather than only happy-path module behavior. That is the right shape for a credential-bearing gateway.

## What Is Bad Or Risky

### Risky: authenticated downstream work is not admission-controlled

The service bounds each request body, response body, downstream timeout, and later scan queue, but it does not bound the number of authenticated service requests in progress. A request can hold a downstream socket and buffer up to the configured response limit before it reaches the bounded scanner (`src/gateway.ts:181-203`, `src/gateway.ts:410-479`). The limits model includes unauthenticated OAuth work and metadata/scanner controls, but no global, per-subject, or per-service downstream request limit (`src/config.ts:179-206`, `src/types.ts:90-109`).

**Justification:** Stateless MCP fixed persistent transport exhaustion, but it did not bound active work. One valid subject—or a prompt-injected client using that subject—can create aggregate socket, heap, scan-queue, audit, and downstream load far above the per-request limits. Reverse-proxy connection limits help but cannot express subject/service fairness.

### Risky: cleartext OAuth trust is warned about rather than explicitly authorized

Non-loopback HTTP resource, issuer, and JWKS URLs only produce startup warnings (`src/config.ts:402-419`). External OAuth then retrieves keys from the configured or issuer-derived JWKS URL and treats successfully verified tokens as identities (`src/auth.ts:57-85`, `src/auth.ts:150-155`).

**Justification:** A cleartext JWKS hop is part of the authentication root of trust. Warning-only behavior is too permissive for a service intended to be reachable by hosted clients. Trusted private networks are a legitimate deployment choice, but accepting this risk should require a named opt-in rather than relying on a log line during startup.

### Risky: audit is synchronous, fail-open, and does not sanitize all caller-controlled text

Every configured file audit creates the directory and appends synchronously on the Node event loop. Write failure logs an error and allows the operation to continue (`src/audit.ts:77-91`). The `/health` response remains `ready` regardless of audit state (`src/server.ts:33-39`). In addition, reference-issuance events persist the caller-provided `reason` unchanged (`src/tokens.ts:145-155`), while the audit sink serializes the event directly.

**Justification:** Slow or full storage can pause all traffic, while failed storage can silently remove the durable trail from privileged operations except for a log event. A caller can also place an opaque reference or credential-shaped value in a later `reason`, contrary to the repository's no-sensitive-audit invariant. Sanitization should be enforced at the sink, not only by every event producer remembering the rule.

### Risky: successful request IDs can collide

Successful downstream request IDs are `req_${Date.now()}` (`src/gateway.ts:179-181`), while denial IDs correctly use `randomUUID()` (`src/denials.ts:23-25`). Two requests starting in the same millisecond receive the same public correlation ID and binary resource URI.

**Justification:** This weakens audit correlation precisely under concurrency and can make two response resources appear to have the same identity. It is an inexpensive correctness fix with no compatibility value in preserving the timestamp-only format.

### Risky: runtime ownership is implicit and fragmented

The immutable `GatewayConfig` object also acts as the identity key for separate module-level `WeakMap` registries: audit, maintenance, token broker, denial store, secret runtime, OAuth state, password/body limiters, and metadata fetchers (`src/audit.ts:65`, `src/maintenance.ts:5`, `src/tokens.ts:361`, `src/denials.ts:61`, `src/secretRuntime.ts:15`, `src/builtinOAuth.ts:82-88`). Server close stops maintenance, but it does not close the secret scanner pool even though the pool has an explicit lifecycle (`src/server.ts:151`, `src/secretScannerPool.ts:79-86`).

**Justification:** This works for one process with one immutable config. It becomes difficult to reason about cleanup, embedding, reload, parallel instances in tests, or future hot configuration. Dependencies are obtained through hidden global lookups rather than constructed and owned by one composition root.

### Risky: tool schemas and runtime parsing are separate sources of truth

MCP input schemas declare closed objects with `additionalProperties: false` (`src/mcp/schemas.ts:54-75`, `src/mcp/schemas.ts:132-148`), while runtime parsing is a separate set of manual readers that selects known fields but does not itself reject extra fields (`src/mcp/tools.ts:251-325`). Several output schemas describe nested values only as generic objects (`src/mcp/schemas.ts:78-97`, `src/mcp/schemas.ts:150-170`).

**Justification:** With only five tools this is manageable, but every contract change must be synchronized across descriptor, parser, TypeScript interface, implementation, output schema, scope classifier, and audit union. The probability of drift rises faster than the tool count.

### Risky: some operational contracts are documented but not enforced

Opaque gateway references live only in process memory, and the refresh-state file is single-process writable. That makes the effective deployment topology one gateway process with no horizontal load balancing unless clients accept random reference failures. The documentation describes the underlying persistence facts, but the Compose/runtime surface does not state a simple `replicas: 1` invariant prominently.

**Justification:** This is acceptable for the target deployment. The risk is an operator treating a stateless MCP transport as meaning the whole application can scale horizontally; the durable capability state is still instance-local.

### Risky: contract details show small signs of drift

The downstream request-body limit throws `response_too_large` even though the message says the request is too large (`src/gateway.ts:353-362`), while inbound HTTP body limits use `request_too_large` (`src/httpBody.ts:5-21`). The MCP server version is also duplicated as a literal rather than derived from package metadata (`src/mcp/server.ts:17-23`, `package.json:3`).

**Justification:** Neither issue threatens the architecture, but both are signals that public contract metadata is manually duplicated. These are cheap to correct before external consumers begin depending on them.

## What Should Change

### Priority 0: require explicit acceptance of insecure OAuth trust

**Change:** Reject non-loopback HTTP values for `server.resource`, external OAuth issuer/JWKS, and built-in OAuth issuer unless a narrowly named development/trusted-network override is enabled. Keep exact loopback HTTP support for local Codex and test workflows. Reject URL userinfo and fragments at the same boundary.

**Justification:** Authentication trust should fail closed by default. An explicit override preserves legitimate private-network deployments while making the risk reviewable in configuration and tests.

### Priority 0: add service-request admission control

**Change:** Add configurable global, per-subject, and optionally per-service in-flight limits around `executeServiceRequest`. Acquire only after authentication and service authorization, but before downstream I/O; release in `finally`. Return a stable structured `busy` or `capacity_exceeded` result and prove rejected requests do not contact the downstream. Keep the existing scanner pool limits because they protect a different resource.

**Justification:** This closes the largest availability gap without reintroducing MCP transport state. Per-service limits also prevent one slow downstream from consuming all gateway capacity.

### Priority 0: harden the audit boundary

**Change:** Apply central value sanitization at the audit sink, including opaque-prefix and credential-pattern handling for caller-controlled `reason`. Define an operator-visible durability policy: at minimum expose audit-write degradation in readiness; optionally support `audit.required: true` to reject new privileged operations after durable audit failure. Avoid synchronous directory creation and append on every event; use a serialized writer with a bounded queue or a deliberately synchronous open file descriptor, with explicit overload behavior. Document external rotation and disk monitoring.

**Justification:** Audit correctness is cross-cutting and cannot safely depend on every producer. The current combination of event-loop blocking and fail-open durability gives operators neither strong availability nor strong audit guarantees.

### Priority 1: use collision-resistant correlation IDs

**Change:** Generate all public request IDs through one helper using `randomUUID()` (optionally retaining a time prefix for readability). Use it for allowed and denied requests, logs, audits, and response-resource URIs.

**Justification:** This is a small, isolated fix that restores reliable correlation under normal concurrency.

### Priority 1: create a runtime composition root

**Change:** Introduce a `GatewayRuntime`/`Application` object that owns config, logger, audit sink, token broker, denial store, OAuth state/services, scanner pool, maintenance tasks, and downstream limiter. Construct it once in startup, pass narrow dependencies to handlers, and give it an idempotent async `close()` used by server close and `SIGTERM`/`SIGINT` handling.

Do this incrementally: first wrap existing constructors and getters without rewriting their internals. Split `builtinOAuth.ts` and `gateway.ts` only as pieces naturally move behind the runtime interfaces.

**Justification:** The present global registries are acceptable today, but the next meaningful feature will make lifecycle ambiguity more expensive. Central ownership improves test isolation and graceful shutdown without adding a framework.

### Priority 1: unify MCP contracts before adding more tools

**Change:** Define each tool once in a small registry containing name, scope, annotations, runtime validator, handler, and output contract. Generate JSON Schema from the runtime schema where practical, or at least validate arguments with the same schema used to produce the descriptor. Add a contract test that rejects unknown input fields and validates representative success/error outputs against advertised schemas.

**Justification:** Five tools do not justify a large abstraction. They do justify eliminating the highest-risk duplication before a sixth or seventh tool multiplies it.

### Priority 2: make the single-instance topology explicit

**Change:** State prominently in deployment documentation that gateway references are instance-local and replicas must remain at one. If horizontal availability ever becomes a real requirement, design a shared capability store with atomic TTL/capacity operations and subject/service binding; do not approximate it with sticky sessions alone.

**Justification:** Documentation is the right solution for the current target. Shared state is a separate product milestone, not an incidental refactor.

### Priority 2: tighten small public contract inconsistencies

**Change:** Distinguish request-body and response-body size error codes, derive MCP server version from one build/package source, and fully specify nested output schemas that clients rely on.

**Justification:** Stable, precise contracts reduce client-specific surprises and make compatibility testing meaningful. These changes should be versioned deliberately if existing clients already consume the current codes.

## What I Would Not Change Yet

### Do not change yet: the generic five-tool surface

The small surface—list, reference issuance, policy description, request, and denial explanation—is cohesive. Adding service-specific tools or profile packs would expand maintenance and security review cost without evidence that the generic gateway has reached its limit.

### Do not change yet: Node's built-in HTTP server

Routing is small and explicit. Express, Fastify, or NestJS would not solve the current workload, lifecycle, or audit issues; they would introduce another abstraction and dependency boundary.

### Do not change yet: in-memory references

For a single self-hosted process, restart revocation is simple and defensible. A database or Redis should arrive only with a concrete requirement for multi-replica continuity, explicit revocation, or durable capabilities.

### Do not change yet: the regex policy model

Administrator-authored method/host/path rules are understandable, default-deny, ordered, and explainable. A policy language or engine would add considerable complexity. Add safer authoring diagnostics only when real configurations show recurring mistakes.

### Do not change yet: response scanners as defense in depth

Do not chase arbitrary encodings by adding an endless decoder catalog. The documented invertible-transformation limitation cannot be solved by pattern matching. High-assurance use cases should instead constrain credential injection locations and response egress, or use purpose-built adapters as a separate product mode.

### Do not change yet: built-in OAuth into enterprise IAM

The built-in flow is appropriately positioned as private, single-admin OAuth and has substantial PKCE, refresh rotation/replay, rate, and metadata protections. Keep that scope. Multi-user administration, MFA, recovery, federation, and mature abuse controls belong in an external identity provider.

### Do not change yet: large modules solely because they are large

`builtinOAuth.ts`, `config.ts`, and `gateway.ts` are hotspots, but they still have cohesive responsibilities and strong tests. Split them when a composition root creates natural seams or when a new feature would otherwise add a second reason to change the same file. A line-count refactor alone would create churn without reducing risk.

## Overall Opinion

SecretSauce is better architected than most early credential gateways. Its strongest quality is that it treats the model and downstream response as untrusted while keeping the decisive controls server-side. The design is small, inspectable, extensively tested, and unusually candid about residual risk.

I would approve it for its stated single-operator/small-environment use case when deployed as one instance behind HTTPS, with narrowly enumerated services and routes, durable storage monitoring, and explicit acceptance of the downstream-transformation limitation.

I would not yet market or operate it as a broadly exposed multi-tenant control plane. The next milestone should be operational hardening—authenticated admission control, OAuth trust fail-closed defaults, audit integrity/readiness, collision-resistant correlation, and owned runtime lifecycle—not a feature expansion or framework migration.

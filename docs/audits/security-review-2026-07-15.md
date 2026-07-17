# Security Review Report

## Metadata

- **Project/repository:** `agent-credential-gateway-mcp` (`devops-mcp`)
- **Git SHA:** `b2ae9d925c2aed495c08a36967abd77f40882a56`
- **Review date/time:** `2026-07-15T03:40:07Z`
- **Reviewer role:** senior application security reviewer
- **Scope reviewed:** all TypeScript source under `src/`; security-relevant tests under `test/`; `package.json`, `package-lock.json`, `Dockerfile`, `docker-compose.example.yaml`, `.github/workflows/ci.yml`, `README.md`, and security/configuration documentation under `docs/`
- **Commands run:** repository/file inventory with `rg`, `find`, and `wc`; targeted source inspection with `sed`, `nl`, and `rg`; Git metadata commands; `npm ls --omit=dev --depth=1`; `git diff --check`; a loopback-only Node HTTP authority-header validation; and the full build/test commands listed in the Appendix
- **Assumptions and limitations:** static white-box review plus focused local validation; no production deployment, reverse proxy, identity provider, downstream service, or real credential was tested. The npm advisory query was not authorized because it would disclose private dependency metadata to an external service, so current dependency advisories were not verified.

## Executive Summary

The gateway has a thoughtful security design and unusually good coverage for credential isolation: authentication, service authorization, URL checks, policy evaluation, token binding, response secret scanning, cookie rejection, redirect behavior, TLS verification, and sanitized logging are all implemented and tested. No plausible live credential or opaque production token was found in tracked application/configuration files; the private key in `test/gateway.test.ts` is a local self-signed TLS fixture, and the Compose bearer value is explicitly a replace-me development placeholder.

Six actionable issues remain: two High and four Medium. The most important is that URL destination validation does not reserve the HTTP `Host` header. An authorized caller can validate an allowed URL while making Node send a different downstream authority, potentially routing substituted credentials to an unapproved virtual host. Separately, network-facing MCP and built-in OAuth endpoints buffer request bodies before authentication and without a size limit; built-in login also performs synchronous password hashing without a concurrency boundary. These paths allow an unauthenticated availability attack.

The next priorities are to reject/overwrite caller-controlled authority and hop-by-hop headers, enforce streaming inbound limits before JSON/form parsing, and stop downstream response reads at `max_response_body` instead of truncating only after full buffering. Bounded token/audit/denial state, login throttling, and rejection of OAuth tokens without a stable principal identity should follow.

## Scope and Methodology

The review mapped the public HTTP routes, MCP tools, authentication modes, destination/policy evaluation, token lifecycle, downstream HTTP transport, response scanning, audit/logging behavior, deployment artifacts, CI, and direct production dependencies. Findings were traced through actual functions and tests. Exploitability was assessed from a remote attacker's perspective without assuming source access.

Generated/untracked `dist/` output was not treated as authoritative; the reviewed source is `src/`. No live identity provider or configured downstream was available. Dependency versions installed locally were inventoried, but current advisories could not be queried under the review's egress constraints.

## Threat Model

- **Exposed interfaces:** unauthenticated `/health`; OAuth discovery/JWKS; built-in `/oauth/authorize` and `/oauth/token`; authenticated Streamable HTTP MCP endpoint; five MCP tools; configured downstream HTTP(S) destinations
- **Sensitive assets:** configured downstream credentials, built-in OAuth signing key and admin password hash, OAuth/bearer access, subject/service ACLs, opaque `gref_...` and `sec_...` capabilities, downstream data, audit records, and internal network reachability
- **Trust boundaries:** unauthenticated network to gateway; OAuth issuer to gateway; authenticated subject to service ACL; model/tool input to privileged gateway; gateway to configured downstream; downstream response to model-visible output; process memory/filesystem to logs and audit storage; build pipeline to published container
- **Likely attacker profiles:** unauthenticated internet client, authenticated but malicious/compromised MCP subject, prompt-injected model acting with a valid subject, malicious or compromised downstream, and supply-chain actor

## Findings Summary

| ID | Severity | CVSS | Confidence | Title | Status |
|----|----------|------|------------|-------|--------|
| SEC-001 | High | 7.1 | Confirmed | Caller-controlled `Host` bypasses the validated downstream authority | Open |
| SEC-002 | High | 7.5 | Confirmed | Pre-authentication request processing permits memory and CPU exhaustion | Open |
| SEC-003 | Medium | 6.5 | Confirmed | Response size limit is applied only after the full downstream body is buffered | Open |
| SEC-004 | Medium | 6.5 | Confirmed | Security state and audit collections grow without bounds | Open |
| SEC-005 | Medium | 6.5 | Confirmed | Built-in OAuth login has no guessing or abuse controls | Open |
| SEC-006 | Medium | 5.9 | High | External OAuth tokens without identity claims collapse to one `unknown` subject | Needs validation |

## Detailed Findings

### SEC-001: Caller-controlled `Host` bypasses the validated downstream authority

- **Severity:** High
- **CVSS v3.1:** 7.1 `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/gateway.ts:110-128`, `src/gateway.ts:243-281`, `src/gateway.ts:303-317`, `src/urlValidation.ts:18-31`, `src/urlValidation.ts:73-92`

#### Evidence

`executeServiceRequest` validates `target.url`, evaluates policy, and then substitutes credential tokens. `buildDownstreamRequest` copies all caller headers except `Transfer-Encoding` and `Content-Length`. `sendDownstreamRequest` passes those headers directly to Node's `http.request`/`https.request` while connecting to the separately validated URL.

The review's loopback-only validation used that same Node API with URL `http://127.0.0.1:<ephemeral>/api` and `Host: unapproved.example.org`; the receiver observed:

```json
{"received_host":"unapproved.example.org"}
```

Therefore, URL host validation does not guarantee the downstream HTTP authority. The audit event also records `target.url.hostname`, not the effective `Host`, so it can misleadingly report the approved authority.

#### Preconditions

The attacker needs a valid subject with `gateway.request` and access to a service/policy-allowed route. Material confidentiality or integrity impact requires the approved destination to use name-based virtual hosting, a reverse proxy, or an upstream that trusts `Host`/forwarding headers for routing. No victim interaction is required.

#### Exploit Scenario

An authorized caller obtains a service-bound `gref_...`, requests an allowed URL, includes the token in its normal credential header, and supplies `Host: unapproved.example.org`. The gateway approves the URL and policy, substitutes the real credential, connects to the approved IP/hostname, but sends the unapproved HTTP authority. A shared reverse proxy can route the request and credential to a different virtual host. This bypasses the documented guarantee that credentials are not forwarded across host boundaries.

#### Safe PoC / Validation

**Environment:** local test only. **Preconditions:** a loopback HTTP fixture that records `request.headers.host`, a test-only credential, and an allow rule. Invoke `executeServiceRequest` with an allowed relative path, `Host: unapproved.example.org`, and the test token. **Expected current result:** the fixture sees the unapproved host and the substituted test credential. **Cleanup:** close the fixture; no persistent data is created. This is non-destructive because all traffic and credentials are synthetic and loopback-only.

#### Impact

Configured credentials can reach an authority that was not approved by destination or policy validation. The same primitive can access a more privileged co-hosted application. Availability impact was not scored because routing behavior is deployment-specific.

#### CVSS Rationale

The attack is remote and requires a low-privilege authenticated gateway subject. Complexity is High because meaningful impact depends on virtual-host/reverse-proxy routing at an approved destination. Confidentiality and integrity can both be High when a substituted credential is disclosed to or accepted by the unintended authority. Scope is kept Unchanged because the gateway explicitly brokers authority to the downstream system.

#### Remediation

- Reject caller-supplied `Host`, `:authority`, `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and hop-by-hop headers unless a narrowly documented use case explicitly allows one.
- Set the outbound `Host` from the validated URL after token substitution; never let the model/tool input select it.
- Audit the effective authority actually passed to Node.
- Consider a central outbound-header allow/deny policy so future transport changes cannot reintroduce the bypass.

#### Verification

Add positive coverage showing ordinary custom/API headers still work and negative coverage showing every reserved authority/hop-by-hop header is rejected or overwritten before substitution/I/O. Exercise both HTTP and HTTPS virtual-host fixtures and assert no credential reaches the unapproved virtual host.

### SEC-002: Pre-authentication request processing permits memory and CPU exhaustion

- **Severity:** High
- **CVSS v3.1:** 7.5 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/server.ts:38-44`, `src/mcp/server.ts:108-114`, `src/builtinOAuth.ts:130-152`, `src/builtinOAuth.ts:193-205`, `src/builtinOAuth.ts:350-359`, `src/builtinOAuth.ts:382-387`

#### Evidence

For MCP POSTs, `readJsonBody` accumulates every request chunk and concatenates it before `authenticateRequest` runs. Both built-in OAuth POST endpoints use `readFormBody`, which has the same unbounded buffering. Neither path applies `config.limits.maxRequestBodyBytes`, validates `Content-Length`, or stops reading after a cap.

After an authorization form passes public request validation, `verifyPassword` calls `pbkdf2Sync`. That intentionally expensive calculation blocks the single Node event loop. There is no per-source/global concurrency or request-rate boundary around it.

#### Preconditions

The MCP body exhaustion path needs no credentials. The OAuth variants require `builtin_oauth` to be enabled; the CPU path also requires a syntactically valid authorization request for an allowed public client, but no valid username or password.

#### Exploit Scenario

An unauthenticated client opens concurrent POSTs and streams large MCP JSON or OAuth form bodies, causing heap growth before any authentication decision. With built-in OAuth enabled, repeated valid-looking login attempts additionally serialize synchronous PBKDF2 work on the event loop, delaying health checks, token exchange, and authenticated MCP traffic.

#### Safe PoC / Validation

**Environment:** local unit/integration test. **Preconditions:** configure a very small inbound cap such as 1 KiB. Stream 1 KiB plus one byte without allocating a large payload. **Expected current result:** the handler continues reading; after remediation it should stop and return `413`. For CPU, stub/measure the password verifier and assert concurrent invalid logins are rejected by a limiter without running unbounded KDF jobs. **Cleanup:** close local connections. The tests prove control flow with tiny data and do not exhaust resources.

#### Impact

A remote unauthenticated actor can degrade or terminate the gateway through memory pressure, event-loop blocking, or both, interrupting all MCP credential operations.

#### CVSS Rationale

The attack is remotely reachable, needs no credentials or user interaction, and is reliable. The realistic impact is High availability loss; no confidentiality or integrity impact was demonstrated.

#### Remediation

- Introduce a distinct maximum inbound HTTP/MCP/OAuth body size and enforce it while streaming, before concatenation and before authentication-dependent parsing.
- Reject excessive declared `Content-Length`, but still count actual bytes to cover chunked requests and dishonest lengths.
- Replace `pbkdf2Sync` in request handling with asynchronous `pbkdf2` or a bounded worker pool.
- Add global and per-source concurrency/rate limits for unauthenticated OAuth and MCP parsing, with conservative request timeouts.
- Return stable `413`/`429` responses without logging request bodies or credentials.

#### Verification

Add positive tests at/under the limit and negative tests one byte over it for MCP JSON, authorize forms, and token forms, including chunked bodies. Prove oversized requests are aborted before JSON/form parsing and before authentication/KDF work. Add a concurrency test that keeps health responses responsive during invalid login load.

### SEC-003: Response size limit is applied only after the full downstream body is buffered

- **Severity:** Medium
- **CVSS v3.1:** 6.5 `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/gateway.ts:148-158`, `src/gateway.ts:303-328`, `src/gateway.ts:374-383`, `test/gateway.test.ts:194-223`

#### Evidence

`sendDownstreamRequest` appends every response chunk to an array and resolves only after `end`, using `Buffer.concat(chunks)`. `limitedResponseText` then calls `response.arrayBuffer()` and only afterward truncates to `maxResponseBodyBytes`. The existing test verifies the returned body is truncated but does not prove the network read or resident allocation is bounded.

The configured maximum therefore limits only returned/scanned bytes, not downloaded or buffered bytes.

#### Preconditions

The attacker needs an authenticated subject allowed to call an endpoint that returns a large body, or control/compromise of an allowed downstream. The downstream must send data quickly enough before the configured timeout.

#### Exploit Scenario

An authorized caller repeatedly invokes an allowed bulk/export endpoint. A body far larger than `max_response_body` is fully accumulated in process memory and copied again through `Buffer.concat`/`arrayBuffer`, causing heap pressure or process termination even though the tool result is marked truncated.

#### Safe PoC / Validation

**Environment:** local test. **Preconditions:** a loopback downstream emits `limit + 1` small chunks and records socket closure. **Expected current result:** the fixture sends the entire response; after remediation the gateway aborts immediately after the cap. **Cleanup:** close both local servers. The payload can be only a few KiB, so validation is non-destructive.

#### Impact

An authenticated caller or malicious allowed downstream can cause gateway-wide availability loss. No secret disclosure is required.

#### CVSS Rationale

The path is network reachable but requires Low privileges and a permitted downstream route. Exploitation is reliable once those conditions hold. Availability impact can be High; confidentiality and integrity are unaffected.

#### Remediation

Count bytes in the downstream `data` handler, retain at most the configured cap, and destroy/abort the downstream request as soon as the cap is exceeded. Avoid constructing an intermediate `Response`/`arrayBuffer` for already buffered data. Decide explicitly whether oversize responses should be safely truncated or fail closed; either behavior must stop the network read at the bound.

#### Verification

Test exact-limit, limit-plus-one, chunked, misleading/missing `Content-Length`, compressed (if later supported), and slow streaming responses. Assert the downstream socket closes at the cap and memory-held bytes do not exceed a small constant above it.

### SEC-004: Security state and audit collections grow without bounds

- **Severity:** Medium
- **CVSS v3.1:** 6.5 `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/audit.ts:68-75`, `src/tokens.ts:70-77`, `src/tokens.ts:84-138`, `src/denials.ts:13-32`, `src/builtinOAuth.ts:23`, `src/builtinOAuth.ts:166-175`, `src/mcp/server.ts:17`, `src/mcp/server.ts:82-92`

#### Evidence

Every audit event is retained forever in the process-global `auditEvents` array, even when file-backed audit is enabled. `TokenBroker` stores issued tokens and its own duplicate audit-event list; expired configured tokens are generally removed only when presented or encountered during a response scan, not by periodic sweeping. Denials are kept indefinitely in a global map. Authorization codes and MCP transports have lifecycle deletion paths, but expired/unclosed entries are not periodically reaped or globally capped.

An authenticated caller can generate audit entries with every tool call, token records with repeated `get_gateway_service_references`, and denial records with policy-denied requests. TTL expiry does not by itself release most of this memory.

#### Preconditions

The attacker needs any valid gateway identity and the scope/tool access for the chosen operation. No downstream compromise or user interaction is needed.

#### Exploit Scenario

A low-rate authenticated client repeatedly invokes a cheap read tool or requests tokens over hours. Resident arrays/maps grow monotonically until garbage collection overhead or heap exhaustion degrades the whole gateway. Token TTLs create a false expectation of bounded state because expiration is largely lazy.

#### Safe PoC / Validation

**Environment:** local unit test. **Preconditions:** expose test-only store statistics and configure small capacities. **Expected current result:** repeated operations exceed those capacities; after remediation old/expired records are evicted or the operation returns a bounded `429`/capacity error. **Cleanup:** discard the in-memory test instance. Small capacities make the test non-destructive.

#### Impact

An authenticated caller can cause durable memory growth and eventual gateway availability loss. Audit continuity can also become unreliable if the process crashes.

#### CVSS Rationale

The attack is remote, simple, and requires Low privileges. Availability can be High after sustained requests. No confidentiality or integrity impact was demonstrated.

#### Remediation

- Do not retain production audit history in an unbounded array; make the in-memory sink test-only or a fixed-size ring buffer.
- Add capacity limits, periodic expiry sweeps, and per-subject quotas for configured and response-secret tokens.
- Give denial context a short TTL and bounded LRU capacity.
- Periodically reap expired OAuth codes and stale transports; cap both maps.
- Avoid duplicate audit retention in the global sink and each broker.
- Emit sanitized capacity/eviction metrics for operations.

#### Verification

Add positive tests for normal reuse/TTL behavior and negative tests proving per-subject/global caps, lazy plus periodic expiry, bounded audit/denial retention, and deterministic behavior at capacity.

### SEC-005: Built-in OAuth login has no guessing or abuse controls

- **Severity:** Medium
- **CVSS v3.1:** 6.5 `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/builtinOAuth.ts:130-164`, `src/builtinOAuth.ts:251-300`, `src/builtinOAuth.ts:350-359`

#### Evidence

Every syntactically valid authorize POST reaches the single admin username/password comparison. There is no per-source, per-username, or global attempt counter; no backoff; no temporary lock; and no `429` response. The PBKDF2 hash is appropriately salted and expensive, but password hashing alone does not bound online attempts.

#### Preconditions

`builtin_oauth` must be exposed. The attacker needs a valid allowed client identifier and authorization parameters; these are public-client values discoverable from normal OAuth integration behavior. Success still depends on guessing/reusing the admin credential.

#### Exploit Scenario

An attacker submits sustained password guesses for the sole admin account. A reused or weak password eventually yields an authorization code and access token with requested gateway scopes. The same attempt stream also contributes to SEC-002's event-loop exhaustion.

#### Safe PoC / Validation

**Environment:** local test. **Preconditions:** test admin hash and allowed client metadata stub. Submit a small number of invalid passwords. **Expected current result:** every attempt performs verification and returns `401`; after remediation later attempts return `429` before KDF work. **Cleanup:** advance/reset the test clock and limiter. This uses synthetic credentials and a few attempts only.

#### Impact

Successful guessing exposes the services available to the built-in admin and permits policy-authorized downstream operations. Existing service ACLs and request policies still limit integrity impact, which is why the rating is not higher.

#### CVSS Rationale

The attack is remote and unauthenticated, but Attack Complexity is High because account compromise depends on password quality/reuse. Confidentiality impact can be High; integrity is Limited by configured service policy; availability is scored separately in SEC-002.

#### Remediation

Apply bounded per-source, per-account, and global attempt limits before password hashing, with exponential backoff and short temporary lockouts. Keep error responses indistinguishable. Record only sanitized counters/outcomes. Document a strong unique admin password and consider delegating internet-facing deployments to an external IdP with MFA.

#### Verification

Test successful login below thresholds, invalid username and invalid password paths, reset windows, global flood protection, and that throttled attempts do not invoke the password verifier. Confirm logs contain no usernames/passwords beyond the already intended subject fields on successful authenticated operations.

### SEC-006: External OAuth tokens without identity claims collapse to one `unknown` subject

- **Severity:** Medium
- **CVSS v3.1:** 5.9 `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N`
- **Confidence:** High
- **Status:** Needs validation
- **Affected components:** `src/auth.ts:61-91`, `src/auth.ts:172-176`, `src/registry.ts:79-96`, `src/tokens.ts:141-155`, `src/tokens.ts:196-205`

#### Evidence

External OAuth signature, issuer, audience, expiration, and scope verification are present. After verification, `subjectFromPayload` uses `sub`, then a non-universal `client_id` claim, and otherwise returns the constant string `unknown` instead of rejecting the token.

Service ACLs and both opaque-token classes use only `auth.subject` as their principal boundary. Consequently, all valid identity-less tokens from the configured issuer share the same authorization principal.

#### Preconditions

The configured IdP must issue an otherwise valid access token without `sub` and `client_id` (for example, one using a different client-identity claim), and an operator must grant `unknown` access or rely on opaque-token subject binding between such clients. Cross-client token abuse additionally requires an opaque token to be disclosed between clients. Runtime IdP claims were not available, so deployment exploitability needs validation.

#### Exploit Scenario

Two unrelated OAuth clients receive valid tokens that both map to `unknown`. If the service ACL permits that subject, both clients receive identical service authorization. If one client's `gref_...` or `sec_...` leaks to the other, the subject check accepts it, defeating the intended cross-subject isolation.

#### Safe PoC / Validation

**Environment:** local unit test. **Preconditions:** sign two local JWTs with the test issuer/key, correct audience/scope, and no `sub`/`client_id`. **Expected current result:** both authenticate as `unknown`; after remediation both are rejected, or map to distinct explicitly configured claims. **Cleanup:** discard test keys/tokens. This is non-destructive and entirely local.

#### Impact

In affected IdP configurations, service ACL and opaque-token isolation can collapse across clients, causing unauthorized service visibility/use or reuse of a leaked capability.

#### CVSS Rationale

The attacker already needs a valid Low-privilege OAuth token. Complexity is High because the IdP claim shape and ACL configuration must align, and cross-client capability reuse needs token disclosure. Confidentiality can be High; integrity is Limited by service policy.

#### Remediation

Reject access tokens that lack a non-empty stable principal identifier. Make the identity claim(s) explicit configuration (for example, `sub` by default, optionally a documented client claim) and namespace the derived principal by issuer and identity type to prevent collisions. Never use a shared fallback principal.

#### Verification

Add positive tests for accepted user and client identities and negative tests for missing, empty, non-string, and unsupported identity claims. Prove two distinct configured identities cannot use each other's `gref_...` or `sec_...` values.

## Exploit Chains

### CHAIN-001: Validated URL plus authority override leaks a substituted credential

SEC-001 is itself a multi-step chain: authenticate as a service-authorized subject, obtain a destination-bound token, select a policy-allowed URL, override `Host`, then let the gateway substitute the credential before Node sends the request. The destination/token/policy controls each operate as designed on the URL, but the final transport authority differs. Combined severity remains **High (CVSS 7.1)** rather than adding a duplicate finding.

### CHAIN-002: Unbounded pre-authentication input plus synchronous KDF blocks the service

With built-in OAuth enabled, SEC-002's unbounded form reads can create heap pressure while valid-looking attempts trigger synchronous PBKDF2. SEC-005's lack of throttling permits sustained concurrency. The combined outcome is a reliable unauthenticated availability attack, already represented by **SEC-002 High (CVSS 7.5)**.

## Hardening Recommendations

- Enforce DNS/IP policy at connection time if hostname destinations must exclude loopback, link-local, cloud metadata, or other private ranges. Pin resolution for the request to reduce DNS-rebinding ambiguity.
- Require suffix matchers to start with `.` or implement explicit DNS-label boundary matching; `endsWith` alone accepts risky operator inputs such as a suffix without a leading dot (`src/urlValidation.ts:40-44`).
- Define one canonicalization contract for encoded paths and verify it against supported downstream servers. Encoded slashes/double-decoding can otherwise produce gateway/downstream policy disagreements.
- Require HTTPS external OAuth issuer/JWKS/resource URLs outside explicit local-development mode. Require `server.resource` for remote deployment instead of deriving public metadata from an untrusted request `Host` (`src/auth.ts:100-126`).
- Bound client-metadata response size and redirect behavior in built-in OAuth. Fetch only the configured allowed client URL/origin and revalidate every redirect target (`src/builtinOAuth.ts:291-300`).
- Add `Cache-Control: no-store`, a restrictive Content Security Policy (`frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, and an appropriate `Referrer-Policy` to built-in OAuth HTML/token responses.
- Validate a minimum PBKDF2 iteration count and cap the configured count to prevent accidental weak hashes or pathological login CPU costs.
- Decide whether audit write failure should fail sensitive operations or trigger health degradation. Current behavior logs the error and continues (`src/audit.ts:70-81`). Also create audit files with explicit restrictive permissions.
- Pin GitHub Actions and the production base image by immutable digest for stronger build provenance. Keep automated dependency/advisory scanning in trusted CI because it could not be verified in this review.

## Positive Security Observations

- Authentication verifies bearer tokens with constant-time equality and OAuth JWTs with signature, issuer, audience, expiration, and per-tool scope checks (`src/auth.ts`).
- Service ACL checks, destination URL validation, and policy evaluation occur before opaque-token substitution and downstream I/O (`src/gateway.ts:53-128`).
- Configured tokens use 192 bits of randomness, are looked up by SHA-256 hash, and are bound to subject, service, destination, and credential. Response-secret tokens are subject/service-bound and indexed with keyed HMAC (`src/tokens.ts`).
- Redirects are not followed by the downstream Node transport, preventing automatic cross-host credential forwarding.
- Caller cookies and transfer encoding are rejected; response cookies are removed; `Content-Length` is recomputed after substitution/tokenization (`src/gateway.ts`, `src/cookies.ts`).
- TLS verification defaults on, `tls.verify: false` is explicit, and actual self-signed HTTPS behavior has positive/negative tests.
- Response bodies and headers are scanned server-side. Exact configured credentials are tokenized even when Secretlint rules are disabled, invalid opaque-prefix candidates are wrapped, and scanner work is isolated in a bounded worker pool that fails closed (`src/responseTokenizer.ts`, `src/secretScannerPool.ts`).
- Logging centrally redacts sensitive field names and omits sensitive header names/body content. Audit structures intentionally store internal token IDs, not raw opaque values or credentials (`src/logger.ts`, `src/audit.ts`).
- Built-in OAuth uses authorization code plus S256 PKCE, exact resource binding, allowlisted client metadata, one-time codes, short code TTL, signed JWTs, and a stable external signing-key file.
- The container runs as the unprivileged `node` user. CI gates image publication on install, TypeScript build, and the full test suite.
- Tests cover many negative security boundaries: invalid/wrong-scope tokens, unauthorized services, invalid destinations, denied policy, redirects, body limits at the result layer, request framing, cookies, forged opaque prefixes, scanner failure/overload, TLS verification, audit/log redaction, and OAuth resource/scope/client/PKCE checks.

## Assumptions and Limitations

- Production reverse proxy behavior, network segmentation, DNS, TLS termination, IdP claim shapes, service ACLs, and downstream routing determine the full impact of SEC-001 and SEC-006.
- No dynamic fuzzing, sustained load testing, container runtime inspection, or third-party service testing was performed.
- The local production dependency tree was inventoried. An `npm audit --omit=dev --json` attempt could not be authorized because transmitting private dependency metadata externally exceeded the permitted review boundary; current advisory status is therefore unknown.
- The review did not assess secrets or configuration injected only at deployment time.
- Secretlint is a useful leak-reduction control, not proof that arbitrary downstream data contains no secret; exact configured-secret tokenization is the stronger deterministic control.

## Appendix

### Key Commands

```text
git rev-parse HEAD
date -u +"%Y-%m-%dT%H:%M:%SZ"
git status --short
rg --files
rg -n <security-sensitive patterns> src test docs
npm ls --omit=dev --depth=1
npm run build
npm test
git diff --check
```

### Validation Results

- `npm run build`: passed.
- Initial sandboxed `npm test`: 90 tests passed and 41 listener-dependent tests failed only with `listen EPERM` on `127.0.0.1`.
- Unchanged `npm test` rerun with loopback permission: **21 test files passed; 131 tests passed**.
- `git diff --check`: passed.
- Loopback-only authority validation: the receiving server observed caller-supplied `Host: unapproved.example.org` while the connection URL used `127.0.0.1`, confirming SEC-001's transport behavior.

### Dependency Inventory Note

The installed direct production packages at review time were MCP SDK 1.29.0, Secretlint packages 13.0.2, JOSE 6.2.3, YAML 2.9.0, and Zod 4.4.3. Version inventory is not an advisory verdict.

### Recommended Remediation Order

1. SEC-001: reserve/overwrite outbound authority and hop-by-hop headers.
2. SEC-002: enforce streaming pre-authentication body limits and move KDF work off the event loop.
3. SEC-003: abort downstream reads at the response cap.
4. SEC-004 and SEC-005: bound resident state and authentication attempts.
5. SEC-006: require an explicit stable OAuth principal.

# Security Review Report

## Metadata

- **Project/repository:** SecretSauce (MCP) (`devops-mcp`)
- **Git SHA:** `2539adcc3a253aa6ae676ebbe1ad9f950259b635`
- **Review date/time:** `2026-07-19T16:13:50Z`
- **Reviewer role:** senior application security reviewer
- **Scope reviewed:** all TypeScript source under `src/`; security-relevant tests under `test/`; runtime, OAuth, MCP, configuration, container, Compose, CI, dependency manifests, and public documentation
- **Commands run:** repository inventory and targeted inspection with `rg`, `sed`, and `nl`; Git metadata/status; `npm ls --omit=dev --depth=1`; `npm audit --omit=dev --json`; focused Vitest reproductions; Node URL normalization probe; `npm run build`; `npm test`; and `git diff --check`
- **Assumptions and limitations:** source-assisted review and synthetic local validation only. No production reverse proxy, identity provider, configured downstream, DNS environment, or real secret was tested. Conditional downstream behaviors are identified explicitly.

## Executive Summary

SecretSauce has a strong security foundation, but this revision is **not ready for an unqualified public-internet claim that credentials cannot be exfiltrated**. Six findings remain: one High, four Medium, and one Low, plus one High exploit chain. The most direct credential-boundary defect is a hostname suffix comparison that can allow an attacker-controlled sibling domain. The additional High-risk chain arises because callers can place a credential reference in arbitrary request fields while response filtering cannot recognize undeclared Base64, percent, hex, split, or application-specific transformations. If an allowed downstream reflects or transforms input, an authenticated caller can recover the raw credential and use it outside gateway policy.

The public OAuth surface also needs attention. Built-in OAuth retrieves client metadata with automatic redirects and an unbounded JSON body, without validating the connected IP or final URL. When an entire origin is allowlisted, an open redirect or attacker-controlled path on that origin can turn this into OAuth code theft and blind SSRF. Built-in OAuth should remain a private, single-administrator option until this is fixed; use a hardened external OAuth provider for general public exposure.

Recommended release priority:

1. Fix `SEC-001` before exposing any service configured with suffix host matching.
2. Address `CHAIN-001` structurally by constraining credential injection and response egress; do not rely on secret scanning as a complete isolation boundary.
3. Fix the encoded-path policy mismatch and OAuth client metadata retrieval before public deployment.
4. Add per-subject MCP capacity controls and OAuth cache-prevention headers.

With exact host matchers, tightly reviewed non-reflective downstream routes, external OAuth, and upstream rate/resource controls, the current service can be deployed under a narrower, documented risk acceptance while fixes are developed.

## Scope and Methodology

The review traced every publicly reachable route through authentication, authorization, destination validation, policy evaluation, credential substitution, downstream HTTP transport, response scanning/tokenization, logging, and audit storage. It separately examined built-in and external OAuth, opaque token binding, MCP transport lifecycle, configuration parsing, container/CI defaults, and production dependencies.

Exploitability was assessed for an internet attacker without filesystem or server-side access. Three focused tests used only synthetic values and no outbound traffic; they confirmed the hostname, encoded-path, and transformed-response behaviors. Those temporary test files were removed after validation. The prior 2026-07-15 audit and remediation record were reviewed to avoid re-reporting fixed issues.

## Threat Model

- **Exposed interfaces:** unauthenticated `/health`, brand assets, protected-resource metadata, OAuth/OIDC discovery and JWKS, built-in `/oauth/authorize` and `/oauth/token`, authenticated Streamable HTTP MCP endpoint, and its five MCP tools
- **Sensitive assets:** configured downstream credentials, OAuth signing material and password hash, access and refresh grants, subject/service ACLs, opaque `gref_...` and `sec_...` capabilities, downstream data, network authority, and audit records
- **Trust boundaries:** internet to gateway; OAuth client/issuer to gateway; authenticated subject to service ACL; model-controlled tool arguments to privileged request construction; gateway to downstream; untrusted downstream response to model-visible output; runtime state/filesystem to logs and persistence
- **Likely attackers:** unauthenticated internet client, malicious or compromised authenticated subject, prompt-injected model operating under a valid subject, attacker controlling a permitted or lookalike hostname, compromised downstream, and an attacker controlling content or redirects on an allowlisted OAuth client origin

## Public Attack Surface and Security Flow

`/health`, brand assets, OAuth metadata, and built-in OAuth endpoints are intentionally unauthenticated. MCP POST authentication occurs before bounded body reading. For a service request, the intended order is authentication and scope check, service authorization, destination validation, policy evaluation, credential substitution, downstream I/O, then response scanning. This ordering is correctly implemented; the findings concern mismatches inside destination/policy validation, overly flexible token placement, incomplete output recognition, and public endpoint resource/trust controls.

## Findings Summary

| ID | Severity | CVSS | Confidence | Title | Status |
|----|----------|------|------------|-------|--------|
| SEC-001 | High | 8.1 | Confirmed | Suffix host matching accepts attacker-controlled sibling domains | Open |
| SEC-002 | Medium | 5.3 | Confirmed | Invertible response transformations bypass credential scanning | Open |
| SEC-003 | Medium | 6.8 | High | Encoded paths can bypass route policy | Open |
| SEC-004 | Medium | 6.8 | High | OAuth client metadata retrieval follows redirects and lacks SSRF/resource bounds | Open |
| SEC-005 | Medium | 6.5 | Confirmed | One authenticated subject can exhaust global MCP transport capacity | Open |
| SEC-006 | Low | 3.1 | Confirmed | OAuth token responses omit mandatory cache-prevention headers | Open |

## Detailed Findings

### SEC-001: Suffix host matching accepts attacker-controlled sibling domains

- **Severity:** High
- **CVSS v3.1:** 8.1 `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/urlValidation.ts:36-44`, `src/urlValidation.ts:74-78`, `src/config.ts` host-matcher parsing, any destination using `hosts: [{ type: suffix, value: example.org }]`

#### Evidence

`matchesHost` implements suffix authorization as `normalized.endsWith(matcher.value)`. Configuration accepts and normalizes a suffix without requiring a leading dot or enforcing a DNS-label boundary. Consequently, the natural-looking suffix `example.org` authorizes both `api.example.org` and attacker-controlled `attackerexample.org`.

The focused local test directly evaluated the production matcher and confirmed:

```text
matchesHost({ type: "suffix", value: "example.org" }, "attackerexample.org") === true
```

Exact host matching does not have this defect. A suffix configured as `.example.org` avoids the sibling match but excludes the apex and relies on every operator knowing this undocumented security distinction.

#### Preconditions

The deployment uses a bare suffix matcher, permits the requested scheme/port/path, and the attacker has a valid identity with access to the service and a usable gateway credential reference. The attacker must control the sibling hostname. No server-side access or victim interaction is required.

#### Exploit Scenario

The attacker obtains a service-bound `gref_...`, submits an absolute target URL such as `https://attackerexample.org/allowed`, and places the reference in the expected request location. Destination and policy checks accept the sibling hostname, then the gateway substitutes the real credential and sends it to the attacker-controlled server. The attacker can use the recovered credential directly against the real downstream, bypassing gateway route policy.

#### Safe PoC / Validation

Use only the pure matcher with synthetic `example.org` values as shown above. No DNS or outbound request is needed. After remediation, test the apex and a real subdomain as positive cases and `attackerexample.org`, `example.org.attacker.invalid`, trailing-dot, mixed-case, and IDN cases as negative cases.

#### Impact

High confidentiality and integrity impact: configured downstream credentials can be disclosed to an external host, after which the attacker may act with the credential's full native privilege rather than the gateway's restricted policy.

#### CVSS Rationale

The path is remote, requires a low-privilege authenticated gateway subject, and is straightforward in an affected configuration. It needs no victim action. Disclosure and subsequent credential use can both be High. Scope is Unchanged because the gateway intentionally brokers authority to the downstream system.

#### Remediation

Canonicalize a suffix by removing any optional leading dot, then accept only `host === suffix` or `host.endsWith("." + suffix)`. Reject empty, IP-literal, malformed, and public-suffix-only values as appropriate. Prefer exact host matchers by default and make suffix semantics explicit in configuration documentation.

#### Verification

Add positive and negative unit tests for label boundaries, apex behavior, case, trailing dots, IPv4/IPv6, and internationalized names. Add an integration test proving a credential is never substituted or sent when a sibling hostname is supplied.

### SEC-002: Invertible response transformations bypass credential scanning

- **Severity:** Medium
- **CVSS v3.1:** 5.3 `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/substitution.ts:16-35`, `src/responseTokenizer.ts:112-121`, `src/responseTokenizer.ts:139-147`, credential usage metadata and public credential-isolation claims

#### Evidence

Credential references are substituted recursively wherever they appear in caller-controlled headers, query values, or bodies; a credential's declared `usage` is descriptive and is not enforced as an injection boundary. The response tokenizer detects the exact configured secret, its JSON-escaped form, declared whole-body Base64, HTTP Basic credentials, sensitive-name values, and scanner patterns. It cannot generally identify reversible transformations.

A focused test Base64-encoded a synthetic configured secret in an ordinary response without `Content-Transfer-Encoding: base64`. `tokenizeWithTransferEncoding` returned that value unchanged and reported `secretTokenized: false`. Percent encoding, hex, character arrays/splitting, hashes of low-entropy values, compression, encryption with caller-known keys, and application-specific transforms have the same structural problem.

This limitation is acknowledged in `docs/security-notes.md` and the configuration reference, but stronger public wording such as “Agents are never entrusted with raw credentials” can reasonably be read as a universal guarantee.

#### Preconditions

The attacker needs a valid subject, an issued reference, and a policy-allowed downstream operation that reflects or transforms attacker-controlled input. The downstream need not be compromised; diagnostic, echo, template, encoding, request-inspection, webhook-test, or configuration-preview endpoints can supply the primitive.

#### Exploit Scenario

The caller places `gref_...` in a benign field accepted by an allowed endpoint and asks the endpoint to return that field Base64-encoded. The gateway substitutes the raw credential before sending. Because the returned encoding is undeclared, the scanner does not recognize it. The caller decodes the result offline and gains the raw credential.

An exact-reflection endpoint also creates a limited equality oracle for guessed low-entropy secrets: a correct guess is tokenized while an incorrect guess is returned. This is secondary to the direct transformation issue but should be considered when credentials are human-memorable.

#### Safe PoC / Validation

Instantiate the tokenizer with a synthetic credential, encode that value locally, and scan it as a plain-text response with no transfer-encoding header. Expected current result: unchanged encoded body and `secretTokenized === false`. No downstream traffic or real credential is involved.

#### Impact

The individual scanner gap discloses a configured secret when an allowed transformation endpoint exists. Its combined effect is higher because recovering the raw credential removes all gateway destination, method, path, audit, and rate-policy controls; see `CHAIN-001`.

#### CVSS Rationale

The attack is remote and requires Low privileges. Attack Complexity is High because exploitability depends on a suitable policy-allowed downstream behavior. Confidentiality impact is High; integrity is represented in the chain rather than this primitive.

#### Remediation

Do not use scanning as the sole credential-isolation boundary. Bind each credential to configured injection locations and have the gateway inject it there; reject references in all other fields. Deny routes that reflect, transform, debug, export, or introspect requests unless their response egress is structurally constrained. For high-assurance services, use response schemas/allowlists or purpose-built adapters that release only expected fields. Codec-aware scanning can add defense in depth for explicitly declared encodings, but arbitrary reversible transformations cannot be comprehensively enumerated.

Clarify public documentation: the gateway substantially reduces accidental disclosure and blocks recognized secrets, but cannot guarantee non-exfiltration through arbitrary downstream computation.

#### Verification

Add negative tests for references in undeclared credential locations. Maintain regression cases for undeclared Base64, percent, hex, split-character, and nested transformations; those tests should prove structural rejection or egress allowlisting, not merely add an ever-growing decoder list.

### SEC-003: Encoded paths can bypass route policy

- **Severity:** Medium
- **CVSS v3.1:** 6.8 `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Confidence:** High
- **Status:** Open
- **Affected components:** `src/urlValidation.ts:88-108`, `src/policy.ts:38-55`, downstreams that decode percent-encoded path characters before routing

#### Evidence

The gateway normalizes literal `.` and `..` segments, then evaluates policy regexes against the URL object's encoded pathname. It does not canonicalize percent-encoded unreserved characters. Node preserves `/%61dmin` as the pathname, so a deny rule anchored to `^/admin$` does not match. A focused test confirmed that this request falls through to an allow-by-default policy.

Many web frameworks decode `%61` to `a` before routing. In such deployments the gateway evaluates `/%61dmin` while the application handles `/admin`. Double encoding, encoded separators, and backend-specific normalization introduce related ambiguity. Query parameters are also intentionally outside path-policy evaluation.

#### Preconditions

The attacker needs valid service access and a policy containing a path distinction that can be crossed by alternate encoding. Material impact requires the downstream router to interpret the transmitted path differently from the gateway.

#### Exploit Scenario

A policy denies `/admin` but otherwise allows requests. The attacker requests `/%61dmin`; the gateway does not match the deny rule, substitutes credentials, and sends the request. The downstream decodes the path and executes its administrative handler, potentially exposing configuration/secrets or performing privileged actions.

#### Safe PoC / Validation

Evaluate the production URL resolver and policy engine with synthetic configuration: default allow plus deny `^/admin$`, target `https://api.example.org/%61dmin`. Expected current result: allowed. Validate real exploitability only against a disposable local router that documents its decoding behavior.

#### Impact

Policy-denied operations can become reachable with gateway credentials. Confidentiality and integrity can both be High depending on the bypassed route.

#### CVSS Rationale

The path is remote and requires Low privileges. Complexity is High because backend normalization must produce the protected route. No user interaction is needed. Availability was not assumed.

#### Remediation

Define one canonical request-target representation and ensure the bytes evaluated by policy correspond to the bytes sent and the downstream's routing semantics. A conservative approach is to reject ambiguous percent-encoded unreserved characters, separators, backslashes, NULs, and encoded dot segments. Prefer anchored path rules and warn or reject unintentionally unanchored regexes. Treat query authorization as a separate explicit policy dimension where security decisions depend on it.

#### Verification

Test literal and encoded unreserved characters, single/double-encoded dot segments and separators, mixed case escapes, backslashes, duplicate slashes, trailing slashes, and queries against the same router technology used in production. Assert deny rules cannot be bypassed and allow rules cannot be broadened.

### SEC-004: OAuth client metadata retrieval follows redirects and lacks SSRF/resource bounds

- **Severity:** Medium
- **CVSS v3.1:** 6.8 `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`
- **Confidence:** High
- **Status:** Open
- **Affected components:** `src/builtinOAuth.ts:1061-1101`, `src/builtinOAuth.ts:1104-1121`, `src/builtinOAuth.ts:1124-1135`, `auth.builtin_oauth.allowed_clients`

#### Evidence

The authorization endpoint accepts a HTTPS URL as `client_id`, checks it against the allowlist, and fetches it as a Client ID Metadata Document. `fetch` uses its default redirect-following behavior and then calls unbounded `response.json()`. The implementation does not check the final URL, resolved/connected IP address, special-use networks, content type, or response size. Successful documents are not cached. When an allowlist entry is an origin, every path on that origin is accepted.

The current IETF Client ID Metadata Document draft requires authorization servers not to automatically follow redirects, prohibits production fetches to special-use IP addresses, and recommends a bounded response (5 KB is the stated example): [OAuth Client ID Metadata Document draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/).

#### Preconditions

Built-in OAuth is enabled. Exploiting authorization-code theft requires an open redirect or attacker-controlled metadata path on an allowlisted origin, plus a victim who submits valid gateway login credentials and consent. Blind SSRF/resource consumption needs a fetchable allowed client URL that redirects or serves a large/slow body; practical reach depends on allowlist configuration and network controls.

#### Exploit Scenario

An attacker selects an allowed client URL that redirects to attacker-hosted metadata. The followed document repeats the original `client_id` but registers the attacker's redirect URI. The victim sees the genuine gateway login page and authenticates. The gateway redirects the authorization code to the attacker, whose chosen PKCE verifier can exchange it for gateway access and refresh tokens. Separately, redirects can make the gateway contact private/special-use addresses, and repeated large metadata responses consume memory and connections before authentication.

#### Safe PoC / Validation

Use two loopback fixtures in a dedicated integration test: an allowlisted fixture returns `302` to the second fixture, which returns synthetic metadata. Expected current result: metadata is accepted. After remediation, the first redirect must fail without contacting the second fixture. Use a tiny configured size cap to test limit-plus-one behavior without resource exhaustion. Do not probe production internal addresses.

#### Impact

The OAuth chain can grant an unauthenticated attacker a victim's full gateway authorization. Redirect-based SSRF can expose reachability and trigger side effects on internal services; unbounded retrieval can degrade availability. The scored vector focuses on token theft.

#### CVSS Rationale

The route is public and requires no attacker account. Complexity is High because an allowlisted-origin content/redirect primitive is required, and User Interaction is Required for authorization-code theft. Successful exploitation gives High confidentiality and integrity impact through the victim's gateway scopes.

#### Remediation

Set `redirect: "error"`; require the response URL to equal the client ID; resolve and validate all addresses before connection and prevent DNS rebinding/connected-address drift; reject loopback, link-local, private, multicast, unspecified, and other special-use ranges in production. Stream at most 5 KB, require an appropriate JSON media type and schema, bound concurrent fetches, and cache successful metadata according to HTTP semantics. Prefer exact metadata-document allowlist entries for a private gateway; origin entries deliberately trust every path and deployment primitive on that origin.

#### Verification

Add positive coverage for a valid exact HTTPS metadata URL and negative coverage for every 3xx class, oversized/chunked/slow bodies, wrong content type, malformed schema, private/special-use IPv4 and IPv6, DNS rebinding simulation, and final URL mismatch. Confirm rejected requests do not issue codes or leak detailed network errors.

### SEC-005: One authenticated subject can exhaust global MCP transport capacity

- **Severity:** Medium
- **CVSS v3.1:** 6.5 `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/mcp/server.ts:70-110`, global `limits.max_mcp_transports`

#### Evidence

Each authenticated initialize request can allocate a `StreamableHTTPServerTransport`. Capacity is checked only against a process-global record count, and records store the transport and last-activity time but not the authenticated subject. Initialization does not require the privileged gateway scopes used by service tools. A single low-privilege token can therefore occupy every slot and refresh activity until expiry. Existing tests confirm the global cap returns `429`, but there is no per-subject fairness boundary.

#### Preconditions

The attacker needs any accepted OAuth/bearer identity. They do not need a downstream service grant or credential reference.

#### Exploit Scenario

The attacker initializes transports until `max_mcp_transports` is reached and keeps them active. All other users attempting to initialize receive capacity errors for as long as the attacker maintains the pool. Existing established sessions may continue.

#### Safe PoC / Validation

Configure a capacity of two, initialize twice under subject A, then attempt initialization under subject B. Expected current result: B receives `429`. After remediation, A's per-subject limit should prevent it from consuming B's reserved fair share. Use local synthetic tokens only.

#### Impact

An authenticated low-privilege principal can deny new MCP sessions gateway-wide.

#### CVSS Rationale

The attack is remote, simple, needs Low privileges, and has no user interaction. Availability impact can be High while capacity is maintained; confidentiality and integrity are unaffected.

#### Remediation

Bind each transport record to the authenticated subject, enforce a conservative per-subject limit and initialization rate limit, and preserve a global emergency cap. Re-authenticate every request and verify the current subject matches the record, but do not make `mcp-session-id` a standalone authorization boundary. Consider admission fairness and trusted-operator recovery.

#### Verification

Add multi-subject tests proving one subject hits its own limit without preventing another from initializing, subject changes cannot reuse a session, idle entries are reclaimed, active sessions cannot evade global bounds, and all denial logs remain token-free.

### SEC-006: OAuth token responses omit mandatory cache-prevention headers

- **Severity:** Low
- **CVSS v3.1:** 3.1 `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/builtinOAuth.ts:744-751`, `src/builtinOAuth.ts:833-840`, `src/builtinOAuth.ts:1259-1265`

#### Evidence

Authorization-code and refresh exchanges return access and refresh tokens through the generic JSON writer, which sets only `Content-Type`. OAuth 2.0 requires responses containing tokens or other sensitive information to include `Cache-Control: no-store` and `Pragma: no-cache`: [RFC 6749 section 5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1).

#### Preconditions

Built-in OAuth is enabled and an intermediary or client cache stores POST responses contrary to common defaults. A victim must complete a token exchange.

#### Exploit Scenario

A shared or misconfigured intermediary caches the successful token response. Another party with access to that cache can recover bearer and refresh tokens.

#### Safe PoC / Validation

Complete a local synthetic authorization-code exchange and inspect response headers. Expected current result: both cache-prevention headers are absent.

#### Impact

Token material may persist in caches beyond the intended response flow. Real-world likelihood is reduced because POST responses are not normally cached without explicit freshness information.

#### CVSS Rationale

The response is remotely delivered but exploitation needs unusual cache behavior and victim interaction. Confidentiality impact is Low in the base finding; broader token capability is deployment-specific.

#### Remediation

Use a dedicated OAuth token/error response writer that sets `Cache-Control: no-store` and `Pragma: no-cache`. Apply a restrictive referrer policy and equivalent cache controls to any page containing authorization codes or sensitive transient state.

#### Verification

Assert both headers on successful authorization-code and refresh responses and on token endpoint errors. Verify discovery/JWKS endpoints retain appropriate independent caching semantics.

## Exploit Chains

### CHAIN-001: Credential reference to raw credential and policy escape

- **Combined severity:** High
- **CVSS v3.1:** 8.2 `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`

1. An authenticated subject receives a destination- and service-bound `gref_...`.
2. The subject places it in an arbitrary field of a policy-allowed call to a downstream endpoint that transforms or reflects input.
3. The gateway substitutes the raw credential after destination/policy approval.
4. The downstream returns an undeclared Base64, percent, hex, split, or application-specific representation.
5. Response scanning does not recognize the transformed value, so it reaches the caller.
6. The caller reverses the transform and uses the raw credential directly, outside all gateway destination, route, audit, and future revocation controls.

This chain crosses from constrained gateway capability into the downstream credential's native authority, so its combined integrity impact and changed scope are higher than `SEC-002` alone. `SEC-001` supplies a simpler alternative exfiltration path in deployments with a vulnerable suffix matcher.

## Hardening Recommendations

1. Keep built-in OAuth limited to its documented private, single-administrator use case. For public multi-user access, prefer an external provider with MFA, mature abuse detection, key rotation, and account recovery.
2. Put the service behind a TLS reverse proxy with connection, request, and per-source rate limits. The direct socket address is not a useful client identity behind a proxy; do not trust arbitrary `X-Forwarded-For` without an explicit trusted-proxy model.
3. Add per-subject and per-service request quotas. Login limits can currently be turned into a shared lockout behind a proxy, while authenticated request/audit floods can consume CPU or disk.
4. Rotate/quota append-only audit storage and monitor disk usage. Preserve fail-closed behavior without letting audit exhaustion take down unrelated operations.
5. Stop using MCP transport session identity as an extra boundary for denial explanation records; supported clients can reinitialize or vary sessions. Subject/service authorization remains the real boundary.
6. Return `403` with an `insufficient_scope` challenge for valid tokens lacking scope, rather than collapsing authentication and authorization failures into `401`; align with the current [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
7. Require explicit canonical HTTPS `server.resource` and issuer values in production. Set HSTS and standard browser security headers at the TLS boundary.
8. Reject configuration URLs containing userinfo. Otherwise values such as `base_url_hint` can expose embedded credentials to authorized clients even though secrets should not be stored in URLs.
9. Warn or reject dangerously broad/unanchored host and path regexes and use a safe-regex policy or complexity bounds for administrator-supplied expressions.
10. Avoid placing different-trust destinations in one service because response `sec_...` tokens are service-bound rather than destination-bound.
11. Consider omitting `service_count` from public health responses if deployment inventory is sensitive.
12. Enforce an RSA key-size floor (at least 2048 bits) when loading built-in OAuth signing keys.
13. Sanitize user-supplied audit `reason` fields for credential/token-shaped values even though a caller could only submit values it already possesses.

## Positive Security Observations

- Authentication and scope checks precede bounded MCP body parsing, and destination validation plus policy evaluation precede credential substitution and downstream I/O.
- Former caller-controlled authority/header issues are remediated: outbound authority is derived from the validated target and dangerous/hop-by-hop headers are handled centrally.
- JWT validation covers signature, issuer, audience/resource, time claims, required scopes, and stable principal identity.
- Built-in OAuth uses PKCE S256, exact metadata-declared redirect matching, bounded login/KDF/state records, asynchronous password hashing, short authorization-code lifetime, rotating hash-only refresh tokens, replay-family revocation, and atomic optional persistence.
- Opaque references use strong randomness and hashes and are bound to subject, service, destination, and credential where appropriate. Cross-subject/service/destination negative tests are extensive.
- Downstream redirects are not followed. TLS verification behavior is explicit and covered by a real self-signed local HTTPS test.
- Response processing is bounded and fail-closed on scanner errors, invalid UTF-8, capacity exhaustion, and oversized bodies. Exact configured credentials, JSON-escaped values, HTTP Basic credentials, sensitive-name values, opaque-token misuse, and Secretlint findings are covered.
- Logs and audit records avoid raw authorization headers, cookies, downstream bodies, and opaque token values. The public surface is cookie-free.
- The container runs as a non-root user, CI has meaningful quality/security checks, and `npm audit --omit=dev` reported zero known vulnerabilities across 127 production dependencies on the review date.
- All six findings from the 2026-07-15 review were traced to current remediations rather than carried forward blindly.

## Assumptions and Limitations

- No production configuration was supplied, so suffix-host exposure, OAuth allowlist breadth, reverse-proxy behavior, external issuer policy, and actual downstream route normalization must be checked per deployment.
- No real secrets, personal/internal hostnames, production accounts, or non-loopback targets were used.
- The transformed-response and encoded-path reproductions establish gateway behavior. End-to-end exploitation requires the conditional downstream behaviors described in each finding.
- Dependency auditing reports publicly known advisories only and is not a source-code or supply-chain provenance guarantee.
- This was not a cryptographic implementation audit of `jose`, Node TLS, Secretlint, or the MCP SDK.
- Browser UI behavior was reviewed from source and HTTP semantics; no interactive browser penetration test was performed.

## Appendix

### Commands and Validation

```text
git rev-parse HEAD
git status --short
rg --files
rg <security-relevant symbols and route patterns> src test docs
sed -n / nl -ba <targeted source, test, configuration, CI, and documentation files>
npm ls --omit=dev --depth=1
npm audit --omit=dev --json
npx vitest run test/security-review-poc.test.ts --reporter=verbose
node <URL pathname normalization probe>
npm run build
npm test
git diff --check
```

The temporary `security-review-poc.test.ts` contained only synthetic pure/local checks and was deleted immediately after it passed. Production dependency audit result: 0 known vulnerabilities (0 critical, high, medium, low, or informational) among 127 production dependencies.

### Release Gate

Do not advertise universal raw-credential non-exfiltration or expose suffix-configured destinations publicly until `SEC-001` is fixed. Before broad public deployment, also close `SEC-004` and choose a documented response-isolation model for `SEC-002`/`CHAIN-001`. If a constrained deployment proceeds earlier, require exact hosts, external OAuth, carefully enumerated non-reflective routes, TLS/rate limiting at the edge, durable bounded audit storage, and explicit residual-risk acceptance.

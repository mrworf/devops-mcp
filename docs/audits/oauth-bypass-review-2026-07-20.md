# OAuth Bypass Security Review

## Metadata

- **Project/repository:** SecretSauce (MCP) (`devops-mcp`)
- **Git SHA:** `a4b1aa01640502654a0f63c61e9f120fab4703b7`
- **Review date/time:** `2026-07-21T02:41:21Z`
- **Reviewer role:** senior application security reviewer
- **Scope reviewed:** OAuth and bearer configuration, built-in and external OAuth token handling, all publicly reachable HTTP routes, MCP request authentication and scope selection, tool dispatch, service ACLs, opaque-reference binding, destination and policy enforcement, credential substitution, and downstream HTTP dispatch
- **Commands run:** Git metadata/status collection; repository inventory and targeted source/test/documentation inspection with `rg`, `sed`, and `nl`; focused Vitest OAuth validation; build and full-suite commands recorded below
- **Assumptions and limitations:** source-assisted review and synthetic loopback validation only. No production configuration, reverse proxy, identity provider, DNS path, or real downstream service was available. The repository contains example configuration, not the operator's deployed service/ACL configuration. Direct access to a downstream outside this gateway was out of scope.

## Executive Summary

One conditional OAuth bypass was confirmed. External OAuth accepts a cleartext HTTP issuer or JWKS URL. If a deployment uses an HTTP JWKS endpoint, an attacker able to modify that network response can replace the trusted signing keys, mint an otherwise valid token for an authorized service subject, and make policy-allowed API calls through the gateway. This is **High severity** because it converts a network interception position into authentication and authorization as an arbitrary configured principal.

No source-level path was found that lets an ordinary unauthenticated remote caller invoke a configured service when OAuth trust anchors are protected by HTTPS and the gateway's configuration/signing material remain trusted. Every reachable MCP POST is authenticated independently before dispatch, tool-specific scopes are checked, service ACLs use the verified principal, and destination/policy checks precede credential substitution and downstream I/O.

`auth.mode: bearer` deliberately replaces OAuth with a shared bearer secret. That mode is not an OAuth bypass in an OAuth-configured deployment; it is a separate development authentication mode selected by the operator. A holder of that secret acts as `bearer-dev` and can access only services whose ACL includes that subject.

## Scope and Methodology

The review first mapped all externally reachable routes in `src/server.ts`, then traced the only remote path to `executeServiceRequest`: MCP POST authentication, body parsing, tool-specific scope enforcement, SDK dispatch, service authorization, destination resolution, policy evaluation, opaque-reference validation/substitution, and downstream I/O. External JWT validation and the complete built-in authorization-code/PKCE and refresh-token flows were inspected separately.

Potential mismatches between the pre-dispatch scope classifier and SDK dispatch were considered for JSON-RPC batches, unknown tools, alternate methods and paths, caller-supplied MCP session IDs, missing auth context, malformed bearer headers, invalid claims, and cross-subject references. Existing negative tests and focused local execution were used as evidence. No real tokens, credentials, hosts, or outbound requests were used.

## Threat Model

- **Exposed interfaces:** `/health`, brand assets, OAuth protected-resource metadata, built-in OAuth discovery/JWKS/authorize/token routes, and the configured Streamable HTTP MCP path
- **Sensitive assets:** downstream credentials, OAuth signing trust, access and refresh tokens, configured service identities and ACLs, opaque gateway references, downstream data, and policy-approved mutation authority
- **Trust boundaries:** client to gateway; gateway to external OAuth JWKS; OAuth issuer to gateway; authenticated principal to service ACL; MCP tool arguments to downstream network dispatch; configuration/filesystem to runtime
- **Likely attacker profiles:** unauthenticated internet caller, on-path network attacker between the gateway and external identity provider, malicious authenticated principal, prompt-injected client operating with a valid token, and local attacker with configuration or signing-key access

## Authentication-to-Downstream Flow

The externally reachable call path is:

1. `src/server.ts:48-64` accepts only a POST on the configured MCP path and calls `authenticateRequest` before SDK dispatch.
2. `src/server.ts:52-54` parses the bounded JSON body and requires the scopes associated with every message in the request.
3. `src/mcp/server.ts:38-52` refuses tool calls without SDK-propagated auth context.
4. `src/mcp/tools.ts:188-192` is the only tool branch that reaches `executeServiceRequest`.
5. `src/gateway.ts:55-61` enforces the service ACL, destination constraints, and policy before credential substitution.
6. `src/gateway.ts:106-125` validates opaque references and constructs the downstream request only after those controls pass.

The unauthenticated health, asset, metadata, discovery, and JWKS routes do not call the service gateway. Authenticated MCP GET and DELETE requests return `405`, and unknown paths return `404`.

## Findings Summary

| ID | Severity | CVSS | Confidence | Title | Status |
|----|----------|------|------------|-------|--------|
| SEC-001 | High | 8.1 | Confirmed | Cleartext OAuth trust URLs permit signing-key substitution | Open |

## Detailed Findings

### SEC-001: Cleartext OAuth trust URLs permit signing-key substitution

- **Severity:** High
- **CVSS v3.1:** 8.1 `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **Confidence:** Confirmed
- **Status:** Open
- **Affected components:** `src/config.ts:43-64`, `src/config.ts:266-280`, `src/auth.ts:57-84`, `src/auth.ts:150-155`, `auth.oauth.issuer`, `auth.oauth.jwks_uri`; cleartext `auth.builtin_oauth.issuer` is also unsafe for non-loopback clients

#### Evidence

The configuration schema validates `issuer` and `jwks_uri` as generic URLs but does not require HTTPS. Normalization preserves those values unchanged. External authentication passes the configured or issuer-derived URL directly to `createRemoteJWKSet`, then treats any successfully verified JWT from that key set as authenticated after checking issuer, audience, scope, and the configured principal claim.

The focused test at `test/auth.test.ts:1184-1198` starts a loopback HTTP JWKS server, signs a synthetic token with the corresponding private key, and confirms that production `authenticateRequest` accepts it. The review reran that test successfully. This establishes that HTTP JWKS retrieval is supported rather than rejected. The same test suite confirms that a token from a different signing key is rejected, so replacing the remotely retrieved key set changes which attacker-generated token the gateway trusts.

When `jwks_uri` is omitted and `issuer` uses HTTP, `src/auth.ts:58` derives an HTTP JWKS URL. An HTTP built-in issuer has a separate exposure: remote clients submit administrator credentials, authorization codes, access tokens, and refresh tokens over a channel that offers no server authentication or confidentiality unless a separate trusted TLS layer upgrades the public URL.

#### Preconditions

- External OAuth is configured with an `http://` JWKS URL, or with an `http://` issuer and no explicit HTTPS JWKS URL.
- The attacker can observe and modify traffic between the gateway and that JWKS endpoint, such as from the same network segment, a compromised proxy, or a poisoned cleartext route.
- To reach a specific service, the attacker knows or can guess a principal value present in that service's `access.users` list.
- The requested downstream destination, method, and path must still be allowed by gateway policy. No victim interaction or existing OAuth credential is required.

#### Exploit Scenario

On a JWKS fetch, the attacker returns a key set containing an attacker-controlled public key. They sign a JWT containing the configured issuer and audience, an authorized subject (or configured principal claim), and `gateway.read gateway.references gateway.request` scopes. The gateway verifies that JWT using the substituted key, allows the attacker to obtain a service-bound `gref_...`, and then sends policy-approved API calls with the configured downstream credential.

Service ACL, destination, policy, and reference-binding checks remain active, but they operate on the forged identity and scopes. Therefore, they do not repair the broken OAuth trust decision.

#### Safe PoC / Validation

- **Intended environment:** local automated test only
- **Preconditions:** repository dependencies installed; permission to bind a loopback port
- **Command:**

  ```bash
  npx vitest run test/auth.test.ts -t "accepts valid OAuth JWTs from JWKS and enforces scopes"
  ```

- **Expected safe result:** the synthetic JWT is accepted when its public key is served by the configured loopback HTTP JWKS endpoint, proving the gateway does not require a protected JWKS transport.
- **Cleanup:** the test closes its loopback server; no persistent file or credential is created.
- **Why non-destructive:** it uses generated test keys, a local endpoint, a synthetic subject, and no downstream request.

For a remediation regression, add a configuration test that rejects non-loopback HTTP issuer/JWKS URLs and a positive test for HTTPS URLs. If loopback HTTP remains supported for tests or local development, add positive cases for canonical loopback hosts and negative cases for private, link-local, public, credential-bearing, and misleading hostnames.

#### Impact

The attacker can impersonate any configured principal and exercise every service, destination, method, and path available to that principal. For services that use gateway-managed credentials, the attacker can obtain references and cause the gateway to apply those credentials to downstream calls. This can expose sensitive service data and permit privileged mutations. The gateway's policy still bounds the operation, so unrestricted downstream compromise is not assumed.

#### CVSS Rationale

The attack requires an adjacent/on-path network position (`AV:A`) but is reliable once that position exists (`AC:L`). It needs no prior application privilege or victim interaction. Impersonating an authorized principal can cause High confidentiality and integrity impact across policy-allowed operations. Availability impact was not assumed, and Scope remains Unchanged because the gateway intentionally brokers the downstream authority.

#### Remediation

Reject non-HTTPS OAuth trust URLs during configuration normalization:

- Require `https:` for `auth.oauth.issuer` and `auth.oauth.jwks_uri` in hosted or production use.
- Require `https:` for the public `server.resource` and `auth.builtin_oauth.issuer` used by non-loopback clients.
- If local development needs cleartext HTTP, permit only exact loopback hosts (`127.0.0.1`, `[::1]`, and, if deliberately supported, `localhost`) under an explicit development exception. Do not treat RFC1918/private addresses as equivalent to loopback.
- Reject URL credentials and fragments. Define whether query strings are allowed for JWKS URLs rather than accepting them accidentally.
- Document that TLS termination must make the externally advertised issuer/resource HTTPS even though the Node server may receive proxied HTTP internally.

Do not attempt to solve this with response pinning alone: the initial trusted key retrieval must itself be authenticated.

#### Verification

Add positive and negative tests for every new URL input. Then run an end-to-end local test with an HTTPS JWKS fixture showing that a token signed by the trusted key succeeds and a key served by an untrusted endpoint fails. Run the full suite and build afterward.

## Exploit Chains

No separate multi-finding chain was identified. SEC-001 directly creates a forged OAuth identity; the subsequent reference issuance and service request are normal gateway behavior under that forged identity. Their presence explains impact but does not constitute independent vulnerabilities.

## Hardening Recommendations

1. **Enforce scopes again at tool dispatch.** `callTool` currently relies on `requiredScopesForMcpBody` in the HTTP route. The current parsed object is shared with SDK dispatch, and no mismatch was found, so this is not a demonstrated bypass. Checking the selected descriptor's scopes immediately before its implementation would preserve authorization if another transport or internal caller is added later.
2. **Add HTTP-level scope regression tests.** Existing tests prove JWT claim validation and unit-level scope rejection, while unauthenticated HTTP tests prove the challenge. Add end-to-end tests showing that a valid token missing each tool's scope receives no tool result and causes no downstream request, including a mixed-scope JSON-RPC batch.
3. **Make insecure authentication modes explicit.** Consider refusing `auth.mode: bearer` on a non-loopback listener unless an explicit development override is set. This is an operator-selected alternate authentication mode, not a current OAuth bypass, but a guard would reduce accidental public deployments.
4. **Optionally constrain token class per provider.** External JWT verification does not distinguish an access token from another signed JWT carrying the same issuer, audience, scopes, and principal. Providers differ in their token-type claims, so this should be configurable and documented rather than enforced with one universal claim.

## Positive Security Observations

- Authentication happens before MCP body parsing and before all tool dispatch, and every stateless MCP POST is authenticated independently (`src/server.ts:48-64`). Caller-supplied session IDs do not establish trust.
- External and built-in JWT validation checks signature, issuer, audience, time validity, required scopes, and a non-empty stable principal claim (`src/auth.ts:31-85`, `src/auth.ts:166-179`). Negative tests cover wrong issuer, audience, signature, expiry, `nbf`, mode confusion, missing scopes, and invalid principals.
- The MCP handler refuses tool execution without an auth context (`src/mcp/server.ts:38-52`, `src/mcp/server.ts:58-68`).
- Tool-specific route scope selection covers read, reference, and request operations, including every message in a JSON-RPC batch (`src/server.ts:157-168`).
- Service authorization is an exact subject ACL check, and both token issuance and service requests call it (`src/registry.ts:87-114`, `src/tokens.ts:84-96`, `src/gateway.ts:55-60`).
- Opaque references are random, hash-indexed, expiring, and bound to subject, service, and destination before credential substitution (`src/tokens.ts:101-160`).
- Destination and policy decisions occur before reference redemption, credential substitution, or downstream I/O (`src/gateway.ts:55-125`).
- Built-in OAuth uses local RSA signing keys, password verification, verified client metadata, exact redirect binding, PKCE, short-lived one-use authorization codes, rotating hash-only refresh tokens, replay-family revocation, resource/client/scope binding, and bounded unauthenticated work. No built-in code-flow bypass was found.

## Assumptions and Limitations

The review could not determine whether any deployed gateway currently uses HTTP OAuth URLs because no deployment configuration was present. If all public issuer, resource, and JWKS URLs are HTTPS with valid certificate verification, SEC-001 is not exploitable in that deployment.

An attacker with write access to the gateway configuration, OAuth signing key, environment secrets, or built-in refresh-state file is already across the reviewed trust boundary and can construct authenticated state or replace credentials. Likewise, code running inside the gateway process can call exported functions with a fabricated `AuthContext`; no remote route to do so was found.

This review answers OAuth bypass into gateway-mediated service calls. It does not assess whether a configured downstream is independently reachable without the gateway or whether its own authentication can be bypassed.

## Appendix: Validation Status

- Focused OAuth validation: passed (3 selected tests; 49 skipped).
- Initial sandboxed focused run: failed only because loopback bind returned `listen EPERM`; the identical command passed with loopback permission, as required by repository instructions.
- Build: passed (`npm run build`).
- Full suite: passed (`npm test`; 29 files and 281 tests). The initial sandboxed run failed only on loopback `listen EPERM`; the identical full-suite command passed with loopback permission.
- Git diff check: passed (`git diff --check`).

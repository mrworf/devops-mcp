# PRD: SecretSauce (MCP) — MVP

> **Give agents access, not secrets**

## 1. Summary

Build an OpenAI-compatible MCP server that lets Codex, ChatGPT desktop, and other supported OpenAI MCP clients interact with configured homelab/admin HTTP APIs without exposing raw credentials to the model or client session.

The server acts as a service-scoped HTTP API gateway. Agents request temporary opaque service references, use those references in headers, query parameters, or request bodies, and the MCP server replaces those references with real credentials only after authentication, authorization, destination validation, reference binding, and policy checks.

The MVP targets homelab and small self-hosted environments. It is not intended as an enterprise credential platform.

## 2. Product positioning

This is not primarily a secrets vault.

It is:

> An MCP-controlled API gateway that lets agents operate configured HTTP services without receiving raw credentials.

The gateway protects against accidental credential exposure and provides policy, audit, and token-scoped access. It does not guarantee that an agent cannot misuse an allowed credential within the configured policy.

## 3. Target clients

The MVP targets OpenAI MCP clients first.

Supported for MVP:

* Codex CLI
* Codex IDE extension
* ChatGPT desktop app using the shared Codex MCP host configuration

Optional or post-MVP:

* ChatGPT web through plugin-provided or hosted MCP integration

Important distinction:

* Codex CLI, Codex IDE extension, and ChatGPT desktop can use Codex MCP configuration.
* ChatGPT web does not read local Codex MCP config.
* ChatGPT web support requires a hosted/plugin integration path.

## 4. Target users

### Primary user

A homelab operator using Codex CLI, ChatGPT desktop, or another OpenAI MCP-capable agent to administer self-hosted services.

Example services:

* Portainer
* OPNsense
* TrueNAS
* Proxmox
* Home Assistant
* UniFi Controller
* Jellyfin
* Internal web APIs

### Secondary user

A technically capable small-team admin who wants flexible agent access to internal HTTP APIs without exposing raw credentials directly to the agent.

## 5. Problem

AI agents need API credentials to administer services. Providing raw credentials directly to Codex or ChatGPT is risky because credentials may appear in prompts, tool output, logs, generated files, terminal history, crash reports, model context, or screenshots.

Dedicated MCP servers for every service provide stronger controls but are time-consuming to build and maintain. Homelab users need a flexible generic option that is safer than pasting API keys into the agent.

## 6. Goals

### Primary goals

* Prevent raw API keys, usernames, passwords, and configured secrets from being exposed to OpenAI MCP clients.
* Provide a flexible service-scoped HTTP request tool.
* Restrict credential use to configured services, destinations, hosts, schemes, ports, users, sessions, and policies.
* Support OpenAI-compatible MCP tool descriptors.
* Support Streamable HTTP MCP transport.
* Support OAuth authentication for MCP clients.
* Support bearer-token authentication as an optional development/simple-deployment mode.
* Provide audit logs for token issuance and downstream API requests.
* Support self-signed TLS by allowing per-service certificate verification disablement.
* Support explicit allow/deny policy with default deny.
* Replace configured credentials and Secretlint findings in downstream responses with scoped opaque references.
* Require reason fields for both reference requests and service requests.
* Provide explainable policy denials.

## 7. Non-goals for MVP

* No dedicated service-specific MCP implementations.
* No enterprise IAM.
* No built-in secrets vault.
* No automatic API discovery.
* No full semantic understanding of safe versus unsafe API operations.
* No guaranteed prevention of all secret leakage in API responses.
* No web admin UI.
* No hosted SaaS.
* No approval workflow beyond OpenAI client approval prompts.
* No built-in Vault, 1Password, AWS KMS, GCP KMS, or Azure Key Vault integration.
* No service profile packs in MVP.
* No ChatGPT web local-config support, because ChatGPT web does not use local Codex MCP config.

## 8. Core concepts

## 8.1 Service

A configured HTTP API target, such as:

```text
portainer-prod
opnsense-home
proxmox-lab
```

A service defines:

* destinations
* allowed hosts
* allowed schemes
* allowed ports
* TLS behavior
* credentials
* access rules
* request policy
* audit behavior

## 8.2 Destination

A configured base URL or instance for a service.

Example:

```yaml
destinations:
  - name: primary
    base_url: https://portainer.example.org:9443
```

A service may have multiple destinations.

Example:

```yaml
destinations:
  - name: prod
    base_url: https://portainer.example.org:9443
  - name: lab
    base_url: https://lab.portainer.example.org:9443
```

## 8.3 Credential

A configured secret value used to authenticate to a downstream service.

Examples:

* API key
* bearer token
* username
* password
* cookie value
* custom header value

## 8.4 Gateway service reference

A temporary placeholder returned to the agent instead of a real credential.

Example:

```text
gref_portainer_api_key_abc123
```

The reference is not valid outside the MCP server.

## 8.5 Capability

Temporary authorization for an authenticated user to use an opaque service reference for a specific service, destination, and access method.

## 8.6 Policy

Service-level request rules that determine whether a downstream HTTP request is allowed or denied.

## 9. OpenAI MCP requirements

## 9.1 MCP transport

MVP must support:

```text
Streamable HTTP MCP transport
```

The server must expose a URL suitable for Codex configuration.

Example:

```text
https://gateway.example.org/mcp
```

MVP does not require:

* STDIO transport
* SSE-only legacy transport
* local process launch mode

STDIO may be added later, but the primary deployment model is a containerized infrastructure service.

## 9.2 MCP initialization instructions

The MCP server must return an `instructions` field during initialization.

The first 512 characters must be self-contained and explain the core safety model.

Required opening text:

```text
This MCP server lets agents call configured HTTP services without exposing protected backend values. Always call list_services first, then get_gateway_service_references with a clear reason, then use service_request with service, destination, method, path or allowed URL, and a request reason. Place credential references according to their usage hints, and pass `gateway_access` references in `service_reference`. References have no meaning outside this MCP server. Requests may be denied by service policy.
```

Full instructions should also include:

* Never claim a gateway reference is a real API key.
* Never attempt to use gateway references outside this MCP server.
* Use relative paths when possible.
* Use absolute URLs only when they match a configured destination.
* Include a specific reason for every reference request.
* Include a specific reason for every service request.
* Use `describe_service_policy` when endpoint policy needs to be inspected before attempting a request.
* If denied, call `explain_denial`.
* Do not retry denied requests by changing hosts, paths, or token placement unless the denial explanation says it is allowed.
* Treat TLS verification warnings as meaningful risk signals.
* Do not ask the user for raw credentials.

## 9.3 MCP tools

MVP exposes five model-visible tools:

```text
list_services
describe_service_policy
get_gateway_service_references
service_request
explain_denial
```

No service-specific tools are required for MVP.

The tool count should remain small so Codex can reliably choose the correct tool.

## 9.4 Tool descriptor requirements

Every tool descriptor must include:

* stable tool name
* human-readable title
* concise description
* `inputSchema`
* `outputSchema` if returning structured content
* `securitySchemes`
* `_meta.securitySchemes` mirror for compatibility
* appropriate annotations
* short invocation status text where supported

The server must not rely on tool annotations for security. Annotations are client hints only. The server must enforce authentication, authorization, reference binding, destination validation, TLS policy, and request policy.

## 9.5 Tool result format

Every tool result must return:

* `structuredContent` for machine-readable output
* concise `content` text for model-readable summary
* hidden `_meta` only for client/UI details that should not be modeled

The server must never place raw credentials in `structuredContent`, `content`, or `_meta`.

Example:

```json
{
  "structuredContent": {
    "request_id": "req_123",
    "status_code": 200,
    "headers": {
      "content-type": "application/json"
    },
    "body": "[...]",
    "secret_tokenized": true,
    "secret_tokenization_count": 2,
    "tls": {
      "verify": false
    },
    "truncated": false
  },
  "content": [
    {
      "type": "text",
      "text": "Request req_123 completed with HTTP 200. TLS verification was disabled for this destination."
    }
  ],
  "_meta": {
    "audit_id": "audit_789"
  }
}
```

## 10. Authentication and authorization

## 10.1 OAuth

The MCP server must support OAuth for OpenAI MCP clients.

OAuth requirements:

* The MCP server must advertise OAuth capability in a way compatible with OpenAI MCP clients.
* The server must support Codex login flow using:

```text
codex mcp login <server-name>
```

* The server must support configurable OAuth issuer, audience, client ID, and scopes.
* The authenticated subject must be available to service listing, token issuance, policy evaluation, and audit logging.
* Unauthenticated MCP requests must be rejected.

## 10.2 Bearer token mode

Bearer-token authentication may be supported for development and simple deployments.

This mode must be clearly documented as simpler but less capable than OAuth.

## 10.3 Authorization model

OAuth identifies the user/client.

Gateway capabilities authorize specific service and credential use.

OAuth access alone must not automatically allow use of every configured downstream credential.

Authorization inputs:

* authenticated subject
* MCP client/session ID if available
* service ID
* destination ID
* credential ID
* configured access rules
* requested action
* policy result

## 11. Required MCP tools

## 11.1 Tool: `list_services`

### Purpose

List services and destinations available to the authenticated user.

### Input

```json
{}
```

### Output

```json
{
  "services": [
    {
      "id": "portainer-prod",
      "name": "Portainer Production",
      "description": "Main Portainer instance",
      "destinations": [
        {
          "id": "primary",
          "base_url_hint": "https://portainer.example.org:9443",
          "tls_verify": false
        }
      ],
      "access_methods": [
        {
          "id": "api_key",
          "usage_hint": "Use reference as X-API-Key header"
        }
      ],
      "policy_summary": "mode=deny"
    }
  ]
}
```

### Descriptor requirements

Recommended descriptor properties:

```ts
{
  title: "List configured services",
  description:
    "List the HTTP services and access methods available to this authenticated user through the gateway. Does not return protected backend values.",
  securitySchemes: [
    { type: "oauth2", scopes: ["gateway.read"] }
  ],
  _meta: {
    securitySchemes: [
      { type: "oauth2", scopes: ["gateway.read"] }
    ],
    "openai/toolInvocation/invoking": "Listing services",
    "openai/toolInvocation/invoked": "Services listed"
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    openWorldHint: false,
    idempotentHint: true
  }
}
```

### Recommended OpenAI approval behavior

```text
auto
```

## 11.2 Tool: `describe_service_policy`

### Purpose

Describe configured destinations, service access methods, and ordered allow/deny policy rules for a service the authenticated user can access.

### Input

```json
{
  "service": "portainer-prod"
}
```

### Output

```json
{
  "id": "portainer-prod",
  "name": "Portainer Production",
  "description": "Main Portainer instance",
  "api_docs_url": "https://api.example.org/portainer/openapi.json",
  "destinations": [
    {
      "id": "primary",
      "base_url_hint": "https://portainer.example.org:9443",
      "tls_verify": false
    }
  ],
  "access_methods": [
    {
      "id": "api_key",
      "usage_hint": "Use reference as X-API-Key header"
    }
  ],
  "policy": {
    "mode": "deny",
    "rules": [
      {
        "id": "allow-stack-read",
        "effect": "allow",
        "priority": 100,
        "methods": ["GET"],
        "hosts": [],
        "paths": ["/api/stacks.*"],
        "reason": "Read-only stack inventory"
      }
    ]
  }
}
```

### Descriptor requirements

Recommended descriptor properties:

```ts
{
  title: "Describe service policy",
  description:
    "Describe configured destinations, service access methods, and ordered allow/deny policy rules for a service this authenticated user can access. Does not return protected backend values.",
  securitySchemes: [
    { type: "oauth2", scopes: ["gateway.read"] }
  ],
  _meta: {
    securitySchemes: [
      { type: "oauth2", scopes: ["gateway.read"] }
    ],
    "openai/toolInvocation/invoking": "Describing service policy",
    "openai/toolInvocation/invoked": "Service policy described"
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    openWorldHint: false,
    idempotentHint: true
  }
}
```

### Recommended OpenAI approval behavior

```text
auto
```

## 11.3 Tool: `get_gateway_service_references`

### Purpose

Return short-lived gateway-only references for configured service access.

### Input

```json
{
  "service": "portainer-prod",
  "destination": "primary",
  "access_ids": ["api_key"],
  "reason": "Inspect current stack configuration before proposing a Compose update."
}
```

Required fields:

* `service`
* `access_ids`
* `reason`

`destination` is required when the service has multiple destinations.

### Output

```json
{
  "references": [
    {
      "access_id": "api_key",
      "reference": "gref_portainer_api_key_abc123",
      "usage_hint": "Use as X-API-Key header",
      "expires_at": "2026-07-09T18:30:00Z",
      "exportable": false,
      "usable_outside_gateway": false,
      "reveals_protected_value": false
    }
  ]
}
```

The response must not include protected backend values.

### Descriptor requirements

Recommended descriptor properties:

```ts
{
  title: "Get gateway service references",
  description:
    "Get short-lived gateway-only references for configured service access. References cannot reveal or export protected values and creating one does not contact the downstream service.",
  securitySchemes: [
    { type: "oauth2", scopes: ["gateway.references"] }
  ],
  _meta: {
    securitySchemes: [
      { type: "oauth2", scopes: ["gateway.references"] }
    ],
    "openai/toolInvocation/invoking": "Getting service references",
    "openai/toolInvocation/invoked": "Service references ready"
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: false,
    openWorldHint: false,
    idempotentHint: false
  }
}
```

### Recommended OpenAI approval behavior

```text
prompt
```

Rationale: creating a reference does not call the downstream service, but it grants temporary capability to use configured service access through the gateway.

## 11.4 Tool: `service_request`

### Purpose

Send an HTTP request to a configured service destination after validating authentication, authorization, destination, reference binding, TLS policy, and request policy.

### Input

```json
{
  "service": "portainer-prod",
  "destination": "primary",
  "method": "GET",
  "path": "/api/stacks",
  "headers": {
    "X-API-Key": "gref_portainer_api_key_abc123"
  },
  "reason": "List stacks so I can identify the Jellyfin stack."
}
```

Required fields:

* `service`
* `method`
* either `path` or `url`
* `reason`

Optional fields:

* `destination`
* `service_reference` (required for services exposing `gateway_access`; consumed by the gateway and never forwarded downstream)
* `headers`
* `query`
* `body`

Supported HTTP methods:

```text
GET
POST
PUT
PATCH
DELETE
HEAD
OPTIONS
```

### Output

```json
{
  "request_id": "req_123",
  "status_code": 200,
  "headers": {
    "content-type": "application/json"
  },
  "body": "[...]",
  "secret_tokenized": true,
  "secret_tokenization_count": 2,
  "tls": {
    "verify": false
  },
  "truncated": false
}
```

### Descriptor requirements

Recommended descriptor properties:

```ts
{
  title: "Send service HTTP request",
  description:
    "Send an HTTP request to a configured service through the gateway. Gateway service references in headers, query, or body are replaced with configured access only after authorization and policy checks.",
  securitySchemes: [
    { type: "oauth2", scopes: ["gateway.request"] }
  ],
  _meta: {
    securitySchemes: [
      { type: "oauth2", scopes: ["gateway.request"] }
    ],
    "openai/toolInvocation/invoking": "Sending service request",
    "openai/toolInvocation/invoked": "Service response received"
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    openWorldHint: true,
    idempotentHint: false
  }
}
```

### Recommended OpenAI approval behavior

```text
prompt
```

The gateway itself must still enforce service policy. Client approval is not a security boundary.

## 11.5 Tool: `explain_denial`

### Purpose

Explain why a prior reference request or service request was denied.

### Input

```json
{
  "request_id": "req_123"
}
```

### Output

```json
{
  "request_id": "req_123",
  "reason": "Denied by policy rule deny-delete.",
  "matched_rule": "deny-delete",
  "policy_mode": "deny",
  "suggestion": "Use GET to inspect the resource or ask the user to update policy."
}
```

### Descriptor requirements

Recommended descriptor properties:

```ts
{
  title: "Explain denied request",
  description:
    "Explain why a gateway request was denied, including matched policy rule and suggested next step if available.",
  securitySchemes: [
    { type: "oauth2", scopes: ["gateway.read"] }
  ],
  _meta: {
    securitySchemes: [
      { type: "oauth2", scopes: ["gateway.read"] }
    ],
    "openai/toolInvocation/invoking": "Checking denial",
    "openai/toolInvocation/invoked": "Denial explained"
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    openWorldHint: false,
    idempotentHint: true
  }
}
```

### Recommended OpenAI approval behavior

```text
auto
```

## 12. Token requirements

## 12.1 Reference binding

Tokens must be bound to:

* authenticated user
* MCP client/session, if available
* service
* destination, if provided
* credential ID
* token issuance reason
* configured service destinations

A token issued for one service must not be usable for another service.

A token issued for one destination must not be usable for another destination unless explicitly configured.

## 12.2 Token lifetime

MVP must support:

* idle TTL
* hard max lifetime

Default values:

```yaml
tokens:
  idle_ttl: 10m
  max_ttl: 1h
```

Using a token may refresh the idle TTL.

Using a reference must not extend it beyond the hard max lifetime.

Expired references must be rejected.

## 12.3 Reference values

Reference values should be opaque and non-guessable.

Readable service hints are allowed only if they do not leak sensitive information.

Acceptable:

```text
gref_portainer_api_key_abcd1234
```

Also acceptable:

```text
gref_7t93KQeJ2jTqSg9c
```

The reference value itself must not be logged in audit logs. Audit logs should contain only internal reference IDs.

## 12.4 Unknown references

Requests containing unknown opaque references must be rejected.

Requests containing valid references that do not belong to the authenticated user/service/destination must be rejected.

## 13. Service request execution

For every `service_request`, the MCP server must:

1. authenticate the caller
2. authorize access to the service
3. resolve destination
4. validate URL/path against configured destinations
5. validate scheme
6. validate host
7. validate port
8. evaluate request policy
9. validate opaque reference usage
10. replace opaque references with real credential values
11. perform the downstream HTTP request
12. validate cookie/encoding constraints and tokenize response headers and body source text
13. return structured response to the agent
14. write audit log entries

Policy must be evaluated before credential substitution.

If policy denies the request, the downstream request must not be sent.

## 14. URL and destination handling

## 14.1 Relative paths

Relative paths are preferred.

Example:

```json
{
  "path": "/api/stacks"
}
```

## 14.2 Absolute URLs

Absolute URLs must be supported because services may have multiple hostnames or multiple instances.

Example:

```json
{
  "url": "https://portainer.example.org:9443/api/stacks"
}
```

If an absolute URL is used, it must match a configured destination for the service.

Credential substitution must only occur when the target URL matches the configured service destination rules.

Requests to unconfigured hosts must be rejected.

## 14.3 Destination matching

A request target must match:

* service
* destination, if required
* allowed scheme
* allowed host
* allowed port
* configured base URL rules
* request policy

Credential substitution must not occur unless destination validation succeeds.

## 15. Host, scheme, and port rules

## 15.1 Host matching

Service destinations must support host matching with:

* exact hostname
* suffix match
* regex match

Example:

```yaml
hosts:
  - exact: portainer.example.org
  - suffix: .example.org
  - regex: '^[a-z0-9-]+\.portainer\.example\.org$'
```

Host matching must be performed against the normalized hostname only.

Normalization requirements:

* lowercase hostname
* strip trailing dot
* exclude scheme
* exclude path
* exclude query string
* exclude fragment
* exclude port unless port-specific matching is explicitly configured

## 15.2 Broad regex warnings

The server must validate regexes at startup.

The server should warn on broad host regexes such as:

```text
.*
^.*$
.*example.*
```

MVP may warn instead of rejecting broad regexes.

A future strict mode may reject broad regexes unless explicitly overridden.

## 15.3 Scheme restrictions

Service destinations must support scheme restrictions.

Example:

```yaml
schemes: [https]
```

Requests using other schemes must be rejected.

## 15.4 Port restrictions

Service destinations must support port restrictions.

Example:

```yaml
ports: [9443]
```

Requests using other ports must be rejected.

## 16. TLS behavior

## 16.1 TLS verification

MVP must support disabling TLS certificate verification per service or destination.

Example:

```yaml
tls:
  verify: false
```

Default behavior:

```yaml
tls:
  verify: true
```

If `tls.verify: false`, the server must allow self-signed or invalid certificates for that service/destination.

Audit logs and response metadata must record that TLS verification was disabled.

## 16.2 Future certificate pinning

Future support should include certificate fingerprint pinning.

Example:

```yaml
tls:
  verify: false
  fingerprint: "sha256/..."
```

Fingerprint pinning is not required for MVP.

## 17. Redirect handling

MVP must not forward credentials across host boundaries.

Default behavior:

```text
Do not automatically follow redirects.
```

Optional MVP behavior:

```text
Allow same-host redirects only if explicitly configured.
```

Cross-host redirects must be rejected unless explicitly configured.

Credentials must not be forwarded to a different host.

## 18. Policy model

## 18.1 Policy modes

Each service must have a policy mode:

```yaml
policy:
  mode: deny
```

or:

```yaml
policy:
  mode: allow
```

Default policy mode must be:

```yaml
mode: deny
```

## 18.2 Policy rules

Policy rules must support:

* `id`
* `effect`: allow or deny
* `priority`
* `methods`
* `hosts`
* `paths`
* optional `reason`

Example:

```yaml
policy:
  mode: deny
  rules:
    - id: allow-stack-read
      effect: allow
      priority: 100
      methods: [GET]
      paths:
        - /api/endpoints.*
        - /api/stacks.*

    - id: deny-delete
      effect: deny
      priority: 1000
      methods: [DELETE]
      paths:
        - /.*
      reason: "DELETE blocked in MVP"
```

## 18.3 Policy evaluation

Policy evaluation rules:

1. Find all matching rules.
2. If matching rules exist, apply the highest-priority rule.
3. If no rule matches, apply the policy mode.
4. `mode: deny` means unmatched requests are denied.
5. `mode: allow` means unmatched requests are allowed.
6. If priorities tie, deny wins.

## 18.4 Path matching

MVP must support path matching using regex-like patterns or explicit regex objects.

Path matching must be performed against the normalized path.

Normalization requirements:

* remove URL scheme and host
* preserve path
* exclude fragment
* handle query string separately or include it only if explicitly configured
* prevent path traversal ambiguity
* normalize duplicate slashes where safe

Query matching is optional for MVP.

## 19. Token substitution

## 19.1 Supported locations

The agent may place opaque references in:

* headers
* request body
* query string

The server must replace recognized opaque references with the corresponding raw credential value before sending the downstream request.

Credential usage may include non-secret prefix and suffix text used to generate an exact reference-placement hint. Named header credentials may opt into enforcement; enforcement defaults off. When enabled, the gateway owns that header, canonicalizes safely repairable duplicate or malformed variants with sanitized warnings, and rejects missing, ambiguous, or wrongly placed references before downstream I/O.

## 19.2 Substitution restrictions

The server must reject:

* unknown tokens
* expired references
* tokens belonging to another user
* tokens belonging to another session
* tokens belonging to another service
* tokens belonging to another destination, unless explicitly allowed
* tokens used against an invalid destination

## 20. Response secret tokenization

The gateway must scan response header values and UTF-8 body source text without parsing JSON. Exact configured credentials and Secretlint findings are replaced with reversible opaque placeholders. `sec_…` placeholders are bound to authenticated subject and service; valid existing `gref_…` placeholders may be reused for configured credentials.

`gref_` and `sec_` are reserved prefixes. Only live tokens owned by the current subject/service pass through. Invalid candidates are themselves wrapped in `sec_…` and produce sanitized audit warnings.

Whole Base64 bodies are decoded and scanned only when declared with `Content-Transfer-Encoding: base64`. Cookie headers are prohibited on the proxied surface. Scanning is bounded and fails closed.

Response metadata reports `secret_tokenized` and `secret_tokenization_count`.

## 21. Request and response limits

MVP must support configurable limits:

* max request body size
* max response body size
* max response header size
* request timeout

Example defaults:

```yaml
limits:
  max_request_body: 1mb
  max_response_body: 5mb
  timeout: 30s
```

If a response exceeds the configured size, the server must truncate or reject it according to configuration.

Default behavior should be truncate with explicit metadata or reject with a structured error.

## 22. Audit logging

The server must audit:

* authenticated subject
* MCP client/session ID if available
* service
* destination
* reference request reason
* request reason
* access IDs used
* internal reference ID, not raw reference value
* method
* target host
* target path
* policy decision
* matched policy rule
* downstream status code
* request timestamp
* request duration
* TLS verification mode
* response tokenization count and matched rule IDs
* error details if denied or failed

Audit logs must not include:

* raw credentials
* raw opaque reference values
* full Authorization headers
* full request body by default
* full response body by default

Optional debug logging may include bodies only if explicitly enabled and clearly marked unsafe.

## 23. Error handling

Errors must be structured.

Example:

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Request denied by policy.",
    "request_id": "req_123"
  }
}
```

Required error codes:

```text
unauthenticated
unauthorized_service
unknown_service
unknown_destination
unknown_access
reference_expired
reference_invalid
destination_not_allowed
host_not_allowed
scheme_not_allowed
port_not_allowed
policy_denied
tls_error
downstream_timeout
downstream_error
request_too_large
response_too_large
config_error
```

Denied requests must return a request ID suitable for `explain_denial`.

## 24. Explain denial behavior

When a request is denied, the server must store enough denial context for `explain_denial`.

`explain_denial` should return:

* request ID
* denial reason
* matched rule
* policy mode
* suggestion, if available

Example:

```json
{
  "request_id": "req_123",
  "reason": "DELETE requests are blocked for this service.",
  "matched_rule": "deny-delete",
  "policy_mode": "deny",
  "suggestion": "Use GET to inspect the resource or ask the user to update policy."
}
```

The suggestion must not recommend bypassing host, token, or policy controls.

## 25. Configuration

## 25.1 Format

MVP configuration should be file-based.

Supported format:

```text
YAML
```

## 25.2 Example configuration

```yaml
server:
  listen: 0.0.0.0:8080
  mcp_path: /mcp

auth:
  oauth:
    issuer: https://auth.example.com
    audience: secretsauce
    client_id: secretsauce
    required_scopes:
      - gateway.read
      - gateway.references
      - gateway.request

tokens:
  idle_ttl: 10m
  max_ttl: 1h

limits:
  max_request_body: 1mb
  max_response_body: 5mb
  timeout: 30s

services:
  portainer-prod:
    type: http
    name: Portainer Production
    description: Main Portainer instance

    destinations:
      - name: primary
        base_url: https://portainer.example.org:9443
        schemes: [https]
        hosts:
          - exact: portainer.example.org
          - regex: '^[a-z0-9-]+\.portainer\.example\.org$'
        ports: [9443]

    tls:
      verify: false

    credentials:
      - id: api_key
        usage:
          kind: header
          name: X-API-Key
          prefix: "Bearer "
          enforce: true
        source:
          kind: env
          name: PORTAINER_API_KEY

    access:
      users:
        - henric@example.com

    policy:
      mode: deny
      rules:
        - id: allow-stack-read
          effect: allow
          priority: 100
          methods: [GET]
          paths:
            - /api/stacks.*
            - /api/endpoints.*

        - id: deny-delete
          effect: deny
          priority: 1000
          methods: [DELETE]
          paths:
            - /.*
```

## 26. Secret sources

MVP must support:

* environment variable
* mounted file / Docker secret

Environment example:

```yaml
source:
  kind: env
  name: PORTAINER_API_KEY
```

File example:

```yaml
source:
  kind: file
  path: /run/secrets/portainer_api_key
```

Out of scope for MVP:

* built-in KMS integration
* built-in Vault integration
* built-in 1Password integration
* built-in Portainer secret integration

These can be added later through pluggable secret providers.

## 27. Docker deployment

MVP must provide a Docker image.

Required:

* containerized server
* config mounted read-only
* secrets provided through env vars or mounted files
* health check endpoint
* structured logs to stdout

Example Docker Compose:

```yaml
services:
  secretsauce:
    image: secretsauce-mcp:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      - ./secrets:/run/secrets:ro
    environment:
      CONFIG_PATH: /config/config.yaml
      PORTAINER_API_KEY_FILE: /run/secrets/portainer_api_key
```

## 28. Codex configuration

Documentation must include an OpenAI Codex config example.

OAuth example:

```toml
[mcp_servers.secretsauce]
url = "https://gateway.example.org/mcp"
enabled = true
default_tools_approval_mode = "prompt"
tool_timeout_sec = 60

[mcp_servers.secretsauce.tools.list_services]
approval_mode = "auto"

[mcp_servers.secretsauce.tools.get_gateway_service_references]
approval_mode = "prompt"

[mcp_servers.secretsauce.tools.service_request]
approval_mode = "prompt"

[mcp_servers.secretsauce.tools.explain_denial]
approval_mode = "auto"
```

Bearer-token development example:

```toml
[mcp_servers.secretsauce]
url = "https://gateway.example.org/mcp"
bearer_token_env_var = "SECRETSAUCE_MCP_TOKEN"
enabled = true
default_tools_approval_mode = "prompt"
```

Documentation must explain:

* how to add the MCP server to Codex CLI
* how to run OAuth login
* how to verify the server appears in Codex MCP list
* how ChatGPT desktop uses the shared Codex MCP host configuration
* why ChatGPT web requires a separate hosted/plugin integration path

## 29. OpenAI approval behavior

Recommended defaults:

```toml
[mcp_servers.secretsauce]
default_tools_approval_mode = "prompt"

[mcp_servers.secretsauce.tools.list_services]
approval_mode = "auto"

[mcp_servers.secretsauce.tools.describe_service_policy]
approval_mode = "auto"

[mcp_servers.secretsauce.tools.explain_denial]
approval_mode = "auto"

[mcp_servers.secretsauce.tools.get_gateway_service_references]
approval_mode = "prompt"

[mcp_servers.secretsauce.tools.service_request]
approval_mode = "prompt"
```

Users who want stricter control may configure:

```toml
[mcp_servers.secretsauce.tools.service_request]
approval_mode = "approve"
```

Users who want less friction may configure broader auto-approval, but this is not the recommended default.

Client approval prompts are not a server-side security boundary.

## 30. Security requirements

## 30.1 Raw credential handling

The server must never return raw configured credential values through MCP tools.

The server must not log raw credentials.

The server must replace raw configured credentials and detected response secrets with scoped opaque references.

## 30.2 Destination binding

Credential substitution must only happen if the request target matches the configured service destination.

A Portainer token must not materialize for OPNsense, OpenAI, arbitrary internet hosts, or any unconfigured host.

## 30.3 User/session binding

Gateway service references must not be reusable across authenticated users.

## 30.4 Policy enforcement

Policy must be evaluated before credential substitution.

If policy denies the request, the downstream request must not be sent.

## 30.5 Redirect safety

Credentials must not be sent to redirected hosts.

## 30.6 TLS visibility

If TLS verification is disabled, response metadata and audit logs must record that fact.

## 30.7 OpenAI annotations are not security controls

Tool annotations such as `readOnlyHint`, `destructiveHint`, `openWorldHint`, and `idempotentHint` are client hints only.

The gateway must enforce all security controls server-side.

## 31. Observability

MVP must provide:

* structured JSON logs
* health endpoint
* startup config validation errors
* audit log stream or file
* request IDs

Nice to have:

* Prometheus metrics

Possible metrics:

```text
requests_total
denied_requests_total
downstream_errors_total
token_requests_total
active_tokens
response_secret_tokenizations_total
tls_verify_disabled_requests_total
```

## 32. Admin/config validation

On startup, the server must validate:

* YAML syntax
* duplicate service IDs
* duplicate destination IDs within a service
* duplicate credential IDs within a service
* invalid regexes
* invalid base URLs
* missing secret sources
* unsupported TLS config
* unsupported policy mode
* invalid policy rules
* broad host regex warnings
* missing OAuth configuration when OAuth is enabled
* invalid token TTL settings
* invalid size limit settings

Configuration errors should fail startup with clear messages.

Broad host regexes may warn instead of failing startup in MVP.

## 33. Acceptance criteria

MVP is complete when:

1. A Dockerized MCP server can start with a YAML config.
2. The server exposes a Streamable HTTP MCP endpoint.
3. OAuth authentication is required in production mode.
4. Bearer-token auth is available for development/simple mode, if implemented.
5. An authenticated Codex CLI session can connect to the MCP server.
6. `codex mcp login <server-name>` works for OAuth mode.
7. Codex can read server initialization instructions.
8. Codex can discover exactly five tools:

   * `list_services`
   * `describe_service_policy`
   * `get_gateway_service_references`
   * `service_request`
   * `explain_denial`
9. Tool descriptors include `inputSchema`.
10. Tools returning structured results include `outputSchema`.
11. Tool descriptors include `securitySchemes`.
12. Tool descriptors mirror `securitySchemes` under `_meta.securitySchemes`.
13. Tool descriptors include appropriate annotations.
14. `list_services`, `describe_service_policy`, and `explain_denial` are marked read-only.
15. `service_request` is marked as potentially destructive and open-world.
16. An authenticated agent can list available services.
17. An authenticated agent can request an opaque service reference with a reason.
18. The reference response contains no raw credential.
19. The agent can make an allowed HTTP request through the MCP server.
20. The server substitutes the opaque reference with the real credential only for a matching service destination.
21. The server denies a request to an unconfigured host.
22. The server denies a request blocked by policy.
23. The server denies expired references.
24. The server denies references bound to another user/service/destination.
25. The server supports `tls.verify: false`.
26. The server records disabled TLS verification in response metadata and audit logs.
27. The server tokenizes configured credentials and Secretlint findings in response headers and body source text.
28. Audit logs are written for reference requests and service requests.
29. Audit logs do not contain raw credentials or raw opaque reference values.
30. Denied requests include request IDs and explainable denial reasons.
31. `explain_denial` returns useful denial context.
32. Configuration errors fail startup with clear messages.
33. Documentation includes Codex CLI setup.
34. Documentation includes ChatGPT desktop setup.
35. Documentation states that ChatGPT web requires hosted/plugin integration and does not read local Codex config.

## 34. Suggested MVP implementation order

### Phase 1: Core server

* MCP server skeleton
* Streamable HTTP transport
* config loading
* config validation
* Docker image
* health endpoint

### Phase 2: OpenAI MCP descriptors

* initialization instructions
* four tool registrations
* input schemas
* output schemas
* security schemes
* `_meta.securitySchemes`
* annotations
* structured tool results

### Phase 3: Auth

* OAuth verification
* authenticated subject extraction
* bearer-token dev mode, if included
* service access checks

### Phase 4: Service registry

* service listing
* destination parsing
* host matching
* scheme validation
* port validation
* TLS verify true/false

### Phase 5: Token broker

* reference request tool
* reference generation
* reference TTL
* reference binding
* reference expiration
* reason logging

### Phase 6: HTTP request tool

* service-scoped request execution
* header/body/query reference substitution
* deny unknown/invalid/expired references
* no cross-service token use
* no cross-destination token use unless configured

### Phase 7: Policy engine

* mode: deny/allow
* priority rules
* methods
* paths
* hosts
* deny wins ties

### Phase 8: Response tokenization and audit

* exact configured-credential and Secretlint response tokenization
* structured audit logs
* request IDs
* explain denial tool

### Phase 9: Hardening

* response size limits
* request timeouts
* redirect handling
* broad regex warnings

### Phase 10: Documentation

* Docker Compose example
* YAML config reference
* Codex config example
* OAuth setup
* ChatGPT desktop setup
* ChatGPT web limitation
* self-signed TLS guidance
* approval mode guidance

## 35. Future features

* certificate fingerprint pinning
* custom CA bundle support
* trust-on-first-use certificate pinning
* approval workflow for dangerous requests
* service profile packs
* Portainer profile
* OPNsense profile
* Proxmox profile
* TrueNAS profile
* Home Assistant profile
* role-based access control
* group-based access control
* pluggable secret providers
* Vault integration
* 1Password integration
* AWS/GCP/Azure KMS integrations
* URL-encoded response-secret decoding
* OpenAPI-based policy generation
* request diff previews
* dry-run support where downstream APIs support it
* web admin UI
* Prometheus metrics
* signed audit log
* append-only audit log backend
* per-service rate limits
* per-user rate limits
* ChatGPT web hosted/plugin integration

## 36. Open questions

1. Which OAuth provider should be supported first?
2. Should bearer-token auth be included in MVP or only documented as a dev-only shortcut?
3. Should token values include service/credential hints, or should they be fully opaque random strings?
4. Should request bodies ever be logged in debug mode?
5. Should query strings be included in path policy matching for MVP?
6. Should absolute URLs be accepted in MVP immediately, or gated behind a config flag?
7. Should `tls.verify: false` require an explicit `unsafe: true` flag?
8. Should oversized responses be truncated by default or rejected?
9. Should policy rules use regex only, glob syntax, or both?
10. Should path matching include query parameters in MVP?
11. Should host regex broadness warnings be warnings only or fatal in strict mode?
12. Should the gateway support multiple credentials per request in MVP?
13. Should token issuance itself be policy-controlled beyond user/service/credential access?
14. Should ChatGPT web hosted/plugin support be MVP or post-MVP?
15. What should the project name be?

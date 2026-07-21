# SecretSauce Configuration Reference

The gateway uses a primary YAML file plus a Secretlint rules YAML, both mounted read-only in Docker. Secrets are not stored in either file; use environment variables or mounted files.

## Server
- `server.listen`: bind address in `host:port` form, for example `0.0.0.0:8080`.
- `server.mcp_path`: Streamable HTTP MCP path, usually `/mcp`.
- `server.resource`: public resource URL used in OAuth metadata and challenges.

## Auth
Production OAuth mode:

```yaml
auth:
  mode: oauth
  oauth:
    issuer: https://auth.example.com
    audience: secretsauce
    jwks_uri: https://auth.example.com/.well-known/jwks.json
    principal_claim: sub
    required_scopes:
      - gateway.read
      - gateway.references
      - gateway.request
```

Development bearer mode:

```yaml
auth:
  mode: bearer
  bearer:
    token_env: SECRETSAUCE_MCP_TOKEN
```

Bearer mode is simpler and useful for local deployments, but OAuth is the production path.

`auth.oauth.principal_claim` defaults to `sub`. The selected claim must be a non-empty string and becomes the subject used by service ACLs and opaque-reference binding. Client-credentials issuers may select a stable claim such as `client_id`; tokens missing the configured claim are rejected and never share a fallback identity.

Built-in OAuth mode for a private ChatGPT-hosted MCP:

```yaml
server:
  resource: https://mcp.example.org

auth:
  mode: builtin_oauth
  builtin_oauth:
    issuer: https://mcp.example.org
    admin_username_env: SECRETSAUCE_ADMIN_USERNAME
    admin_password_hash_env: SECRETSAUCE_ADMIN_PASSWORD_HASH
    signing_key_file: /run/secrets/oauth_signing_key.pem
    access_token_ttl: 1h
    authorization_code_ttl: 5m
    refresh_token_idle_ttl: 30d
    refresh_token_max_ttl: 90d
    refresh_token_store_file: /var/lib/secretsauce/oauth/refresh-state.json
    allowed_clients:
      - https://chatgpt.com
    required_scopes:
      - gateway.read
      - gateway.references
      - gateway.request
```

`builtin_oauth` is intended for a private single-admin deployment. It publishes authorization server discovery from this gateway, accepts ChatGPT's CIMD public-client flow with PKCE, and issues JWT access tokens plus rotating opaque refresh tokens for the MCP resource. Refresh tokens are bound to the authorized client, resource, subject, and scope ceiling. Reusing a rotated token revokes its active family. Store `SECRETSAUCE_ADMIN_PASSWORD_HASH` as `pbkdf2-sha256$iterations$saltBase64url$hashBase64url`, not as a raw password. The signing key file must contain an RSA private key PEM and must be mounted from stable storage. If the signing key is regenerated inside an ephemeral container, existing ChatGPT OAuth access tokens become invalid after every restart.

The consent page verifies the allowlisted HTTPS client metadata document, its exact `client_id`, and the requested redirect URI before displaying credential fields. When verified metadata contains a non-empty `client_name` of at most 120 characters, the page uses it to identify the requesting client; otherwise it displays the neutral name “MCP client.” Technical OAuth values remain available under “Connection details.”

Client metadata retrieval never follows redirects and connects only to a DNS-resolved, pinned public address while retaining HTTPS hostname verification. Loopback, private, link-local, multicast, unspecified, documentation, and other special-use IPv4/IPv6 ranges are rejected. Responses must be JSON, are limited to 5 KiB and five seconds, and are cached only when HTTP freshness permits (at most one hour) in a 1,000-entry LRU. Origin entries in `allowed_clients` continue to authorize metadata paths on that origin; exact entries authorize only that URL. Fetches are limited by `limits.max_oauth_client_metadata_inflight` (default `4`) and `limits.max_oauth_client_metadata_inflight_per_origin` (default `2`).

Durations accept `ms`, `s`, `m`, `h`, and `d`. Refresh grants expire after 30 days without use and after 90 days regardless of use by default; both values are configurable, and the idle lifetime must not exceed the maximum lifetime.

Password verification uses asynchronous PBKDF2 so expensive login checks do not block MCP traffic or health checks. At most `limits.max_password_verifications` checks run globally (default `2`) and `limits.max_password_verifications_per_source` per direct socket address (default `1`); excess checks receive `429` before PBKDF2 starts.

Built-in login failures are limited over a 15-minute window to 10 per direct source, 10 per account, and 100 globally. Lockouts start at 15 minutes and double on repetition up to one hour. Override these values under `auth.builtin_oauth.login_rate_limit`; forwarding headers are ignored and failures never log submitted usernames or passwords.
Built-in authorization codes are isolated per gateway configuration and capped by `limits.max_authorization_codes` (default `1000`). Expired codes are reaped before allocation and during state maintenance; capacity rejects new authorization with `429` without disturbing live codes.
Built-in refresh-token hashes and grant metadata are capped by `limits.max_refresh_token_records` (default `10000`). Expired grants are reaped during token operations and state maintenance. Set `refresh_token_store_file` to a stable writable path to preserve refresh grants, rotations, and replay detection across restarts. The versioned state file contains hashes and grant metadata, never raw tokens, and is replaced atomically with mode `0600`. A malformed or unreadable configured file prevents startup, and a failed token-operation write returns `temporarily_unavailable` without returning new credentials. The file supports one gateway process at a time.

If `refresh_token_store_file` is omitted, refresh state remains in memory and the server emits `oauth.refresh_state_ephemeral` at startup. Access tokens signed by a stable key remain valid across restarts, but clients must reauthorize when they next need to refresh.

## Logging
`logging.level` defaults to `info`. Set it to `debug` while setting up the MCP server to emit sanitized structural diagnostics and response-tokenization counts.

Debug logs are sanitized before writing. They do not include raw credentials, opaque reference values, Authorization headers, cookies, request bodies, or response bodies.

```yaml
logging:
  level: debug
```

## Audit
Recent audit events are kept in a per-configuration memory ring and can also be written as append-only JSONL:

```yaml
audit:
  memory_events: 1000
  file: /var/lib/secretsauce/audit/audit.jsonl
```

`audit.memory_events` defaults to 1000 and bounds only the in-memory view; file-backed JSONL retains every successfully written event. Mount the audit directory on persistent writable storage in Docker. Audit events are sanitized and do not include raw credentials, opaque reference values, Authorization headers, cookies, request bodies, or downstream response bodies. Opaque downstream access references are still in-memory only and expire on restart.

Expired configured-access and response-secret reference records are removed before issuance and by the periodic state maintenance loop; all reference hashes, indexes, and in-memory values are removed together.
`limits.max_token_records` defaults to 10000 and `limits.max_token_records_per_subject` to 1000. Both configured-access and response-secret capabilities count toward these limits. Live references are never silently evicted; issuance fails atomically with `capacity_exceeded`.

## Services
Each service defines LLM-facing metadata, destinations, credentials, access users, TLS behavior, and policy. `description` should briefly explain what the service is for. `api_docs_url` may point to human or machine-readable API documentation, such as an OpenAPI JSON file; the gateway exposes the URL but does not fetch or proxy it.

Destination host matchers may be exact names, DNS suffixes, or regular expressions. A suffix is matched on DNS-label boundaries and includes its apex: `suffix: example.org` and `suffix: .example.org` both allow `example.org` and `api.example.org`, but never `attackerexample.org`. Suffixes are IDN-canonicalized and cannot be IP literals; use an exact matcher for an IP address.

```yaml
services:
  example-api:
    type: http
    name: Example API
    description: Inventory and deployment metadata API
    api_docs_url: https://api.example.org/openapi.json
```

Credential sources support:

```yaml
source:
  kind: env
  name: SERVICE_API_KEY
```

```yaml
source:
  kind: file
  path: /run/secrets/service_api_key
```

Services whose downstream API intentionally requires no authentication must opt in explicitly with `no_auth: true` and omit `credentials`:

```yaml
services:
  camera-api:
    type: http
    name: Camera API
    no_auth: true
    destinations:
      - name: primary
        base_url: http://camera.example.org
    access:
      users:
        - operator@example.org
    policy:
      mode: deny
      rules:
        - id: allow-status
          effect: allow
          priority: 100
          methods: [GET]
          paths: ["/api/status"]
```

Omitting credentials without `no_auth: true` fails startup, as does combining the flag with credentials. SecretSauce still exposes `gateway_access` for this service: clients obtain a normal `gref_` and pass it as `service_request.service_reference`. The gateway validates and consumes that field without forwarding it downstream. `no_auth` disables only downstream credential substitution; gateway authentication, user access controls, destination validation, request policy, TLS settings, auditing, and response protection remain enforced.

`policy.mode` defaults to `deny`. Rules use regex path patterns in MVP.

Endpoint rules may selectively disable response scanning:

```yaml
policy:
  rules:
    - id: allow-status
      effect: allow
      priority: 100
      methods: [GET]
      paths: ["/api/status"]
      secretlint:
        disabled_rules:
          - "@secretlint/secretlint-rule-github"
```

Use `secretlint: { enabled: false }` to disable all Secretlint rules for a matched endpoint. These settings never disable sensitive-name protection, exact configured-credential protection, forged opaque-prefix protection, cookie handling, Base64 validation, or framing normalization.

## Secretlint Rules

`SECRETLINT_CONFIG_PATH` defaults to `/config/secretlint.yaml`. The file uses:

```yaml
version: 1
mode: extend
limits:
  max_unique_secrets: 100
  timeout: 5s
rules:
  - id: "@secretlint/secretlint-rule-github"
  - id: "@secretlint/secretlint-rule-pattern"
    options:
      patterns:
        - name: custom-key
          patterns: ["/(?<key>custom_[A-Za-z0-9_-]+)/g"]
```

`extend` overlays entries on the bundled strict catalog; `replace` uses only the listed rules. Unknown packages, duplicate IDs, invalid patterns, and invalid limits stop startup.

Scanner capacity defaults to `min(4, availableParallelism)` workers, a 32-job global queue, and one active plus four queued scans per subject. Override these with `SECRETLINT_WORKERS`, `SECRETLINT_QUEUE_MAX`, `SECRETLINT_SUBJECT_ACTIVE_MAX`, `SECRETLINT_SUBJECT_QUEUE_MAX`, and `SECRETLINT_QUEUE_TIMEOUT_MS`.

Secretlint's own dependency diagnostics are disabled by default, even when the gateway process uses a broad `DEBUG` value such as `DEBUG=*`. Set `SECRETLINT_DEBUG=true` to enable only the Secretlint debug namespaces temporarily. This output is verbose and is separate from the gateway's structured `logging.level` setting; unset the variable or set it to `false` during normal operation.

## Sensitive Name Rules

`SENSITIVE_NAMES_CONFIG_PATH` defaults to `/config/sensitive-names.yaml`. Name detection is separate from Secretlint and uses this strict schema:

```yaml
version: 1
mode: extend
allow_patterns: []
patterns:
  - id: passwords
    regex: "(?:^|_)(?:password|passwd|passphrase)(?:_|$)"
```

All patterns are compiled case-insensitively. Candidate names first gain camel-case boundaries and have non-alphanumeric separators converted to `_`. `extend` starts with the bundled catalog, replaces a bundled pattern with the same ID, and appends new IDs and allow patterns. `replace` uses only the supplied patterns and allows, including an empty catalog. If any allow pattern matches a name, it suppresses all sensitive-name findings for that name. Duplicate IDs, unknown fields, invalid or empty regexes, and values outside the catalog bounds stop startup.

The bundled catalog conservatively covers passwords, secrets, credentials, authorization, qualified API authentication, qualified private/signing/API/access keys, qualified access/refresh/session/ID tokens, connection strings, database URLs, and DSNs. For example, `SERVICE_API_AUTH` is sensitive, while bare or descriptive fields such as `auth`, `auth_mode`, `auth_type`, and `api_authority` remain visible. Bare `key`, `token`, `signing`, `hash`, `_B64`, `_BASE64`, and `_PEM` are not sensitive on their own. For example, `public_key`, `key_id`, `signing_algorithm`, and `token_type` remain visible unless an operator adds a pattern.

For JSON and JSON-like response source text, matching applies to complete, non-empty double-quoted values in direct properties, objects with one string `name` or `key` property and one string `value` property, and complete `NAME=value` JSON strings. The scanner tolerates comments, duplicate keys, trailing or missing commas, and truncated outer containers. It replaces only the original value-content ranges; order, whitespace, duplicate keys, comments, and all bytes outside those ranges are retained. Numbers, booleans, objects, empty strings, single-quoted strings, and unquoted keys are not selected by sensitive names. A recognized sensitive string without a safe closing range fails closed with `secret_scan_failed`.

Independently of Secretlint and sensitive-name matching, response headers and bodies protect HTTP Basic credentials whose case-insensitive `Basic ` scheme is followed by canonical Base64 that decodes to a non-empty `username:password`. The complete scheme and encoded credential are replaced under the `gateway:http-basic-credential` rule ID. Malformed or noncanonical Base64, decoded values without a colon, and empty usernames or passwords are not selected by this detector.

## Proxied HTTP Constraints

- `limits.max_inbound_body` defaults to `1mb` and is enforced while reading authenticated MCP POST bodies and both built-in OAuth form endpoints, including chunked requests and inaccurate `Content-Length` values. Oversize requests receive `413` before JSON or form parsing and cannot consume an authorization code.
- `limits.inbound_body_timeout` defaults to `10s`. Incomplete MCP or OAuth bodies receive `408`, and their connections are closed without parsing partial input.
- Built-in OAuth permits at most `limits.max_unauthenticated_inflight` body readers globally (default `32`) and `limits.max_unauthenticated_inflight_per_source` per direct socket address (default `4`). Excess work receives `429`; forwarding headers never select the limiter identity.
- Denial explanations are kept in a per-configuration TTL/LRU store. `limits.max_denial_records` defaults to `1000`, `limits.denial_ttl` to `15m`, and `limits.state_sweep_interval` to `1m`.
- MCP HTTP is stateless. Each POST creates a short-lived server transport, authenticates the bearer token independently, returns a JSON response, and releases the transport. The gateway does not issue or require `Mcp-Session-Id`; GET and DELETE on the MCP path return `405`. Gateway service references remain usable across independent requests because they are bound to the authenticated subject and service rather than transport state.

  Deployments upgrading from the former stateful transport must remove `limits.max_mcp_transports`, `limits.max_mcp_transports_per_subject`, `limits.max_mcp_initializations_per_subject`, `limits.mcp_initialization_window`, `limits.max_mcp_initialization_records`, and `limits.mcp_transport_idle_ttl`. These fields now produce a startup error with migration guidance. Reference capacity remains controlled by `limits.max_token_records` and `limits.max_token_records_per_subject`; exhaustion is returned as a structured `capacity_exceeded` tool error, not an MCP transport `429`.
- Caller-supplied HTTP authority, forwarding, and hop-by-hop headers are rejected before credential substitution. This includes `Host`, `:authority`, `Forwarded`, every `X-Forwarded-*` header, `Connection`, `Keep-Alive`, proxy authorization headers, `TE`, `Trailer`, `Transfer-Encoding`, and `Upgrade`. The outbound `Host` header is derived from the validated destination URL.
- Destination paths are canonicalized once before policy evaluation and downstream transmission. Duplicate separators and trailing separators are removed. Percent escapes for ASCII unreserved characters, separators, backslashes, NUL, and percent itself are rejected because downstream routers may decode them differently; encoded UTF-8 data and spaces remain supported. Query parameters are not part of path-policy matching.
- `Cookie`, `Cookie2`, `Set-Cookie`, and `Set-Cookie2` are prohibited. Request occurrences are rejected; response occurrences are removed with sanitized warnings.
- Caller-supplied `Content-Length` is discarded and recomputed after request substitution and response transformation.
- `Content-Transfer-Encoding: base64` declares a whole Base64 response or string request body. Declared bodies are decoded before sensitive-name scanning or opaque-token substitution and canonically re-encoded afterward; field-level Base64/PEM values are not decoded. Undeclared Base64-looking content remains opaque. Other or conflicting transfer encodings fail closed.
- `limits.max_response_body` is enforced during the downstream network read. Declared or streamed oversize responses are aborted and return `response_too_large`; partial bodies are never scanned or returned.
- Ordinary and decoded Base64 response bodies, and decoded Base64 request bodies, must be valid UTF-8.

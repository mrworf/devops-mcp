# Config Reference

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
    audience: agent-credential-gateway
    jwks_uri: https://auth.example.com/.well-known/jwks.json
    required_scopes:
      - gateway.read
      - gateway.tokens
      - gateway.request
```

Development bearer mode:

```yaml
auth:
  mode: bearer
  bearer:
    token_env: AGENT_GATEWAY_MCP_TOKEN
```

Bearer mode is simpler and useful for local deployments, but OAuth is the production path.

Built-in OAuth mode for a private ChatGPT-hosted MCP:

```yaml
server:
  resource: https://mcp.example.org

auth:
  mode: builtin_oauth
  builtin_oauth:
    issuer: https://mcp.example.org
    admin_username_env: AGENT_GATEWAY_ADMIN_USERNAME
    admin_password_hash_env: AGENT_GATEWAY_ADMIN_PASSWORD_HASH
    signing_key_file: /run/secrets/oauth_signing_key.pem
    access_token_ttl: 1h
    authorization_code_ttl: 5m
    allowed_clients:
      - https://chatgpt.com
    required_scopes:
      - gateway.read
      - gateway.tokens
      - gateway.request
```

`builtin_oauth` is intended for a private single-admin deployment. It publishes authorization server discovery from this gateway, accepts ChatGPT's CIMD public-client flow with PKCE, and issues JWT access tokens for the MCP resource. Store `AGENT_GATEWAY_ADMIN_PASSWORD_HASH` as `pbkdf2-sha256$iterations$saltBase64url$hashBase64url`, not as a raw password. The signing key file must contain an RSA private key PEM and must be mounted from stable storage. If the signing key is regenerated inside an ephemeral container, existing ChatGPT OAuth tokens become invalid after every restart.

Password verification uses asynchronous PBKDF2 so expensive login checks do not block MCP traffic or health checks. At most `limits.max_password_verifications` checks run globally (default `2`) and `limits.max_password_verifications_per_source` per direct socket address (default `1`); excess checks receive `429` before PBKDF2 starts.

Built-in login failures are limited over a 15-minute window to 10 per direct source, 10 per account, and 100 globally. Lockouts start at 15 minutes and double on repetition up to one hour. Override these values under `auth.builtin_oauth.login_rate_limit`; forwarding headers are ignored and failures never log submitted usernames or passwords.

## Logging
`logging.level` defaults to `info`. Set it to `debug` while setting up the MCP server to emit sanitized structural diagnostics and response-tokenization counts.

Debug logs are sanitized before writing. They do not include raw credentials, opaque token values, Authorization headers, cookies, request bodies, or response bodies.

```yaml
logging:
  level: debug
```

## Audit
Audit events are kept in memory for the current process and can also be written as append-only JSONL:

```yaml
audit:
  file: /var/lib/agent-credential-gateway/audit/audit.jsonl
```

Mount the audit directory on persistent writable storage in Docker. Audit events are sanitized and do not include raw credentials, opaque token values, Authorization headers, cookies, request bodies, or downstream response bodies. Opaque downstream credential tokens are still in-memory only and expire on restart.

## Services
Each service defines LLM-facing metadata, destinations, credentials, access users, TLS behavior, and policy. `description` should briefly explain what the service is for. `api_docs_url` may point to human or machine-readable API documentation, such as an OpenAPI JSON file; the gateway exposes the URL but does not fetch or proxy it.

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

Use `secretlint: { enabled: false }` to disable all Secretlint rules for a matched endpoint. These settings never disable exact configured-credential protection, forged opaque-prefix protection, cookie handling, Base64 validation, or framing normalization.

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

## Proxied HTTP Constraints

- `limits.max_inbound_body` defaults to `1mb` and is enforced while reading authenticated MCP POST bodies and both built-in OAuth form endpoints, including chunked requests and inaccurate `Content-Length` values. Oversize requests receive `413` before JSON or form parsing and cannot consume an authorization code.
- `limits.inbound_body_timeout` defaults to `10s`. Incomplete MCP or OAuth bodies receive `408`, and their connections are closed without parsing partial input.
- Built-in OAuth permits at most `limits.max_unauthenticated_inflight` body readers globally (default `32`) and `limits.max_unauthenticated_inflight_per_source` per direct socket address (default `4`). Excess work receives `429`; forwarding headers never select the limiter identity.
- Caller-supplied HTTP authority, forwarding, and hop-by-hop headers are rejected before credential substitution. This includes `Host`, `:authority`, `Forwarded`, every `X-Forwarded-*` header, `Connection`, `Keep-Alive`, proxy authorization headers, `TE`, `Trailer`, `Transfer-Encoding`, and `Upgrade`. The outbound `Host` header is derived from the validated destination URL.
- `Cookie`, `Cookie2`, `Set-Cookie`, and `Set-Cookie2` are prohibited. Request occurrences are rejected; response occurrences are removed with sanitized warnings.
- Caller-supplied `Content-Length` is discarded and recomputed after request substitution and response transformation.
- `Content-Transfer-Encoding: base64` declares a whole Base64 response body. Other transfer encodings fail closed.
- `limits.max_response_body` is enforced during the downstream network read. Declared or streamed oversize responses are aborted and return `response_too_large`; partial bodies are never scanned or returned.
- Ordinary and decoded Base64 response bodies must be valid UTF-8.

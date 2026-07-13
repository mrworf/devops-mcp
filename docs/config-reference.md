# Config Reference

The gateway uses one YAML file, mounted read-only in Docker. Secrets are not stored in the config; use environment variables or mounted files.

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
  resource: https://mcp-devops.sensenet.nu

auth:
  mode: builtin_oauth
  builtin_oauth:
    issuer: https://mcp-devops.sensenet.nu
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

`builtin_oauth` is intended for a private single-admin deployment. It publishes authorization server discovery from this gateway, accepts ChatGPT's CIMD public-client flow with PKCE, and issues JWT access tokens for the MCP resource. Store `AGENT_GATEWAY_ADMIN_PASSWORD_HASH` as `pbkdf2-sha256$iterations$saltBase64url$hashBase64url`, not as a raw password. The signing key file must contain an RSA private key PEM.

## Logging
`logging.level` defaults to `info`. Set it to `debug` while setting up the MCP server to emit structured setup diagnostics such as MCP method names, required scopes, service IDs, destination IDs, target hosts and paths, TLS verification state, status codes, durations, and redaction counts.

Debug logs are sanitized before writing. They do not include raw credentials, opaque token values, Authorization headers, cookies, request bodies, or response bodies.

```yaml
logging:
  level: debug
```

## Services
Each service defines destinations, credentials, access users, TLS behavior, and policy. Credential sources support:

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

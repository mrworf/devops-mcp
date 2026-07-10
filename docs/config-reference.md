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

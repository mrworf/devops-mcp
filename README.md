<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/secretsauce-primary-docs-dark.png">
    <img src="assets/brand/secretsauce-primary.png" alt="SecretSauce MCP — Give agents access, not secrets" width="900">
  </picture>
</h1>

[![CI](https://github.com/mrworf/secretsauce-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mrworf/secretsauce-mcp/actions/workflows/ci.yml)
[![Docker image](https://img.shields.io/badge/GHCR-secretsauce--mcp-2ea44f?logo=github)](https://github.com/mrworf/secretsauce-mcp/pkgs/container/secretsauce-mcp)

SecretSauce is a self-hosted MCP service that lets Codex, ChatGPT-compatible MCP clients, and other supported agents call configured HTTP services while keeping raw configured credentials out of the normal request flow. Credential substitution and response protection happen in the gateway backend; they do not depend on the agent recognizing secrets or keeping them confidential. Response protection is defense in depth, not a guarantee against arbitrary computation performed by an admin-approved downstream endpoint.

The service acts as an MCP-controlled credential gateway. Agents get short-lived gateway service references, then use those references in approved service requests. The gateway enforces authentication, destination validation, reference binding, and policy before substituting protected backend values and making the downstream HTTP call. It also scans downstream responses and replaces detected secrets with opaque references before returning the response to the agent.

> [!IMPORTANT]
> **Recommended client:** This MCP works with ChatGPT in Chat mode, but Codex or ChatGPT Work mode is recommended for operational and multi-step service workflows. Chat mode may apply platform-level action safety checks that block an otherwise valid action before the tool call reaches this server; in that case, the gateway cannot provide a request ID or explain the denial. Codex and Work mode use agent-oriented security models built around sandboxing, approvals, and tool-specific controls, which are a better fit for these workflows. They are not less secure; they enforce security through a different execution and approval model. See [OpenAI's agent approvals and security documentation](https://learn.chatgpt.com/docs/agent-approvals-security).
>
> The client mode does not weaken this gateway's controls. Authentication, destination validation, policy enforcement, reference binding, protected-value substitution, and auditing remain enforced by the server for every client.

## What It Provides

<img align="right" src="assets/brand/secretsauce-chef.png" alt="SecretSauce chef holding a protected secret recipe" width="150" style="padding: 10px">

- Streamable HTTP MCP endpoint for configured clients.
- A small generic tool surface for listing services, getting gateway service references, making service requests, and explaining denials.
- Server-side credential substitution after auth, destination validation, and policy checks.
- Agent-facing credential reference templates with optional, default-off ownership enforcement for configured authentication headers.
- Default-deny request policy with explainable denials.
- Secretlint response scanning plus configurable sensitive-name detection that replaces detected values with reversible, service-scoped `sec_…` tokens.
- Structured audit logging designed to avoid raw credentials, opaque reference values, authorization headers, cookies, and downstream response bodies.
- Docker deployment with a non-root runtime user and healthcheck.

## Safety Model

In the normal supported flow, agents receive opaque references instead of raw API keys, passwords, bearer tokens, cookies, or other configured downstream credentials. Those values remain on the backend while the gateway performs authentication, destination validation, token validation, policy approval, and substitution. These controls do not rely on model instructions, prompt compliance, agent memory, or agent-side redaction.

> [!WARNING]
> **Approved endpoints are part of the credential security boundary.** Response scanning can replace exact configured credentials and recognized secret patterns, but it cannot recognize every reversible transformation. If an allowed downstream endpoint can echo, encode, template, execute, inspect, or otherwise transform caller-controlled input containing an opaque reference, it may return a representation that the caller can reverse into the raw credential. Administrators should allow only the methods and routes the agent needs, prefer narrowly structured non-computational APIs, and avoid generic debug, echo, script, command, template, and proxy endpoints unless this residual risk is explicitly accepted.

The gateway uses two kinds of opaque placeholders:

- `gref_…` references represent configured service access. They are bound to the authenticated subject, originating service, destination, and access entry.
- `sec_…` references represent secrets detected while scanning downstream responses. Detection and replacement happen on the backend before the response reaches the agent, and these references are bound to the authenticated subject and originating service.

Both reference types work only when submitted back through this gateway and expire under configured idle and maximum TTLs. The MCP HTTP transport is stateless: every POST is authenticated independently, and reference continuity comes from authenticated-subject binding rather than an MCP session.

The proxied HTTP surface is deliberately cookie-free: caller-supplied cookie headers are rejected and downstream cookie headers are discarded. APIs that require browser-style cookie sessions are not supported. Response JSON is scanned as source text without deserialization or reserialization. A tolerant lexical scanner uses configurable, case-insensitive name patterns to protect complete string values in direct fields and common environment shapes, including recoverable JSON with comments, duplicate keys, missing commas, or a truncated outer container. A whole response body is decoded and scanned as Base64 only when it declares `Content-Transfer-Encoding: base64`. A string request body with the same declaration is decoded, has opaque references substituted with JSON-safe source edits when applicable, and is canonically re-encoded before delivery; undeclared Base64-looking content and application-specific transformations remain opaque.

Downstream response bodies remain byte-oriented. Likely text is fully scanned even when labeled `application/octet-stream`; clean likely-binary responses up to 100 KiB are returned losslessly as MCP embedded blobs, while protected-data findings and larger binary bodies fail closed by default.

For every downstream request, the gateway validates the authenticated client, requested service, destination, URL, method, reference binding, and configured policy before replacing opaque references with real credentials. If a request is denied, the client can ask for an explanation instead of guessing around policy boundaries.

## Documentation

- [Configuration reference](docs/config-reference.md)
- [Codex and ChatGPT setup](docs/codex-setup.md), including hosted ChatGPT web configuration
- [Security notes](docs/security-notes.md)
- [Branch protection](docs/branch-protection.md)
- [Docker Compose example](docker-compose.example.yaml)
- [Example config](examples/config.yaml)

Codex CLI, the Codex IDE extension, and ChatGPT desktop can use shared Codex MCP configuration. ChatGPT web does not read local Codex MCP configuration; web usage requires a hosted or plugin integration path.

## Container Image

Images are published to GitHub Container Registry:

```text
ghcr.io/mrworf/secretsauce-mcp
```

Package page: [github.com/mrworf/secretsauce-mcp/pkgs/container/secretsauce-mcp](https://github.com/mrworf/secretsauce-mcp/pkgs/container/secretsauce-mcp)

The CI workflow runs `npm ci`, `npm run build`, and `npm test` first. The Docker image job depends on those quality gates, so a failing build or test run prevents image publishing. Pull requests validate the Docker build without pushing an image; pushes to `main` publish the GHCR image.

## Merge Protection

The workflow reports the `quality-gates` check on pull requests. To make failed checks block merges into `main`, configure a GitHub branch protection rule or ruleset that requires `quality-gates` before merging.

## Production HTTPS with HAProxy

Remote production deployments must expose SecretSauce through HTTPS. Put a TLS-terminating reverse proxy such as HAProxy in front of the gateway, keep the gateway's HTTP listener private, and do not publish the backend port directly to untrusted networks. Equivalent TLS reverse proxies are supported; HAProxy is shown here as a compact same-host example:

```haproxy
frontend secretsauce_https
  bind :443 ssl crt /etc/haproxy/certs/mcp.example.org.pem
  mode http
  default_backend secretsauce_backend

backend secretsauce_backend
  mode http
  option httpchk GET /health
  http-check expect status 200
  server secretsauce 127.0.0.1:8080 check
```

The loopback HTTP hop above is acceptable because HAProxy and SecretSauce share a host and the backend listener is not remotely reachable. If the reverse proxy and gateway run on different hosts, protect that hop with TLS or an isolated, authenticated network. Firewall the gateway so only the reverse proxy can reach it.

Configure public OAuth values explicitly with HTTPS. The gateway does not use `Forwarded` or `X-Forwarded-Proto` to infer its public origin:

```yaml
server:
  listen: 127.0.0.1:8080
  mcp_path: /mcp
  resource: https://mcp.example.org

auth:
  mode: oauth
  oauth:
    issuer: https://auth.example.org
    audience: https://mcp.example.org
    jwks_uri: https://auth.example.org/.well-known/jwks.json
    required_scopes:
      - gateway.read
      - gateway.references
      - gateway.request
```

For built-in OAuth, set `auth.builtin_oauth.issuer` to the same public HTTPS origin as `server.resource`. The origin values do not include the MCP path; ChatGPT and other remote clients use the full MCP Server URL `https://mcp.example.org/mcp`.

SecretSauce rejects non-loopback HTTP resource, issuer, and JWKS URLs by default. Exact loopback HTTP URLs remain supported for local development. A trusted development network can explicitly accept cleartext OAuth trust with `server.allow_insecure_oauth_http: true`; this emits one sanitized startup warning. Missing `server.resource` in OAuth mode also remains a startup warning.

## Local Docker Example

```yaml
services:
  secretsauce:
    image: ghcr.io/mrworf/secretsauce-mcp:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      - ./secretlint.yaml:/config/secretlint.yaml:ro
      - ./sensitive-names.yaml:/config/sensitive-names.yaml:ro
      - ./secrets:/run/secrets:ro
      - ./oauth:/run/oauth:ro
      - ./audit:/var/lib/secretsauce/audit
      - ./oauth-state:/var/lib/secretsauce/oauth
    environment:
      CONFIG_PATH: /config/config.yaml
      SECRETLINT_CONFIG_PATH: /config/secretlint.yaml
      SENSITIVE_NAMES_CONFIG_PATH: /config/sensitive-names.yaml
```

Use the writable audit mount for `audit.file`, for example `/var/lib/secretsauce/audit/audit.jsonl`. When using `auth.mode: builtin_oauth`, keep `auth.builtin_oauth.signing_key_file` on stable mounted storage such as `/run/oauth/oauth_signing_key.pem`; changing that key forces clients to reauthenticate. Set `auth.builtin_oauth.refresh_token_store_file` to a stable writable path such as `/var/lib/secretsauce/oauth/refresh-state.json` to preserve hash-only refresh state across restarts. Omitting it keeps refresh grants in memory and requires reauthorization after restart.

Expose the service through an HTTPS endpoint such as `https://gateway.example.org/mcp` when using remote MCP clients.

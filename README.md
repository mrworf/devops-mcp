# Agent Credential Gateway MCP

[![CI](https://github.com/mrworf/devops-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mrworf/devops-mcp/actions/workflows/ci.yml)
[![Docker image](https://img.shields.io/badge/GHCR-agent--credential--gateway--mcp-2ea44f?logo=github)](https://github.com/mrworf/devops-mcp/pkgs/container/agent-credential-gateway-mcp)

`agent-credential-gateway-mcp` is a self-hosted MCP server that lets Codex, ChatGPT-compatible MCP clients, and other supported agents call configured HTTP services without receiving raw configured credentials. Secret isolation is enforced by the gateway backend before content reaches the agent; it does not depend on the agent recognizing secrets or keeping them confidential.

The service acts as an MCP-controlled credential gateway. Agents request temporary opaque tokens, then use those tokens in approved service requests. The gateway enforces authentication, destination validation, token binding, and policy before substituting real credentials and making the downstream HTTP call. It also scans downstream responses and replaces detected secrets with opaque tokens before returning the response to the agent.

## What It Provides

- Streamable HTTP MCP endpoint for configured clients.
- A small generic tool surface for listing services, requesting opaque tokens, making service requests, and explaining denials.
- Server-side credential substitution after auth, destination validation, and policy checks.
- Default-deny request policy with explainable denials.
- Secretlint response scanning that replaces detected values with reversible, service-scoped `sec_…` tokens.
- Structured audit logging designed to avoid raw credentials, opaque token values, authorization headers, cookies, and downstream response bodies.
- Docker deployment with a non-root runtime user and healthcheck.

## Safety Model

Agents are never entrusted with raw API keys, passwords, bearer tokens, cookies, or other configured downstream credentials. Those values remain on the backend: the gateway substitutes them only after authentication, destination validation, token validation, and policy approval. This protection does not rely on model instructions, prompt compliance, agent memory, agent-side redaction, or the agent keeping a received secret confidential.

The gateway uses two kinds of opaque placeholders:

- `tok_…` tokens represent configured credentials. They are bound to the authenticated subject, originating service, destination, and credential.
- `sec_…` tokens represent secrets detected while scanning downstream responses. Detection and replacement happen on the backend before the response reaches the agent, and these tokens are bound to the authenticated subject and originating service.

Both token types work only when submitted back through this gateway and expire under configured idle and maximum TTLs. Authenticated-subject binding remains in force across supported MCP transport reinitialization; `mcp-session-id` is transport state, not an authorization boundary.

The proxied HTTP surface is deliberately cookie-free: caller-supplied cookie headers are rejected and downstream cookie headers are discarded. APIs that require browser-style cookie sessions are not supported. Response JSON is scanned as source text without parsing or reserialization. A whole response body is decoded and scanned as Base64 only when it declares `Content-Transfer-Encoding: base64`. A string request body with the same declaration is decoded, has opaque tokens substituted, and is canonically re-encoded before delivery; undeclared Base64-looking content remains opaque.

For every downstream request, the gateway validates the authenticated client, requested service, destination, URL, method, token binding, and configured policy before replacing opaque tokens with real credentials. If a request is denied, the client can ask for an explanation instead of guessing around policy boundaries.

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
ghcr.io/mrworf/agent-credential-gateway-mcp
```

Package page: [github.com/mrworf/devops-mcp/pkgs/container/agent-credential-gateway-mcp](https://github.com/mrworf/devops-mcp/pkgs/container/agent-credential-gateway-mcp)

The CI workflow runs `npm ci`, `npm run build`, and `npm test` first. The Docker image job depends on those quality gates, so a failing build or test run prevents image publishing. Pull requests validate the Docker build without pushing an image; pushes to `main` publish the GHCR image.

## Merge Protection

The workflow reports the `quality-gates` check on pull requests. To make failed checks block merges into `main`, configure a GitHub branch protection rule or ruleset that requires `quality-gates` before merging.

## Local Docker Example

```yaml
services:
  agent-credential-gateway:
    image: ghcr.io/mrworf/agent-credential-gateway-mcp:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      - ./secretlint.yaml:/config/secretlint.yaml:ro
      - ./secrets:/run/secrets:ro
      - ./oauth:/run/oauth:ro
      - ./audit:/var/lib/agent-credential-gateway/audit
    environment:
      CONFIG_PATH: /config/config.yaml
      SECRETLINT_CONFIG_PATH: /config/secretlint.yaml
```

Use the writable audit mount for `audit.file`, for example `/var/lib/agent-credential-gateway/audit/audit.jsonl`. When using `auth.mode: builtin_oauth`, keep `auth.builtin_oauth.signing_key_file` on stable mounted storage such as `/run/oauth/oauth_signing_key.pem`; changing that key forces clients to reauthenticate.

Expose the service through an HTTPS endpoint such as `https://gateway.example.org/mcp` when using remote MCP clients.

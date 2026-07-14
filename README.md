# Agent Credential Gateway MCP

[![CI](https://github.com/mrworf/devops-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mrworf/devops-mcp/actions/workflows/ci.yml)
[![Docker image](https://img.shields.io/badge/GHCR-agent--credential--gateway--mcp-2ea44f?logo=github)](https://github.com/mrworf/devops-mcp/pkgs/container/agent-credential-gateway-mcp)

`agent-credential-gateway-mcp` is a self-hosted MCP server that lets Codex, ChatGPT-compatible MCP clients, and other supported agents call configured HTTP services without receiving raw downstream credentials.

The service acts as an MCP-controlled credential gateway. Agents request temporary opaque tokens, then use those tokens in approved service requests. The gateway enforces authentication, destination validation, token binding, and policy before substituting real credentials and making the downstream HTTP call.

## What It Provides

- Streamable HTTP MCP endpoint for configured clients.
- A small generic tool surface for listing services, requesting opaque tokens, making service requests, and explaining denials.
- Server-side credential substitution after auth, destination validation, and policy checks.
- Default-deny request policy with explainable denials.
- Exact-match credential redaction for downstream responses.
- Structured audit logging designed to avoid raw credentials, opaque token values, authorization headers, cookies, and downstream response bodies.
- Docker deployment with a non-root runtime user and healthcheck.

## Safety Model

Agents should never receive raw API keys, passwords, bearer tokens, cookies, or other configured downstream secrets. They receive opaque token placeholders that only work through this MCP server.

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
      - ./secrets:/run/secrets:ro
      - ./oauth:/run/oauth:ro
      - ./audit:/var/lib/agent-credential-gateway/audit
    environment:
      CONFIG_PATH: /config/config.yaml
```

Use the writable audit mount for `audit.file`, for example `/var/lib/agent-credential-gateway/audit/audit.jsonl`. When using `auth.mode: builtin_oauth`, keep `auth.builtin_oauth.signing_key_file` on stable mounted storage such as `/run/oauth/oauth_signing_key.pem`; changing that key forces clients to reauthenticate.

Expose the service through an HTTPS endpoint such as `https://gateway.example.org/mcp` when using remote MCP clients.

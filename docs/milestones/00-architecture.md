# Milestone 00: Architecture Baseline

## Purpose
This file is the shared implementation contract for the Agent Credential Gateway MCP MVP. Read it before implementing any milestone, then read only the selected milestone plan and the project guidance in `docs/AGENTS.md`.

## MVP Architecture
Build a Dockerized TypeScript service on Node.js 22. Use the official MCP TypeScript SDK for MCP protocol behavior and Node's built-in `http` server for HTTP routing. Do not add Express, Fastify, NestJS, Next.js, an ORM, a database, Redis, a queue, a UI framework, a metrics stack, or service profile packs for MVP.

Allowed runtime dependencies:
- `@modelcontextprotocol/sdk`: MCP server, Streamable HTTP transport, tool registration.
- `zod`: external input, tool schema, and config validation.
- `yaml`: YAML config parsing only.
- `jose`: OIDC/JWT/JWKS validation for OAuth resource-server checks.
- Node built-ins: `http`, `crypto`, `fs`, `url`, `timers`, global `fetch`.

Allowed dev dependencies:
- `typescript`
- `vitest`
- `@types/node`

Any new dependency must be justified in the milestone implementation notes and must be smaller than the code it replaces in complexity or risk.

## Module Boundaries
- `server`: process startup, Node HTTP server, `/health`, OAuth metadata, MCP path routing.
- `mcp`: initialization instructions, four tool registrations, descriptors, schemas, safe result helpers.
- `auth`: OAuth/OIDC JWT validation, bearer dev mode, subject/session/scope extraction.
- `config`: YAML parsing, validation, normalization, env/file secret resolution.
- `registry`: service, destination, credential lookup, access checks, TLS flag resolution.
- `tokens`: opaque token issuance, lookup, expiry, binding, in-memory store.
- `policy`: allow/deny evaluation, priority handling, denial explanation context.
- `gateway`: service request validation, token substitution, downstream HTTP execution.
- `redaction`: exact plaintext and JSON-escaped credential redaction.
- `audit`: sanitized JSON audit events, request IDs, denial records.

## Security Invariants
- Never return raw configured credentials through MCP content, structured content, or `_meta`.
- Never log raw credentials, opaque token values, Authorization headers, cookies, request bodies, or downstream response bodies by default.
- Authenticate before service listing, token issuance, policy evaluation, or downstream calls.
- Validate destination, scheme, host, and port before credential substitution.
- Evaluate policy before credential substitution.
- Default policy mode is deny.
- Reject unknown, expired, cross-user, cross-session, cross-service, and cross-destination opaque tokens.
- Disable redirects by default; never forward credentials across host boundaries.
- Record `tls.verify: false` in response metadata and audit events.

## Config Shape
MVP config is YAML:
- `server.listen`, `server.mcp_path`, optional canonical external URL/resource.
- `auth.mode: oauth | bearer`.
- `auth.oauth.issuer`, `audience` or resource, `jwks_uri` or discovery URL, `required_scopes`.
- `auth.bearer.token_env` or `token_file` for development mode.
- `tokens.idle_ttl`, `tokens.max_ttl`.
- `limits.max_request_body`, `limits.max_response_body`, `limits.timeout`.
- `audit.file` optional; stdout is acceptable.
- `services.<id>` with destinations, TLS, credentials, access, and policy.

Downstream credentials are pre-configured into the Docker container with environment variables or mounted files. Do not add a vault or secret manager integration in MVP.

## Error Codes
Use structured errors with these codes: `unauthenticated`, `unauthorized_service`, `unknown_service`, `unknown_destination`, `unknown_credential`, `token_expired`, `token_invalid`, `destination_not_allowed`, `host_not_allowed`, `scheme_not_allowed`, `port_not_allowed`, `policy_denied`, `tls_error`, `downstream_timeout`, `downstream_error`, `response_too_large`, `config_error`.

## OpenAI/Codex Compatibility
- Serve Streamable HTTP MCP at `server.mcp_path`, default `/mcp`.
- Return the PRD-required `instructions` text during MCP initialization. The first 512 characters must stand alone.
- Support OAuth by acting as a resource server, not by implementing an authorization server.
- Expose protected resource metadata and return `WWW-Authenticate` challenges for unauthenticated protected requests.
- Validate JWT signature, issuer, audience/resource, expiry/nbf, and scopes server-side.
- Declare per-tool `securitySchemes` and mirror them under `_meta.securitySchemes`.
- Include `outputSchema` for tools returning `structuredContent`.

## Test Conventions
Until milestone 01 establishes the actual package scripts, use this convention:
- Focused tests: `npm test -- <pattern>`
- Full suite: `npm test`

Each new external input must have at least one positive and one negative test.

## Acceptance
This architecture baseline is complete when it gives later milestone implementers enough context to work safely without rereading the full PRD.

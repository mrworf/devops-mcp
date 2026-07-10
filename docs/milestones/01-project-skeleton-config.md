# Milestone 01: Project Skeleton And Config

## Context
Use the architecture in `00-architecture.md`. This milestone creates the minimal Node/TypeScript service foundation, config model, validation, and Docker skeleton. It must not implement MCP tools yet.

Do not add any framework or dependency beyond the architecture-approved list unless the implementation notes justify it.

## Scope
- Initialize a minimal TypeScript project for Node.js 22.
- Add a Node `http` server with `/health`.
- Add YAML config loading, normalization, validation, and env/file secret resolution.
- Add a Dockerfile skeleton and sample config fixture for tests.

## Non-Scope
- No MCP endpoint or tools.
- No OAuth verification beyond config shape validation.
- No downstream HTTP gateway behavior.
- No token broker or policy engine.

## Interfaces And Types
Create internal types:
- `GatewayConfig`
- `ServiceConfig`
- `DestinationConfig`
- `CredentialConfig`
- `LimitsConfig`
- `AuthConfig`

Create functions:
- `loadConfig(path: string): GatewayConfig`
- `validateConfig(raw: unknown, env?: NodeJS.ProcessEnv): GatewayConfig`

Config must support env and file credential sources:
- `source.kind: env`, `source.name`
- `source.kind: file`, `source.path`

## Likely Files
- `package.json`
- `tsconfig.json`
- `src/server.ts`
- `src/config.ts`
- `src/types.ts`
- `src/errors.ts`
- `test/config.test.ts`
- `test/fixtures/config.valid.yaml`
- `Dockerfile`

## Tests
Positive:
- Valid sample config loads.
- Env secret source resolves.
- File secret source resolves.
- Broad host regex emits warning and startup continues.

Negative:
- Malformed YAML fails.
- Duplicate service, destination, or credential IDs fail.
- Invalid base URL fails.
- Invalid host/path regex fails.
- Invalid TTL or size limit fails.
- Missing env/file secret fails.

## Acceptance Criteria
- `npm test` passes.
- Server starts with a sample config.
- `/health` returns a ready response.
- No MCP tools are registered yet.
- Config errors fail startup with clear messages and no secrets in logs.

## Completion Checklist
- [ ] Minimal TypeScript project exists.
- [ ] Config loader and validator are tested.
- [ ] Health endpoint is implemented.
- [ ] Dockerfile skeleton exists.
- [ ] No unauthorized dependencies were added.

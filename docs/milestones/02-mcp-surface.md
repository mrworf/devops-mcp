# Milestone 02: MCP Surface

## Context
Use the architecture in `00-architecture.md`. This milestone adds the Codex/OpenAI-compatible MCP surface with four stub tools. Business logic may still return safe placeholder errors.

Do not add any HTTP framework; use Node `http` plus the MCP SDK transport.

## Scope
- Add Streamable HTTP MCP endpoint at configured `server.mcp_path`.
- Register exactly four tools: `list_services`, `get_gateway_service_references`, `service_request`, `explain_denial`.
- Add the required initialization instructions.
- Add input schemas, output schemas, per-tool `securitySchemes`, `_meta.securitySchemes`, annotations, and invocation status text.
- Add safe result/error helpers.

## Non-Scope
- No real auth enforcement beyond available stubs from milestone 01.
- No service registry, token broker, policy, or downstream HTTP execution.

## Interfaces And Tool Names
- `list_services`
- `get_gateway_service_references`
- `service_request`
- `explain_denial`

Shared helper:
- `toolSuccess(structuredContent, summary, meta?)`
- `toolError(code, message, requestId?)`

## Likely Files
- `src/mcp/server.ts`
- `src/mcp/tools.ts`
- `src/mcp/schemas.ts`
- `src/mcp/results.ts`
- `src/server.ts`
- `test/mcp-surface.test.ts`

## Tests
Positive:
- MCP initialize returns instructions with the PRD-required opening text.
- Tool discovery returns exactly four tools.
- Descriptors include `inputSchema`, `outputSchema` where structured content is returned, `securitySchemes`, `_meta.securitySchemes`, annotations, and status text.

Negative:
- Stub handler outputs contain no raw credential-shaped config values.
- Unknown MCP path returns a safe HTTP error.

## Acceptance Criteria
- Codex-compatible MCP surface exists.
- Four tool descriptors match the PRD contract.
- No service-specific tools exist.
- `npm test` passes.

## Completion Checklist
- [ ] Streamable HTTP MCP endpoint is mounted.
- [ ] Required instructions are returned.
- [ ] Exactly four tools are discoverable.
- [ ] Tool descriptors are OpenAI-compatible.

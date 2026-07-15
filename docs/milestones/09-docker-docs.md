# Milestone 09: Docker And Docs

## Context
Use the architecture in `00-architecture.md`. This milestone packages and documents the MVP for a homelab user using pre-configured Docker credentials and Codex/ChatGPT desktop MCP configuration.

Do not add a web admin UI or hosted integration.

## Scope
- Finalize Docker image.
- Add Docker Compose example.
- Add sample YAML config.
- Add Codex CLI config examples for OAuth and bearer dev mode.
- Document `codex mcp login <server-name>`.
- Document ChatGPT desktop shared Codex MCP config.
- Document ChatGPT web limitation.
- Document self-signed TLS and response-tokenization limits.

## Non-Scope
- No ChatGPT web plugin.
- No hosted SaaS.
- No service profile packs.
- No external secret manager integrations.

## Likely Files
- `Dockerfile`
- `docker-compose.example.yaml`
- `docs/config-reference.md`
- `docs/codex-setup.md`
- `docs/security-notes.md`
- `examples/config.yaml`

## Tests
Positive:
- Docker container starts with sample config.
- `/health` succeeds in container.
- MCP initialize works in container.
- Tool discovery returns exactly four tools in container.
- Docs examples match actual schema.

Negative:
- Container fails clearly when required config is missing.
- Sample docs do not include raw credentials.

## Acceptance Criteria
- A homelab user can run the MVP in Docker.
- Codex CLI and ChatGPT desktop setup are documented.
- ChatGPT web limitation is explicit.
- Self-signed TLS and response-tokenization limits are clear.
- `npm test` passes.

## Completion Checklist
- [ ] Docker image runs as non-root if practical.
- [ ] Compose example mounts config and secrets read-only.
- [ ] Codex OAuth and bearer examples are accurate.
- [ ] Security limitations are documented plainly.

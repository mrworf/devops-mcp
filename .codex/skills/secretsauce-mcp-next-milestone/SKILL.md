---
name: secretsauce-mcp-next-milestone
description: Use for this SecretSauce (MCP) project when the user asks to start, implement, continue, complete, or inspect the next MVP milestone, including phrases like "start next milestone", "implement next MVP milestone", or "continue SecretSauce milestone"; reads docs/milestones/status.yaml and the selected milestone plan, implements only that milestone, and updates milestone status.
---

# SecretSauce (MCP) Next Milestone

Use this skill only inside the `secretsauce-mcp` project.

## Workflow
1. Read `docs/AGENTS.md`.
2. Run `node .codex/skills/secretsauce-mcp-next-milestone/scripts/next_milestone.mjs` to identify the first pending milestone, unless the user names a specific milestone.
3. Read `docs/prd.md`, `docs/milestones/00-architecture.md`, and the selected milestone file.
4. Implement only the selected milestone. Do not skip ahead or add behavior from later milestones.
5. Add positive and negative tests for every new external input.
6. Run focused tests and then the full suite. If no suite exists yet, use the milestone's acceptance criteria as the validation target and create the suite when the milestone requires it.
7. If validation passes, commit one concise milestone commit when git is available.
8. Mark the milestone complete with `node .codex/skills/secretsauce-mcp-next-milestone/scripts/mark_complete.mjs <id> --notes "<short validation summary>"`.
9. If validation cannot pass, mark the milestone blocked by editing `docs/milestones/status.yaml` with a concise note and do not mark it complete.

## Guardrails
- Keep MVP scope limited to the four PRD tools.
- Do not add service-specific tools or profile packs.
- Do not add unapproved frameworks or dependencies.
- Never log raw credentials, opaque token values, Authorization headers, cookies, request bodies, or downstream response bodies by default.
- Enforce auth, destination validation, and policy before credential substitution or downstream HTTP calls.

## Status Values
- `pending`: not started.
- `in_progress`: actively being implemented or validation is ongoing.
- `completed`: implemented, validated, and committed when git is available.
- `blocked`: cannot continue without user input or an environment fix.

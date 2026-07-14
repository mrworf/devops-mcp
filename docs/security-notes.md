# Security Notes

- The gateway is not a secrets vault. It is a service-scoped HTTP gateway that keeps configured credentials out of MCP tool results.
- Policy is enforced before credential substitution.
- Destination scheme, host, and port are validated before credential substitution.
- Opaque tokens are bound to subject, service, destination, and credential. MCP transport session IDs may be recorded when available, but are not a hard token boundary because ChatGPT and Codex may reinitialize or vary transport sessions between tool calls.
- `tls.verify: false` is supported for self-signed homelab services and is reported in response metadata and audit events.
- MVP redaction covers exact plaintext credential values and JSON-escaped forms in response headers and body.
- MVP redaction does not detect URL-encoded values, base64 values, derived secrets, private keys, or newly generated downstream tokens.
- Avoid allowing endpoints that return backups, complete config dumps, token lists, private keys, or other bulk secret material.
- Audit events do not include raw credentials, opaque token values, Authorization headers, cookies, request bodies, or response bodies.
- Debug logging is opt-in through `logging.level: debug` and is sanitized before writing. It is intended for setup diagnostics and records structural details such as methods, service IDs, destination IDs, target hosts and paths, status codes, durations, and redaction counts.

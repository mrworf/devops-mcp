# Security Notes

- The gateway is not a secrets vault. It is a service-scoped HTTP gateway that keeps configured credentials out of MCP tool results.
- Policy is enforced before credential substitution.
- Destination scheme, host, and port are validated before credential substitution.
- Opaque tokens are bound to subject, session when available, service, destination, and credential.
- `tls.verify: false` is supported for self-signed homelab services and is reported in response metadata and audit events.
- MVP redaction covers exact plaintext credential values and JSON-escaped forms in response headers and body.
- MVP redaction does not detect URL-encoded values, base64 values, derived secrets, private keys, or newly generated downstream tokens.
- Avoid allowing endpoints that return backups, complete config dumps, token lists, private keys, or other bulk secret material.
- Audit events do not include raw credentials, opaque token values, Authorization headers, cookies, request bodies, or response bodies.

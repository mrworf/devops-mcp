# Milestone 08: Response Tokenization, Audit, And Denials

## Context
This milestone completes response safety, audit logging, structured errors, and denial explanations.

## Implemented behavior
- Scan response headers and UTF-8 body source text with the strict Secretlint catalog.
- Replace exact configured credentials and detected response secrets with reversible opaque references.
- Preserve response source text outside exact replacement ranges; JSON is never parsed or reserialized.
- Treat `gref_` and `sec_` as reserved prefixes and wrap invalid candidates to prevent prefix-based exfiltration.
- Decode and scan whole Base64 bodies declared with `Content-Transfer-Encoding: base64`.
- Reject proxied request cookies and remove proxied response cookies.
- Use a bounded, fair worker pool and fail closed on overload or scanning errors.
- Emit sanitized audit events, request IDs, denial explanations, and tokenization counts.

## Safety invariants
- Authorization, destination validation, and policy run before request token substitution or downstream traffic.
- Configured-credential protection and forged-prefix validation cannot be disabled per endpoint.
- Raw credentials, response secrets, opaque values, cookies, request bodies, and downstream response bodies are absent from audit and logs.
- Request and returned response lengths reflect final byte sequences.

## Acceptance criteria
- Response secrets can be safely referenced through `sec_…` without reaching the agent as raw values.
- Forged `gref_`/`sec_` prefixes cannot bypass scanning.
- Cookie-dependent downstream sessions are unsupported and never propagated.
- Full tests and production build pass.

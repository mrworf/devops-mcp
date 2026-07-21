# Security Remediation Record — 2026-07-19 Review

This companion records remediation of the findings in `security-review-2026-07-19.md` without modifying the original audit. SEC-002 remains an explicitly accepted structural limitation; it was not treated as fixed.

| Finding | Status | Remediation evidence |
|---|---|---|
| SEC-001 | Remediated | DNS suffix matchers now enforce apex-or-label-boundary semantics, canonicalize IDNs, reject IP suffixes, and deny sibling hosts before credential substitution or downstream I/O. |
| SEC-002 | Accepted risk | Response scanning remains best-effort and cannot recognize every invertible downstream transformation. Endpoint selection and policy remain part of the credential boundary. |
| SEC-003 | Remediated | Routing-ambiguous path escapes are rejected from the raw target, and the canonical pathname evaluated by policy is the pathname sent downstream. |
| SEC-004 | Remediated | OAuth client metadata uses redirect-free, public-address-only, DNS-pinned HTTPS retrieval with type/schema, size, timeout, concurrency, and bounded-cache controls. |
| SEC-005 | Remediated | MCP HTTP is stateless and creates no persistent transport records, eliminating the transport-capacity exhaustion path while authenticating every request independently. |
| SEC-006 | Remediated | Token successes/errors and authorization-code redirects carry `Cache-Control: no-store`, `Pragma: no-cache`, and `Referrer-Policy: no-referrer`. |

## Verification

- Every remediation was delivered as an isolated commit after `npm run build`, the complete `npm test` suite, and `git diff --check` passed.
- Positive and negative tests cover every new external configuration input and every fail-closed security boundary.
- Tests use synthetic values and `example.org` stand-ins; no real credentials or deployment endpoints are recorded.
- Logging assertions and code review confirm that the changes do not log raw credentials, authorization headers, cookies, opaque reference values, or downstream response bodies.

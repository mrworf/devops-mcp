# Security Review Remediation Tracking

This companion record tracks remediation of the findings in `security-review-2026-07-15.md`. The original report and reviewed Git SHA remain unchanged.

| Finding | Status | Verification |
|---|---|---|
| SEC-001 | Remediated | Authority, forwarding, and hop-by-hop headers are rejected before substitution and HTTP/HTTPS I/O; outbound authority is derived from the validated URL. |
| SEC-002 | Remediated | Inbound bodies are size-, time-, and concurrency-bounded; password verification uses asynchronous PBKDF2 with bounded concurrency. |
| SEC-003 | Pending | |
| SEC-004 | Pending | |
| SEC-005 | Pending | |
| SEC-006 | Pending | |

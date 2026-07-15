# Security Review Remediation Tracking

This companion record tracks remediation of the findings in `security-review-2026-07-15.md`. The original report and reviewed Git SHA remain unchanged.

| Finding | Status | Verification |
|---|---|---|
| SEC-001 | Remediated | Authority, forwarding, and hop-by-hop headers are rejected before substitution and HTTP/HTTPS I/O; outbound authority is derived from the validated URL. |
| SEC-002 | Remediated | Inbound bodies are size-, time-, and concurrency-bounded; password verification uses asynchronous PBKDF2 with bounded concurrency. |
| SEC-003 | Remediated | Downstream response bytes are bounded during network reads; oversize responses are aborted without partial output. |
| SEC-004 | In progress | Audit, denial, and opaque-token state are bounded; token issuance and response tokenization enforce atomic global/per-subject quotas. |
| SEC-005 | Remediated | Built-in OAuth applies bounded source, account, and global failure limits before PBKDF2 with temporary exponential lockouts. |
| SEC-006 | Pending | |

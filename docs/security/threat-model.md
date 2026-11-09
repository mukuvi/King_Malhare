# Security threat model

Scope: the King Malhare platform itself, its operators, and the assets it assesses. Method: STRIDE with an attacker who can reach the SPA/API, submit targets, obtain a low-privilege account, or control a scanned target (hostile responses).

## Assets

1. Authorization records and scope - the legal/ethical control.
2. Cloud credentials and API keys.
3. Findings and evidence - sensitive description of weaknesses.
4. Audit trail - accountability.
5. Scanner workers - code execution with network reach.
6. Tenant data - assets, reports.

## Trust boundaries

```
Internet → Caddy → SPA static files
Internet → Caddy → Go API
API → PostgreSQL / Redis / object storage
API → internal worker callbacks (service token)
Worker → targets (internet and, only when authorized, private networks)
Worker → scanner binaries (untrusted parsers)
ZAP daemon (internal only)
```

## STRIDE analysis

| Threat | Vector | Impact | Controls |
| --- | --- | --- | --- |
| Spoofing | Stolen session cookie | Account takeover | HttpOnly, Secure, SameSite=Lax, 12h absolute TTL, rotation on login, Argon2id, session revocation, rate-limited login |
| Spoofing | Forged worker callbacks | Fake findings/state | 32-byte service token, constant-time compare, internal listener, no public route |
| Tampering | Cross-org object access (IDOR) | Data breach | Org-scoped queries + object checks + authorization tests for every resource |
| Tampering | Mass assignment on PATCH | Privilege escalation | Explicit field allowlists, role checks, cannot change own role |
| Repudiation | Missing actions | No accountability | Append-only audit events for auth, scans, findings, reports, settings, members |
| Information disclosure | Credentials in logs/UI | Cloud compromise | AES-256-GCM at rest, never serialized to responses, worker payloads not logged, redaction helper |
| Information disclosure | Evidence URL guessing | Sensitive data leak | UUIDs, org check, auth required for download, content-disposition attachment, no directory listing |
| Denial of service | Scan flooding | Resource exhaustion | Per-org scan quota, Redis job cap, worker concurrency, per-job timeout, resource limits, 429 responses |
| Elevation of privilege | SSRF / metadata access | Cloud credential theft | No API-side target fetch; target validation; block 169.254.169.254, metadata hostnames, link-local; private requires authorization; no redirect following cross-host |
| Elevation of privilege | Scanner command injection | Host compromise | `exec` without shell, allowlisted args only, no raw config passthrough, container isolation, cap_drop, read-only FS |
| Elevation of privilege | Container escape | Host compromise | Non-root user, dropped caps, seccomp default, no privileged, no docker socket, internal network only |
| Elevation of privilege | XSS | Session theft/actions | React escaping by default, no `dangerouslySetInnerHTML` for user content, CSP, output encoding server side for report HTML, sanitized markdown |
| CSRF | Cross-site POST | Unauthorized scans | SameSite=Lax + double-submit CSRF header, Origin check on mutations |
| Supply chain | Malicious dependency | Build compromise | Lockfiles, dependency updates, `govulncheck`/`npm audit` in CI, regularly rebuilt base images |
| Insider | Analyst runs intrusive test | Legal exposure | Separate `scans:intrusive` permission, explicit consent checkbox, audit, emergency stop |

## Scanner-specific threats

1. **A user scans a third party.** Mitigated by mandatory authorization records with expiry, approver identity, target binding, and a scope allowlist snapshot; target must match the asset. Authorization alone does not prove permission, so the UI requires the operator to assert a reference and approver; the audit trail records it.
2. **Hostile target returns a crafted response to exploit the parser.** Parsers use strict JSON/XML safe modes, size caps, timeouts, and never `eval`. XML parsing disables external entities in adapters that parse XML.
3. **Scanner binary vulnerability.** Containers run as non-root with resource limits; scanners are updated via image rebuilds; the worker has no DB credentials. Only the API can write findings.
4. **DNS rebinding.** Both API and worker resolve the target; the worker re-resolves immediately before execution and checks every address. Redirects to a different host are rejected by the baseline HTTP client. The scanner connection is not pinned to a single resolved IP, so a DNS server that changes its answer between validation and the request remains a residual risk; screened deployments should use authoritative DNS and outbound allowlists.
5. **Credential exfiltration via cloud scan.** Credentials are decrypted only for the job; adapter uses read-only calls; output is inspected for accidental secret patterns before upload (`redact()`), and jobs requiring write scopes are rejected.
6. **Runaway process.** Child process group killed on timeout/cancel; output capped; max concurrent jobs bounded.

## Security headers

`Content-Security-Policy`, `Strict-Transport-Security` (prod), `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options: DENY`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`. CSP for the SPA: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`.

## Residual risks

- A determined operator can enter false authorization metadata. The platform records but cannot verify legal permission.
- ZAP active scanning and SQLMap can be disruptive; they are gated but not harmless.
- Host-level root compromise of the worker host remains a full compromise of scan capability (not of tenant data, which the worker cannot read directly).
- CVE data depends on an external provider; outages surface as an explicit error with cache fallback.

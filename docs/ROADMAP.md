# Development roadmap and phase log

This log states what is implemented, what is partial, and what remains. It is updated as the platform evolves. A feature is only marked complete when it has a working backend path.

## Phase 1 — Architecture, structure, design system, landing

**Complete**
- Monorepo layout, architecture, ER diagram, API contract, scanner execution model, threat model and deployment docs.
- Design system (buttons, inputs, cards, modals, drawers, tables, tabs, pagination, skeletons, empty and error states).
- Dark-first marketing landing page with responsive layout and real product positioning.
- OpenAPI 3.1 description served by the API.

## Phase 2 — Authentication, authorization, assets, database

**Complete**
- PostgreSQL schema (25+ tables) with constraints, indexes, triggers and forward-only migrations.
- Argon2id password hashing; opaque sessions stored as SHA-256 hashes; CSRF double-submit; login and registration rate limits; secure cookie options.
- RBAC (`owner`, `admin`, `analyst`, `viewer`) with 15 permissions enforced server-side.
- Organization isolation on every query and object lookup.
- Asset registration (10 types), ownership, tags, environments, archive lifecycle.
- Authorization records with approver, validity window, intrusive and private-range flags; revocation.
- Audit log for authentication, assets, authorization, scans, findings, reports, settings and members.
- Member invitation with generated temporary passwords, role hierarchy enforcement.
- API keys with scopes, hashing, expiry and revocation.

## Phase 3 — Scan orchestration, Nmap, Nuclei

**Complete**
- Redis queue, worker claim, progress callbacks, execution records, cancellation, emergency stop, stale-job reaper.
- SSE live progress with snapshot replay.
- Scope snapshot and double validation (API + worker), DNS/private/metadata checks, intrusive gating.
- Docker-isolated worker with dropped capabilities, read-only filesystem, resource limits and no public ports.
- Nmap XML parser with risky-service findings and honest unavailable state.
- Nuclei JSONL parser with CVE/CWE/CVSS mapping and bundled safe templates.
- Scanner catalogue, system profiles, parameter allowlists and custom profiles.
- Scan comparison by fingerprint.

## Phase 4 — OWASP ZAP and web assessment

**Complete**
- First-party HTTP baseline: security headers, clickjacking, cookies, CORS, server disclosure, stack traces, TLS protocol/certificate and signed exposure checks.
- ZAP adapter: spider, passive analysis, optional active scan, alert normalization; availability detected from the daemon.
- Nikto and Gobuster adapters with conservative severity mapping.
- testssl.sh adapter with JSON parsing.
- Guarded SQLMap adapter (single parameter, boolean/error only, no dump, no shell, intrusive approval required).

## Phase 5 — Findings and intelligence

**Complete**
- Normalized result schema and deterministic fingerprints.
- Finding deduplication with preserved triage status, first/last seen and scan linkage.
- Triage: status, severity, assignee, narrative fields, verification, remediation records, timeline events.
- Evidence upload with MIME/magic-byte validation, SHA-256, storage abstraction (local or S3/MinIO) and organization-scoped download.
- CVE lookup via CIRCL with seven-day cache and stale fallback; CWE catalogue; local lookup history.

## Phase 6 — Reporting

**Complete**
- Fourteen-section server-rendered HTML report with escaped user content and a restrictive CSP.
- Server-side PDF report with cover, summary, scope, methodology, findings, evidence inventory, risk and remediation sections.
- Report records with SHA-256 hashes of both artefacts, organization-scoped delivery and deletion.
- Report generation from a scan or a selected finding set.

## Phase 7 — Cloud and network integrations

**Complete**
- AWS read-only posture checks via boto3: root MFA/access keys, CloudTrail, S3 public access, password policy, open security groups, stale keys.
- Prowler and ScoutSuite CLI adapters with generic result normalization and encrypted credentials.
- Trivy image/filesystem adapter and Checkov IaC adapter (allowlisted path only).
- testssl.sh and Nmap coverage for network/TLS.
- Cloud connection CRUD with AES-256-GCM encryption and never returning secrets.

**Partial / next**
- Azure and GCP native SDK checks (currently available through Prowler/ScoutSuite CLIs only; provider credentials are supported).
- Prowler/ScoutSuite/Checkov/Trivy are not installed in the default worker image; availability is reported honestly and the image can be extended.
- Cloud scan validation is structural; live permissions are validated by running a posture scan.

## Phase 8 — Authentication security

**Complete**
- Bounded rate-limit and lockout verification against an explicit test account.
- Authentication-bypass detection on invalid credentials.
- Session cookie flag and login session-rotation checks.
- Test-account password travels only in the job payload, never in stored scan config.

**Deliberately not implemented**
- Credential stuffing, password spraying, unlimited attempts, third-party account attacks.
- Password policy discovery without an authenticated policy endpoint.

## Phase 9 — Analytics, notifications, history, scheduling

**Complete**
- Dashboard metrics from PostgreSQL: posture score, counts, severity distribution, 30-day trend, recent scans, activity.
- Notifications on scan completion/failure/cancellation, reports and authorizations; read state.
- Scan history, filtering, pagination, comparison.
- Non-intrusive scheduled assessments with five-field cron (UTC), an in-process scheduler and system-actor authorization checks.
- Audit log filtering.
- Internal Prometheus metrics and monitoring scaffolding.

**Partial / next**
- Schedules do not support intrusive or cloud scanners (intentional; manual approval required).
- Notifications are in-app only. Email/webhook delivery is not configured.
- Scheduler runs in the API process; for multiple API replicas, a dedicated scheduler election would be preferable.

## Phase 10 — Hardening, tests, deployment

**Complete**
- Dockerfiles for API, web/Caddy and worker; Compose topology with isolated networks and hardened worker.
- Production override, TLS via Caddy, health checks, JSON logs, backups and restore scripts, retention SQL.
- CI: Go vet/tests/migrations/idempotency/govulncheck, frontend typecheck/tests/build, Python lint/tests, container builds and Trivy scan.
- OpenAPI and human-readable API documentation.
- Backend unit tests, frontend unit tests, scanner/scope tests.

**Remaining**
- Browser end-to-end (Playwright) suite against the full Compose stack.
- API integration tests covering every endpoint with a seeded database (core auth/scope paths are covered by unit tests).
- Real lab validation for every scanner adapter; Nmap, HTTP baseline and Nuclei paths are the primary validated paths.
- External secret manager integration (Vault/SOPS) and automated certificate monitoring.
- Multi-organization switching per user account (the schema supports multiple memberships; the UI currently uses the first membership chosen at login).

## Known limitations

1. `hackathon-grade` demo content is intentionally absent; empty states are real.
2. OS fingerprinting requires privileged nmap; the worker skips `-O` when not permitted and reports it.
3. SQLMap requires a URL with a query parameter and an intrusive authorization.
4. Checkov requires `CHECKOV_ALLOWED_ROOT` and a mounted path. Supply the path with the `scan_path` parameter, or use the asset target when it is a path.
5. CVE lookups require outbound HTTPS from the API; cached records are marked stale on provider failure.
6. API keys authenticate as their creator with the scopes granted at creation time; key rotation is manual.
7. The bundling of the SPA behind Caddy is the supported deployment. Splitting the frontend to another origin requires `SameSite=None; Secure` and CORS configuration.
8. Password policy and MFA configuration checks need an application-specific policy endpoint or admin API; the authentication module currently verifies login throttling, lockout, bypass, cookie flags and session rotation.
9. SSRF, IDOR, CSRF, upload and API-specific test cases are covered only when the selected Nuclei/ZAP profile contains them. There is no bespoke per-application test harness yet.
10. There is no email verification, password reset flow or email/webhook notification delivery.
11. Cloud credential rotation (key versioning) is modelled in the schema but not automated.
12. Tenant isolation is enforced in every query and object lookup and covered by integration tests; PostgreSQL row-level security is not enabled.
13. Browser end-to-end tests are not yet part of CI.

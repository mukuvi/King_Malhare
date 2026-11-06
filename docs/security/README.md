# Security policy and operating requirements

## Authorized use

King Malhare exists to test systems for which you hold written authorization. The platform enforces an authorization record at scan creation and again inside the worker, but it cannot verify that the approval is truthful. The operator is responsible for:

- Holding a signed scope, rules of engagement and testing window.
- Ensuring the target list matches the approval.
- Obtaining separate approval for intrusive testing.
- Following applicable law and provider terms.

Do not test third-party systems. Do not use the authentication module for credential stuffing or password spraying. Do not use cloud credentials beyond read-only permissions required for posture assessment.

## Reporting a vulnerability in King Malhare

Contact the repository owner privately with reproduction steps, affected version and impact. Do not open a public issue containing exploit details or secrets.

## Deployment security checklist

- [ ] `POSTGRES_PASSWORD` is unique and strong.
- [ ] `SESSION_PEPPER` is 32 random bytes (64 hex) and not the development value.
- [ ] `CREDENTIAL_ENCRYPTION_KEY` is 32 random bytes (64 hex) and stored in a secret manager, backed up separately from the database.
- [ ] `WORKER_SERVICE_TOKEN` is random and distinct from other secrets.
- [ ] `APP_ENV=production` and `COOKIE_SECURE=true`.
- [ ] `SITE_ADDRESS` is the public HTTPS origin and `APP_ORIGIN` matches it.
- [ ] PostgreSQL and Redis are not published to the host/public internet.
- [ ] Scanner workers have no published ports and are attached to an internal network.
- [ ] The worker image is rebuilt regularly for scanner and dependency updates.
- [ ] Backups are encrypted, stored off-host and restore-tested.
- [ ] The API is reachable only through the TLS reverse proxy.
- [ ] An external uptime monitor checks `/api/v1/health` and `/api/v1/ready`.
- [ ] Cloud credentials are read-only and scoped to the minimum account/regions.
- [ ] Audit retention and evidence retention match policy and contracts.
- [ ] `ALLOW_PRIVATE_TARGETS` is disabled unless the deployment is an isolated assessment environment.

## Data handling

Findings and evidence describe exploitable weaknesses and may contain sensitive data. Treat the database, storage volume and backups as confidential. Do not expose the API or worker network to the public internet. Reports are protected by organization-scoped access; generated HTML has a restrictive CSP and no scripts.

## Secrets

- Passwords: Argon2id.
- Session tokens: random 32 bytes, stored as SHA-256 with a server pepper.
- Cloud credentials: AES-256-GCM with a key from the environment; nonce and ciphertext stored; AAD binds organization and connection ID.
- API keys: SHA-256 hashed, shown once.
- Evidence and report artifacts: local disk or S3-compatible storage; hashes stored for integrity.

## Scanning safety

- Targets are normalized and metadata addresses are always rejected.
- Private targets require `allow_private` on the authorization.
- Intrusive tests require `scans:intrusive`, an intrusive approval and explicit consent.
- Scanner commands use fixed argument vectors; user input never becomes a shell token.
- Per-job timeout, output cap, process-group termination and cancellation are enforced.
- Organization emergency stop cancels all work and blocks new scans.
- The API never fetches a target; SSRF is constrained to worker-side scope-checked connections.

See [the threat model](threat-model.md) for the full analysis.

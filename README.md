# King Malhare

**Offensive Security & Vulnerability Assessment Platform**

> Know your weaknesses before attackers do.

King Malhare is a self-hosted security assessment platform for authorized penetration testing of websites, APIs, networks, cloud accounts and authentication systems. It combines a Go API, isolated Python scanner workers, PostgreSQL, Redis, and a React operations console.

![status](https://img.shields.io/badge/status-active%20development-f5a524) ![license](https://img.shields.io/badge/license-proprietary-1b1b1f)

---

## What is real (and what is not)

King Malhare does not ship fabricated scans, mock findings or hardcoded dashboard numbers. Every number in the UI is read from PostgreSQL, and every finding is produced by a scanner run you started against an asset you explicitly authorized.

| Capability | State |
| --- | --- |
| Session auth (Argon2id, opaque tokens, CSRF, rate limits) | Implemented |
| Organizations, RBAC, audit log | Implemented |
| Asset inventory + authorization records + scope enforcement | Implemented |
| Scan orchestration (Redis queue, SSE progress, cancel, emergency stop) | Implemented |
| Nmap host/port/service assessment | Implemented (requires `nmap`) |
| Nuclei template scanning | Implemented (requires `nuclei` + templates) |
| HTTP baseline assessment (headers, cookies, CORS, TLS, exposure, directory discovery) | Implemented |
| Nikto, Gobuster, testssl.sh, SQLMap, Trivy integrations | Implemented as guarded adapters; report "unavailable" when the binary is absent |
| Burp Suite, ffuf, WhatWeb, WAFW00F, httpx, Subfinder, SSLyze, Grype, Syft, Semgrep, Gitleaks, tfsec, Schemathesis | Implemented as guarded adapters; report "unavailable" when the binary or service is absent |
| OWASP ZAP | Implemented via ZAP daemon API; unavailable unless `ZAP_URL` is configured |
| Prowler, ScoutSuite, Checkov | Implemented as guarded CLI adapters; unavailable unless installed and configured |
| AWS posture checks | Implemented read-only checks (boto3) |
| Azure / GCP posture checks | Adapter interface + documented CLI path; not yet enabled |
| Findings lifecycle, evidence, retest, remediation tracking | Implemented |
| CVE intelligence (CIRCL CVE API, cached) | Implemented (requires outbound HTTPS) |
| HTML + PDF report generation | Implemented |
| Notifications, schedules, comparisons, API keys, OpenAPI | Implemented |
| Evidence storage | Local filesystem by default; S3-compatible driver available |
| Docker/Compose deployment, Caddy TLS, CI | Implemented |

Unavailable scanner binaries are detected at worker startup and shown as **Unavailable** in Integrations. They are never faked. External cloud CLIs (Azure/GCP) remain a documented next step.

## Tool integrations

The optional Kali worker image (`apps/scanner-workers/Dockerfile.kali`) is built on Kali Linux and installs the major assessment metapackages: information gathering, vulnerability analysis, web, database, reporting, fuzzing, sniffing/spoofing and the top 10 toolset. It includes real tools such as Nmap, Nuclei, Burp Suite, OWASP ZAP, Nikto, SQLMap, ffuf, Gobuster, WhatWeb, WAFW00F, httpx, Subfinder, SSLyze, SSLScan, Amass, theHarvester, DNSRecon, DNSEnum, Fierce, Sublist3r, Assetfinder, Masscan, Netdiscover, arp-scan, Enum4linux, SMBMap, DIRB, dirsearch, feroxbuster, Wfuzz, Arjun, Commix, Dalfox, WPScan, JoomScan, Droopescan, Skipfish, Wapiti, SearchSploit, Trivy, Grype, Syft, Prowler, ScoutSuite, Checkov, tfsec, Semgrep, Gitleaks, Bandit, TruffleHog, Schemathesis and more.

A generic catalog adapter runs each tool through an argument vector, never a shell string. Tools marked intrusive require an authorization that explicitly permits intrusive testing. Missing binaries are reported as unavailable at worker startup instead of being simulated. Burp Suite connects to a `burp-rest-api` endpoint through `BURP_URL` and `BURP_API_KEY`.

Each finding includes remediation guidance, technical and business impact, evidence, CVE/CWE identifiers where available, and a remediation history. Reports embed the same recommendations in the HTML and PDF outputs. The API exposes the same data through `GET /findings/{id}` and `POST /findings/{id}/remediation`.

## Architecture at a glance

```
Browser ──HTTPS──> Caddy ──> React SPA (static)
                     │
                     └──/api──> Go API ──> PostgreSQL
                                   │  └──> Redis (jobs, progress, rate limits)
                                   │  └──> Evidence / report storage
                                   │
                                   └── internal callback (service token)
                                           ▲
                                 Python scanner workers
                                   (queue consumer, no public port)
                                           │
                                Docker-sandboxed scanner CLIs
```

Full documentation:

- [System architecture](docs/architecture/system-architecture.md)
- [Database ER diagram](docs/architecture/database.md)
- [API architecture](docs/api/README.md)
- [Scanner execution model](docs/architecture/scanner-execution.md)
- [Threat model](docs/security/threat-model.md)
- [Deployment](docs/deployment/README.md)
- [Testing guide](docs/testing.md)
- [Roadmap and phase log](docs/ROADMAP.md)
- [Security policy](docs/security/README.md)

## Quick start (local development)

Prerequisites: Docker + Compose, Go 1.24+, Node 20+, Python 3.11+.

```bash
cp .env.example .env
# The example contains development-only secrets. Replace them before production:
openssl rand -hex 32   # SESSION_PEPPER
openssl rand -hex 32   # CREDENTIAL_ENCRYPTION_KEY
openssl rand -hex 32   # WORKER_SERVICE_TOKEN

docker compose up -d postgres redis
make migrate
make seed
```

Run the three development processes in separate terminals:

```bash
(cd apps/web && npm install)      # once
make dev-api      # Go API on :8080 and internal :8081
make dev-web      # Vite on :5173 (proxies /api to :8080)
make dev-worker   # creates the venv, installs requirements, runs one worker
```

Create the first account at `http://localhost:5173/register`. The first organization owner is created through registration; subsequent registrations honor `REGISTRATION_ENABLED`.

For the full production-like stack behind Caddy (HTTP on localhost by default):

```bash
docker compose up -d --build
# http://localhost
```

### Run a real assessment in five minutes

1. Start the controlled lab target: `python3 scripts/lab_target.py 3000` (localhost only; deliberately insecure).
2. Add asset `http://127.0.0.1:3000` with environment **lab**.
3. Add an authorization record naming yourself as approver, set an expiry in the future, and allow private targets.
4. Start a **Web baseline**, **Nuclei** or **Nmap** assessment. Progress arrives over SSE; findings are written to PostgreSQL.
5. Open Findings, triage, then generate a PDF report from the scan.

> With the containerized worker, target the lab with `http://host.docker.internal:3000` and make sure the asset and authorization use the same host. The compose worker is configured with `host-gateway`. The host lab binds localhost only; for the containerized worker, run the lab on an interface reachable by the Docker bridge or use a containerized target instead.

## Verification status

The following were executed against the local lab during development: registration and CSRF enforcement, asset/authorization creation, HTTP baseline (14 findings), Nuclei (4 findings), Nmap (1 finding / 6 open ports), authentication baseline (2 findings), finding triage, evidence upload/download with SHA-256, HTML and PDF reports (including an embedded screenshot), cross-tenant 404s, revocation blocking new scans, and a scan executed by the containerized worker through the full Docker stack. See [testing](docs/testing.md) for commands and the honest list of gaps.

## Production deployment

```bash
cp .env.example .env
# set POSTGRES_PASSWORD, SESSION_PEPPER, CREDENTIAL_ENCRYPTION_KEY,
# WORKER_SERVICE_TOKEN, APP_ORIGIN, ACME_EMAIL, and cookie settings
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Caddy obtains TLS certificates automatically. Scanner workers have no published ports and run on an internal-only network. See [deployment docs](docs/deployment/README.md).

## Repository layout

```
apps/
  api/                Go API, migrations, report engine, tests
  scanner-workers/    Python worker, scanner adapters, fixtures, tests
  web/                React/Vite console and design system
docs/
  architecture/  api/  deployment/  security/
infrastructure/
  caddy/  monitoring/
scripts/
```

Shared contracts live in the OpenAPI document served by the API (`apps/api/internal/api/openapi.yaml`) and the JSON job envelope documented in [scanner execution](docs/architecture/scanner-execution.md). There is no separate `packages/` directory in this repository: the Go types, Python adapters and OpenAPI schema are the authoritative contracts, and duplicating them in another package would create drift.

## Offline and air-gapped use

The console and scanner workers are self-hosted. The web app bundles its fonts and icons and registers a service worker that caches the app shell, so the console can open without internet access. Local assessments against local lab targets work when the API, PostgreSQL, Redis and worker are running. External CVE intelligence, passive DNS sources and some cloud checks require outbound internet; the platform reports those failures honestly instead of inventing results.

## Edge hardening

The production nginx configuration adds rate limits for login, registration and the API, security headers (CSP, HSTS, frame denial, referrer policy and permissions policy), dotfile and secret-file blocking, and noindex on authenticated routes. The temporary IP-based host is marked noindex and serves a disallow-all robots.txt. The intended public domain is the canonical SEO origin.

## Privacy and terms

The public site includes Privacy Policy and Terms of Service pages at `/privacy` and `/terms`. Replace them with your organization's legal text before production use.

## Safety and legal

King Malhare is for systems you own or have **written permission** to test. Every scan requires a non-expired authorization record tied to the asset. Targets outside the recorded scope are rejected by both the API and the worker. Private ranges are only reachable when the authorization explicitly allows internal targets. Intrusive modules (SQLMap, auth password auditing) require an additional explicit approval and consent flag. An emergency stop halts all queued and running work.

Do not use this software against third-party systems. You are responsible for compliance with applicable law and contracts.

## License

Proprietary. All rights reserved unless a license is added by the repository owner.

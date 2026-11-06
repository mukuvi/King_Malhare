# Testing guide

## Automated tests

### Backend (Go)

```bash
cd apps/api
go test ./...
```

With a disposable PostgreSQL and Redis instance, the API integration test runs too:

```bash
export TEST_DATABASE_URL='postgres://kingmalhare:kingmalhare-dev-password@localhost:5432/kingmalhare?sslmode=disable'
export TEST_REDIS_URL='redis://localhost:6379/15'
go test ./... -v
```

**Warning:** the integration test truncates `organizations` and `users` in the target database. Point it only at a disposable test database.

Covered:
- Argon2id hashing/verification and password policy.
- AES-256-GCM round trip and AAD binding.
- Token hashing with a server pepper.
- Target normalization, metadata rejection, private/link-local policy, CIDR limits.
- Scanner parameter allowlists and intrusive classification.
- HTML/PDF report generation, escaping and PDF header validity.
- End-to-end HTTP: registration, session/CSRF, asset creation, authorization, queued scan, cross-tenant 404s, revoked-authorization rejection, real Redis job presence.

### Scanner workers (Python)

```bash
cd apps/scanner-workers
python3 -m pytest -q
```

Covered:
- Scope re-validation: expiry, host mismatch, private targets, metadata/link-local blocking, unsafe CIDRs, cloud credential requirements, container references.
- Fingerprint stability and scanner scoping.
- Secret redaction.
- Exposure signature matching and risky-port conservatism.
- Adapter availability probes.

### Frontend (Vitest + Testing Library)

```bash
cd apps/web
npm run test -- --run
npm run typecheck
npm run build
```

Covered: design-system rendering, status/severity labels, loading buttons, empty states, formatting utilities.

## Validated end-to-end paths

The following were executed against the controlled lab target in `scripts/lab_target.py` (localhost only):

| Path | Result |
| --- | --- |
| Registration, session cookie, CSRF enforcement | Verified |
| Asset creation and authorization binding | Verified |
| HTTP baseline scan | 14 findings (headers, cookies, CORS, `.env`, `.git`, actuator, OpenAPI) |
| Nuclei scan with bundled templates | 4 findings |
| Nmap top-100 service scan | 1 finding, 6 open ports |
| Auth baseline with an authorized test account | 2 findings, no lockout/burst beyond 3 attempts |
| Finding triage and audit events | Verified |
| Evidence upload/download with SHA-256 | Verified (PNG round trip) |
| HTML + PDF report generation | Verified; PDF starts with `%PDF-` and renders 14 findings |
| Cross-tenant asset/scan access | 404 |
| Revoked authorization scan attempt | 403 |

## Manual lab workflow

```bash
# Terminal 1: infrastructure
docker compose up -d postgres redis
make migrate

# Terminal 2: API
make dev-api

# Terminal 3: worker
make dev-worker

# Terminal 4: web
make dev-web

# Terminal 5: deliberately vulnerable local target
python3 scripts/lab_target.py 3000
```

Register, add asset `http://127.0.0.1:3000` in environment `lab`, record an authorization with `allow_private` and `intrusive_allowed`, then run each profile. Inspect Integrations to confirm which scanners are actually available.

## Docker deployment checks

```bash
docker compose config
docker compose build api web worker
docker compose up -d postgres redis
make migrate
docker compose up -d api worker web
curl -fsS http://localhost/api/v1/health
curl -fsS http://localhost/api/v1/ready
```

The worker has no published ports. Check health from inside:

```bash
docker compose exec worker python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8090/health').read().decode())"
```

## Gaps

- Browser E2E (Playwright) is not wired into CI; the UI was exercised with Selenium during development but the spec is not committed.
- Automated scanner output fixtures for every adapter are still being expanded; parser-level unit tests cover the highest-risk mappings.
- No load test for Redis queue saturation or concurrent workers.

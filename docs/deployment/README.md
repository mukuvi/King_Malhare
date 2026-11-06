# Deployment

## Topology

```
Internet
  │ 443
Caddy (TLS, HSTS, rate limit at edge)
  ├── /            → static SPA build
  └── /api/*       → api:8080
                        ├── postgres:5432 (private network)
                        ├── redis:6379 (private network)
                        ├── storage volume / S3
                        └── internal worker callbacks :8081
workers (no ports) ── internal network ──> redis, api:8081
```

Networks: `edge` (Caddy/web/API), `internal` (API, PostgreSQL, Redis, workers, optional ZAP) and `egress` (workers only, for outbound scanning). Workers are attached to `internal` and `egress`, but have no published ports. PostgreSQL and Redis are published only on `127.0.0.1` in the development Compose file; the production override removes those mappings. If `ALLOW_PRIVATE_TARGETS=true`, workers can reach private ranges only when the authorization permits it — restrict this on shared infrastructure.

## Production bring-up

1. Provision a VPS with Docker Engine 24+ and Compose v2, 4 vCPU / 8 GB RAM minimum for active web scanning.
2. Point an A/AAAA record at the host. Open 80/443 only. Do not expose 5432/6379/8080.
3. Clone the repository, then:

```bash
cp .env.example .env
# required changes:
#   POSTGRES_PASSWORD
#   SESSION_PEPPER=$(openssl rand -hex 32)
#   CREDENTIAL_ENCRYPTION_KEY=$(openssl rand -hex 64)
#   WORKER_SERVICE_TOKEN=$(openssl rand -hex 32)
#   APP_ORIGIN=https://security.example.com
#   SITE_ADDRESS=https://security.example.com
#   ACME_EMAIL=you@example.com
#   COOKIE_SECURE=true
#   APP_ENV=production

docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose exec api /app/kmctl migrate
docker compose exec api /app/kmctl seed
docker compose exec api /app/kmctl create-admin --email you@example.com --org "Your Org"
```

4. Verify: `https://security.example.com/api/v1/health` returns `{"status":"ok"}`; the login page loads; Integrations shows detected scanners.
5. Create the first asset and authorization. Never enable `ALLOW_PRIVATE_TARGETS` unless the deployment itself is the isolated assessment environment.

## Default worker tool set

The worker image includes **Nmap, Nuclei (with bundled safe templates), Nikto, SQLMap, Gobuster, testssl.sh** and the built-in HTTP/auth engines. It intentionally reports **Prowler, ScoutSuite, Checkov, Trivy and OWASP ZAP** as unavailable until they are installed or configured:

```dockerfile
# Example: derived worker image
FROM king-malhare-worker:latest
USER root
RUN apk add --no-cache trivy || true   # or install from the upstream release
RUN pip install --no-cache-dir prowler checkov scoutsuite
USER scanner
```

For ZAP, start the optional Compose profile and set `ZAP_URL=http://zap:8080` plus `ZAP_API_KEY` in `.env`:

```bash
docker compose --profile zap up -d zap worker
```

Check Integrations after the rebuild; detection is automatic from the worker heartbeat. A missing binary is always reported as unavailable, never simulated.

## Monitoring

The optional monitoring stack scrapes the API's internal `/metrics` endpoint and public health probes:

```bash
docker compose -f docker-compose.yml -f infrastructure/monitoring/compose.monitoring.yml up -d
```

Prometheus listens on `127.0.0.1:9090` with alert rules for API down, readiness failure, queue backlog, worker heartbeat loss and scan failure ratio. Pair it with an external uptime monitor; internal network metrics alone will not detect a total host outage.

## Updates

```bash
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
docker compose exec api /app/kmctl migrate
```

Migrations are forward-only. Take a database dump before updating production. For a disposable local environment only, `CONFIRM=RESET make db-reset` drops the schema and re-applies migrations.

## Backups

```bash
./scripts/backup.sh            # pg_dump + storage archive + .env warning
./scripts/restore.sh <file>    # restores into a stopped API
```

Schedule daily with cron, encrypt off-host (`age`/GPG), test restores quarterly. Object storage volumes contain evidence and reports; back them up together with the database so storage keys resolve.

## Health and monitoring

- `GET /api/v1/health` — process liveness.
- `GET /api/v1/ready` — checks PostgreSQL and Redis.
- Compose health checks gate startup.
- `infrastructure/monitoring/` contains a Prometheus scrape config and alert rules for API 5xx rate, scan failure ratio, queue depth, worker heartbeat staleness, disk usage.
- Worker heartbeat is in Redis (`km:worker:heartbeat`), surfaced on the Integrations page.
- Logs are JSON to stdout with request IDs. Ship with the host's log driver.
- Lock dependencies with `go.sum` and `package-lock.json`; rebuild base images regularly to pick up OS and scanner security updates.

## Retention

Set `DATA_RETENTION_DAYS`. Run `scripts/retention.sql` nightly with psql; it deletes expired report artifacts and audit rows and updates storage cleanup tasks. Findings are preserved; raw scan results older than retention are pruned.

## CI/CD

`.github/workflows/ci.yml` runs:
- Go vet + unit/integration tests (Postgres/Redis services)
- Python ruff + pytest
- Frontend typecheck, unit tests, build
- Docker image builds
- `govulncheck`, `npm audit --omit=dev`, Trivy image scan (report-only on PR, blocking on main)
- Migration apply/down test on a scratch database

Deployment is intentionally manual or via a protected workflow; scanner workers have network reach and should not auto-deploy to production from forks.

## Vercel / Cloudflare Pages frontend

The SPA can be hosted separately if desired, but cookie auth requires same-site API access. Recommended: keep the SPA behind Caddy. If splitting, set `VITE_API_BASE=https://api.example.com/api/v1`, configure credentialed CORS for exactly `APP_ORIGIN`, set cookie `SameSite=None; Secure`, and keep CSRF protection enabled. The default deployment avoids that complexity.

## Scaling

- API is stateless; scale horizontally behind Caddy.
- Workers scale with `docker compose up -d --scale worker=3`; queue concurrency and per-org quotas prevent starvation.
- PostgreSQL: tune shared_buffers, use managed backups; add read replica for reporting at scale.
- Redis: enable AOF for queue durability; a lost queue only loses in-flight jobs (scans fail and can be retried).

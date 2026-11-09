# API architecture

Base path: `/api/v1`. JSON in/out. Authentication is an opaque session cookie for the SPA and hashed bearer API keys for automation. Mutating cookie-authenticated requests require `X-CSRF-Token` matching the `km_csrf` cookie.

OpenAPI: served at `/api/v1/openapi.yaml`; a human-readable API reference is served at `/api/v1/docs` and in the product under **API documentation**.

## Conventions

- Success: `200` or `201` with the resource, or `202` for queued work.
- Errors: `{ "error": { "code": "snake_case_code", "message": "human readable", "details": {} } }`.
- Pagination: `?page=1&per_page=25` (max 100). Response: `{ "items": [], "page": 1, "per_page": 25, "total": 0 }`.
- Sorting: `?sort=created_at&order=desc`; sort field is allowlisted per endpoint.
- Filtering: explicit query parameters, no raw SQL fragments.
- Idempotency: scan start accepts `Idempotency-Key`; reports deduplicate identical in-flight requests.
- Time: RFC 3339 UTC. UUIDs for identifiers.

## Authentication

| Method | Endpoint | Notes |
| --- | --- | --- |
| POST | `/auth/register` | First user or when `REGISTRATION_ENABLED=true`; creates org + owner |
| POST | `/auth/login` | Sets `km_session` (HttpOnly, SameSite=Lax, Secure in prod) and `km_csrf` |
| POST | `/auth/logout` | Revokes session |
| GET | `/auth/me` | User, org, role, permissions |
| POST | `/auth/change-password` | Requires current password; revokes other sessions |

Rate limits: login 10/15 min per IP+email; register 5/hour per IP; all other authenticated requests 600/min per session; scan creation 30/hour per org.

API keys: `Authorization: Bearer km_<prefix>_<secret>`. Only SHA-256 hash stored. Scopes mirror permission names. CSV/JSON automation can use these.

## Resource map

```
/assets                     GET POST
/assets/{id}                GET PATCH DELETE(archive)
/assets/{id}/authorizations GET POST
/authorizations/{id}        PATCH (revoke)
/assets/{id}/scans          GET
/assets/{id}/findings       GET

/scan-profiles              GET POST
/scan-profiles/{id}         PATCH DELETE
/scanners                   GET (availability from worker heartbeats)
/scans                      GET POST
/scans/{id}                 GET
/scans/{id}/cancel          POST
/scans/{id}/events          GET (SSE)
/scans/{id}/executions      GET
/scans/{id}/results         GET
/scans/{id}/findings        GET
/scans/compare              GET ?base=&compare=
/scans/emergency-stop       POST (owner/admin)
/emergency-stop             DELETE (clear)

/findings                   GET
/findings/{id}              GET PATCH
/findings/{id}/verify       POST
/findings/{id}/remediation  POST
/findings/{id}/evidence     GET POST(multipart)
/evidence/{id}/download     GET

/intel/cve/{cveId}          GET (cached proxy)
/intel/cwes                 GET
/intel/lookup               POST {cve|keyword}
/intel/recent               GET (recent local lookups)

/reports                    GET POST
/reports/{id}               GET DELETE
/reports/{id}/html          GET
/reports/{id}/pdf           GET

/notifications              GET
/notifications/read         POST
/audit-events               GET

/cloud-connections          GET POST
/cloud-connections/{id}     DELETE
/cloud-connections/{id}/validate POST

/api-keys                   GET POST
/api-keys/{id}              DELETE
/schedules                  GET POST
/schedules/{id}             PATCH DELETE

/org                         GET PATCH
/org/members                GET POST
/org/members/{userId}       PATCH DELETE
/audit-events               GET
/me                         PATCH
/stats/overview             GET
/stats/trends               GET ?days=30
/integrations               GET

/internal/worker/...        service-token authenticated only
/health, /ready             unauthenticated liveness/readiness
```

## RBAC permissions

| Permission | owner | admin | analyst | viewer |
| --- | :-: | :-: | :-: | :-: |
| org:manage | ✓ | ✓ | | |
| members:manage | ✓ | ✓ | | |
| assets:read | ✓ | ✓ | ✓ | ✓ |
| assets:write | ✓ | ✓ | ✓ | |
| auth:manage | ✓ | ✓ | ✓ | |
| scans:read | ✓ | ✓ | ✓ | ✓ |
| scans:write | ✓ | ✓ | ✓ | |
| scans:intrusive | ✓ | ✓ | | |
| findings:read | ✓ | ✓ | ✓ | ✓ |
| findings:write | ✓ | ✓ | ✓ | |
| reports:read | ✓ | ✓ | ✓ | ✓ |
| reports:write | ✓ | ✓ | ✓ | |
| audit:read | ✓ | ✓ | | |
| integrations:manage | ✓ | ✓ | | |
| api_keys:manage | ✓ | ✓ | | |

Authorization is checked in the HTTP layer via middleware (`requirePermission`), and every data query additionally scopes by organization. Object-level ownership checks prevent cross-org access even with a valid UUID.

## Scan creation payload

```json
{
  "asset_id": "uuid",
  "authorization_id": "uuid",
  "scanner": "nuclei",
  "category": "web",
  "profile_id": "uuid or null",
  "params": { "severity": ["high", "critical"], "rate_limit": 50 },
  "confirm_intrusive": false,
  "idempotency_key": "optional-client-key"
}
```

Unknown scanner, parameter, or scope combination returns `422 validation_error` with field details. Running without a valid authorization returns `403 authorization_required`.

## API key quickstart

Create a scoped key under **Integrations** or with `POST /api-keys`. API-key requests use `Authorization: Bearer km_<prefix>_<secret>` and do not require a CSRF token.

```bash
# Check worker-detected scanner availability.
curl -s -H "Authorization: Bearer km_prefix_secret" \
  https://your-host/api/v1/scanners

# Queue a scoped web assessment.
curl -s -X POST https://your-host/api/v1/scans \
  -H "Authorization: Bearer km_prefix_secret" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": "uuid",
    "authorization_id": "uuid",
    "scanner": "ffuf",
    "category": "web",
    "params": {"wordlist": "common", "threads": 10}
  }'

# Poll the assessment and read normalized findings.
curl -s -H "Authorization: Bearer km_prefix_secret" \
  https://your-host/api/v1/scans/{scanId}
curl -s -H "Authorization: Bearer km_prefix_secret" \
  https://your-host/api/v1/scans/{scanId}/findings
```

The same key can be used with the OpenAPI document at `/api/v1/openapi.yaml`, the interactive reference at `/api/v1/docs`, or any HTTP client. Scopes mirror permission names; a read-only key cannot create assets or queue scans.

## Findings and recommendations

Every normalized finding includes a description, technical impact, business impact, remediation guidance, evidence, CVE/CWE identifiers where available, and lifecycle status. `GET /findings/{id}` returns the recommendation and the remediation history. `POST /findings/{id}/remediation` records an action, owner and optional deadline. Reports include the same recommendation text in the HTML and PDF outputs.

## Versioning

`/v1` is stable within minor releases. Additive fields are non-breaking. Removing or changing a field requires `/v2`. Deprecations appear in the OpenAPI description and response `Deprecation` header for at least one minor cycle.

## Internal worker endpoints

All require `X-Service-Token` compared in constant time, plus an `X-Worker-Id` header. They are bound to the internal listener only (`INTERNAL_LISTEN_ADDR`, default `:8081`) in production and are not routed by Caddy.

- `POST /internal/worker/jobs/{id}/claim`
- `POST /internal/worker/jobs/{id}/progress`
- `POST /internal/worker/jobs/{id}/executions`
- `POST /internal/worker/jobs/{id}/results`
- `POST /internal/worker/jobs/{id}/complete`
- `GET /internal/worker/jobs/{id}/cancel-state`
- `GET /internal/worker/config/{orgId}` (emergency stop + retention)

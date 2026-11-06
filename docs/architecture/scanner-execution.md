# Scanner execution architecture

## Isolation model

Workers run as a separate container/service. In production they are attached only to the `internal` Docker network, have no published ports, `cap_drop: ALL`, `no-new-privileges`, a read-only root filesystem with writable tmpfs for `/tmp`, and CPU/memory/PID limits. They never receive a database URL. All reads/writes go through the API with a shared service token over the internal network.

Scanner CLIs execute with `exec` (no shell), a fixed argument vector derived from validated configuration, a per-job timeout, a maximum captured-output size, and a clean environment. User-supplied strings never become a shell token.

## Job envelope

```json
{
  "scan_id": "uuid",
  "org_id": "uuid",
  "scanner": "nuclei",
  "category": "web",
  "target": "https://app.example.com",
  "target_type": "web_app",
  "config": { "severity": ["medium", "high", "critical"], "rate_limit": 50 },
  "scope": {
    "asset_id": "uuid",
    "authorization_id": "uuid",
    "allow_private": false,
    "intrusive_allowed": false,
    "expires_at": "2026-12-01T00:00:00Z",
    "approved_targets": ["app.example.com"]
  },
  "encrypted_credentials": null
}
```

Cloud credentials are decrypted by the API at dispatch, placed only in the job envelope, consumed by the worker, and never logged. Jobs are removed from Redis once claimed.

## Adapter contract

Every adapter implements:

```python
class ScannerAdapter:
    name: str
    category: str
    intrusive: bool = False
    requires_binary: str | None = None

    async def run(self, ctx: JobContext) -> AsyncIterator[ProgressEvent]: ...
    async def results(self) -> list[NormalizedResult]: ...
```

`NormalizedResult`:

| Field | Rules |
| --- | --- |
| `fingerprint` | sha256 of scanner/title/endpoint/cve-or-cwe, stable across runs |
| `title` | 8–200 characters |
| `severity` | critical, high, medium, low, info |
| `confidence` | certain, firm, tentative |
| `cve` / `cwe` | optional, validated format |
| `cvss` | optional 0.0–10.0 |
| `endpoint` | normalized URL or host:port, no credentials |
| `description`, `remediation` | plain text |
| `evidence` | dict of concrete request/response excerpts, counts, versions |
| `raw` | truncated native object for traceability |

Mappings are conservative. Header findings are emitted only when a header is genuinely absent; TLS findings only when the handshake proves the condition; directory findings only for confirmed non-404 responses; cloud findings only from an explicit failed control.

## Implemented adapters

| Adapter | Binary/service | Key checks | Intrusive |
| --- | --- | --- | --- |
| `http-baseline` | built-in (httpx) | security headers, cookie flags, CORS, TLS cert/protocol, exposed paths (.git, .env, backup, actuator, swagger), server disclosure, clickjacking, CSP gaps | no |
| `nmap` | nmap | host discovery, top-port scan, service/version, risky exposed services (Telnet, SMB, RDP, Redis, Mongo, Elasticsearch, FTP, databases), OS hints via `-O` when permitted | no |
| `nuclei` | nuclei | template-based CVEs, exposures, misconfigurations, panels; JSONL parse | configurable |
| `zap` | ZAP daemon API | spider + passive/active scan, alerts normalized with risk/CWE | active scan optional |
| `nikto` | nikto | server misconfigurations, dangerous files, outdated components | no |
| `gobuster` | gobuster | content discovery against a bounded wordlist, status/length filtering | no |
| `testssl` | testssl.sh | protocol/cipher/certificate findings | no |
| `sqlmap` | sqlmap | only with intrusive approval; bounded risk/level, single parameter, no OS shell, no data dump | **yes** |
| `trivy` | trivy | container image/filesystem misconfigurations and vulns | no |
| `checkov` | checkov | IaC misconfiguration scan on an allowlisted repo path | no |
| `prowler` | prowler | AWS/Azure/GCP posture CLI, read-only | no |
| `scoutsuite` | scoutsuite | multi-cloud read-only posture | no |
| `auth-baseline` | built-in | login rate-limit and lockout behavior against an explicitly supplied **test account**, password policy observation, cookie/session flags | **yes** |
| `aws-posture` | boto3 | root MFA, CloudTrail, public S3 block, password policy, security groups open to world, access-key age | no |

If a binary is missing, the adapter returns `unavailable` with the checked path. The scan fails with an actionable message rather than inventing results.

## Scope enforcement (defence in depth)

1. **API, before enqueue:** asset exists in org; authorization exists, belongs to asset, is active, not expired, and is marked intrusive if the scanner/profile is intrusive; requested parameters validated against an allowlist; target resolved (without scanning) and rejected if it is a metadata address or disallowed private range.
2. **Worker, before execution:** re-checks expiry, intrusive flag, and target host against the approved target snapshot. DNS resolution is repeated and every resolved address is checked; link-local `169.254.0.0/16` and metadata hostnames are always rejected. Private addresses require `allow_private` and an asset environment of `lab` or `internal`.
3. **Scanner, during execution:** no user-supplied flags; redirects are not followed to out-of-scope hosts in baseline checks; cloud calls are read-only.

SSRF is constrained because the API never fetches the target itself. Worker HTTP clients connect only to the validated target host, do not follow cross-host redirects, and refuse proxy environment variables.

## Cancellation and emergency stop

- Per-scan cancel: API sets `cancel_requested` and `SET km:scan:cancel:{id}` with a TTL. The worker polls this key between phases and terminates the subprocess group. The job reports `cancelled`.
- Emergency stop: `POST /scans/emergency-stop` sets `km:emergency-stop:{org}` and marks all non-terminal scans cancelled. Workers check the org flag before each phase and before spawning a child. Clearing it is an owner/admin action with an audit entry.
- API reaper: scans in `running` with no heartbeat for `SCAN_STALE_MINUTES` are marked failed with an actionable error. Automatic re-queue is intentionally not performed, to prevent duplicate intrusive traffic.

## Adding an adapter

1. Add the scanner name to the API's scanner catalog and parameter schema (`internal/scanner/catalog.go`, `docs/api`).
2. Create `apps/scanner-workers/km_worker/scanners/<name>.py` implementing the contract.
3. Map native output to `NormalizedResult`; add parser fixtures and tests under `tests/fixtures`.
4. Register the adapter and binary path in the worker registry.
5. Add the binary to the scanner image only if licensing and size permit; otherwise document host installation and availability detection.
6. Add a lab test target and an integration test that asserts normalized findings for a known condition.

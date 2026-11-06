package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiSpec []byte

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openapiSpec)
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'")
	_, _ = w.Write([]byte(docsHTML))
}

const docsHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>King Malhare API</title>
<style>
  body{margin:0;background:#0a0a0b;color:#e9e4d8;font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
  .wrap{max-width:900px;margin:0 auto;padding:56px 28px}
  .brand{font-weight:700;letter-spacing:.22em;font-size:12px;text-transform:uppercase}
  .brand span{color:#f5a524}
  h1{font-family:Georgia,serif;font-weight:400;font-size:38px;letter-spacing:-.02em;margin:34px 0 10px}
  p{color:#a8a196;max-width:680px}
  h2{font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#f5a524;margin:38px 0 10px}
  code{background:#18181b;border:1px solid #2a2a2f;padding:1px 6px;border-radius:4px;font-size:12.5px;color:#f2c879}
  table{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:8px}
  th{text-align:left;color:#8f887c;font-size:10px;text-transform:uppercase;letter-spacing:.1em;border-bottom:1px solid #2a2a2f;padding:8px}
  td{border-bottom:1px solid #1e1e22;padding:9px 8px;vertical-align:top}
  .m{display:inline-block;font-family:ui-monospace,monospace;font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:6px}
  .get{background:#14351f;color:#6ee7a0}.post{background:#3a2a10;color:#f5b74a}.patch{background:#1b2a3f;color:#7db7ff}.delete{background:#3a1717;color:#ff8f8f}
  a{color:#f5b74a}
  .note{border-left:2px solid #f5a524;background:#141414;padding:12px 16px;margin:20px 0;font-size:13.5px;color:#b6ae9f}
  footer{margin-top:50px;border-top:1px solid #26262b;padding-top:16px;color:#6f695f;font-size:12px}
</style></head><body><div class="wrap">
<div class="brand">KING <span>MALHARE</span> / API</div>
<h1>Developer API</h1>
<p>Versioned REST API used by the King Malhare console. The OpenAPI 3.1 description is served at <a href="/api/v1/openapi.yaml"><code>/api/v1/openapi.yaml</code></a>. All endpoints return JSON and errors use a consistent envelope.</p>
<div class="note"><strong>Authentication.</strong> Browser sessions use the <code>km_session</code> HttpOnly cookie and must send <code>X-CSRF-Token</code> (value of the <code>km_csrf</code> cookie) on every mutating request. Automation uses <code>Authorization: Bearer km_…</code> keys created under Integrations → API keys. Every key is bound to an organization and a scope list.</div>
<h2>Authentication</h2>
<table><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr>
<tr><td><span class="m post">POST</span></td><td><code>/auth/register</code></td><td>Create the first organization and owner</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/auth/login</code></td><td>Create a session; sets CSRF cookie</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/auth/me</code></td><td>User, organization, role and permissions</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/auth/logout</code></td><td>Revoke the current session</td></tr></table>
<h2>Assets and authorization</h2>
<table><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr>
<tr><td><span class="m get">GET</span><span class="m post">POST</span></td><td><code>/assets</code></td><td>List or register an asset</td></tr>
<tr><td><span class="m get">GET</span><span class="m patch">PATCH</span></td><td><code>/assets/{id}</code></td><td>Asset detail and updates</td></tr>
<tr><td><span class="m get">GET</span><span class="m post">POST</span></td><td><code>/assets/{id}/authorizations</code></td><td>Written scope approvals</td></tr>
<tr><td><span class="m patch">PATCH</span></td><td><code>/authorizations/{id}</code></td><td>Revoke an authorization</td></tr></table>
<h2>Assessments</h2>
<table><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr>
<tr><td><span class="m get">GET</span><span class="m post">POST</span></td><td><code>/scans</code></td><td>List or queue an assessment</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/scans/{id}</code></td><td>Scope, config, executions, counts</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/scans/{id}/events</code></td><td>Server-Sent Events progress stream</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/scans/{id}/cancel</code></td><td>Cancel a queued or running job</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/scans/{id}/results</code></td><td>Normalized scanner output</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/scans/compare?base=&amp;compare=</code></td><td>New, resolved and persisting findings</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/scans/emergency-stop</code></td><td>Stop all work immediately</td></tr></table>
<h2>Findings and reporting</h2>
<table><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr>
<tr><td><span class="m get">GET</span></td><td><code>/findings</code></td><td>Filter and page the finding register</td></tr>
<tr><td><span class="m get">GET</span><span class="m patch">PATCH</span></td><td><code>/findings/{id}</code></td><td>Detail, triage, assignment</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/findings/{id}/evidence</code></td><td>Multipart evidence upload (25 MB)</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/findings/{id}/verify</code></td><td>Confirm verification</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/reports</code></td><td>Generate HTML and PDF reports</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/reports/{id}/pdf</code></td><td>Download the PDF</td></tr></table>
<h2>Intelligence and operations</h2>
<table><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr>
<tr><td><span class="m get">GET</span></td><td><code>/intel/cve/{CVE-YYYY-NNNN}</code></td><td>CVE lookup through CIRCL with cache</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/intel/cwes</code></td><td>CWE classification reference</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/stats/overview</code></td><td>Dashboard metrics from PostgreSQL</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/stats/trends?days=30</code></td><td>Daily finding and scan trend</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/scanners</code></td><td>Tool availability from worker heartbeats</td></tr>
<tr><td><span class="m get">GET</span></td><td><code>/audit-events</code></td><td>Organization audit trail</td></tr></table>
<div class="note">Worker callbacks under <code>/internal/worker/*</code> are not part of the public API. They require the <code>X-Service-Token</code> shared secret and are bound to the internal listener only.</div>
<footer>King Malhare · Know your weaknesses before attackers do.</footer>
</div></body></html>`

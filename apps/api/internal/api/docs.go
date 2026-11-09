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
  :root{--paper:#f7f2e8;--surface:#fffdf9;--surface-2:#fbf8f2;--ink:#1f1b16;--muted:#6b6459;--line:#e7ded0;--rose:#e8a8a2;--rose-strong:#9e5b58;--mint:#9ddcbf;--mint-strong:#2a6e61;--butter:#f9d878;--lilac:#ddd2f6}
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(900px 520px at 8% -8%,rgba(232,168,162,.18),transparent 62%),radial-gradient(760px 500px at 100% 0%,rgba(157,220,191,.18),transparent 60%),radial-gradient(700px 460px at 50% 110%,rgba(221,210,246,.2),transparent 65%),var(--paper);color:var(--ink);font:15px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .wrap{max-width:1080px;margin:0 auto;padding:40px 20px 64px}
  .top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
  .brand{display:flex;align-items:center;gap:12px;text-decoration:none;color:inherit}
  .mark{width:44px;height:44px;border-radius:15px;background:var(--surface);border:1.5px solid var(--ink);display:flex;align-items:center;justify-content:center;flex:0 0 auto}
  .brand-name{display:block;font-weight:650;letter-spacing:-.02em;font-size:14px}
  .brand-sub{display:block;font-size:9px;letter-spacing:.18em;text-transform:uppercase;color:var(--mint-strong)}
  .pill{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);background:rgba(255,253,249,.85);padding:8px 14px;border-radius:999px;font-size:11px;color:var(--muted);text-decoration:none}
  .hero{padding:54px 0 8px;max-width:760px}
  .eyebrow{font-size:10px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;color:var(--mint-strong)}
  h1{font-size:clamp(36px,7vw,58px);line-height:1.02;letter-spacing:-.045em;margin:14px 0 14px;font-weight:650;text-wrap:balance}
  .lead{font-size:15px;color:var(--muted);max-width:700px;margin:0}
  .grid{display:grid;grid-template-columns:1.35fr .9fr;gap:18px;margin-top:28px}
  .grid>*{min-width:0}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:20px;box-shadow:0 18px 40px -34px rgba(31,27,22,.35);padding:22px;min-width:0;overflow:hidden}
  .card.rose{background:linear-gradient(135deg,rgba(232,168,162,.18),rgba(255,253,249,.92));border-color:rgba(158,91,88,.25)}
  .card.mint{background:linear-gradient(135deg,rgba(157,220,191,.2),rgba(255,253,249,.92));border-color:rgba(42,110,97,.2)}
  h2{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--rose-strong);margin:36px 0 10px}
  h3{font-size:13px;margin:0 0 6px;letter-spacing:-.01em}
  p{margin:0 0 10px;color:var(--muted);overflow-wrap:break-word}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:var(--surface-2);border:1px solid var(--line);border-radius:6px;padding:1px 6px;color:var(--rose-strong);overflow-wrap:anywhere}
  pre{background:var(--surface-2);border:1px solid var(--line);border-radius:14px;padding:16px;overflow-x:auto;font-size:11.5px;line-height:1.7;color:var(--ink);margin:0;max-width:100%}
  pre code{background:none;border:none;padding:0;color:inherit;font-size:inherit}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;color:var(--muted);font-size:9.5px;text-transform:uppercase;letter-spacing:.12em;border-bottom:1px solid var(--line);padding:9px 8px}
  td{border-bottom:1px solid var(--line);padding:10px 8px;vertical-align:top}
  tr:last-child td{border-bottom:none}
  .m{display:inline-block;font-family:ui-monospace,monospace;font-size:9px;font-weight:800;letter-spacing:.04em;padding:3px 7px;border-radius:6px;margin-right:5px;margin-bottom:2px}
  .get{background:rgba(157,220,191,.35);color:#25584f}.post{background:rgba(232,168,162,.4);color:#7d4745}.patch{background:rgba(221,210,246,.55);color:#543b7b}.delete{background:rgba(239,68,68,.12);color:#991b1b}
  a{color:var(--rose-strong)}
  .note{border-left:3px solid var(--rose);background:rgba(255,253,249,.82);border-radius:0 14px 14px 0;padding:14px 16px;margin:16px 0;font-size:13px;color:var(--muted)}
  .note strong{color:var(--ink)}
  .note.mint{border-left-color:var(--mint-strong)}
  .footer{margin-top:48px;border-top:1px solid var(--line);padding-top:18px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:11px}
  .footer a{text-decoration:none}
  @media(max-width:860px){.grid{grid-template-columns:1fr}}
  @media(max-width:720px){
    .wrap{padding:24px 14px 44px}
    .hero{padding:34px 0 4px}
    table,tbody,tr,td{display:block;width:100%}
    thead{display:none}
    tr{border:1px solid var(--line);border-radius:14px;background:var(--surface);padding:12px;margin-bottom:10px}
    td{border:none;padding:3px 0}
    td:first-child{margin-bottom:2px}
    td:nth-child(3){font-size:12px;color:var(--muted)}
    .card{padding:18px}
  }
</style></head><body><div class="wrap">
<div class="top">
  <a class="brand" href="/">
    <span class="mark">
      <svg viewBox="0 0 48 48" width="31" height="31" aria-hidden="true">
        <path d="M17.4 22.5C12.8 13.6 13.9 6.2 18.3 6.2c3.5 0 4.1 7.1 2.6 16.3" fill="#F3C0B8" stroke="#1F1B16" stroke-width="1.4" stroke-linejoin="round"/>
        <path d="M30.6 22.5c4.6-8.9 3.5-16.3-.9-16.3-3.5 0-4.1 7.1-2.6 16.3" fill="#F3C0B8" stroke="#1F1B16" stroke-width="1.4" stroke-linejoin="round"/>
        <path d="M24 14.8c6.7 0 10.8 4.8 10.8 11.6 0 7.4-4.7 12.5-10.8 12.5S13.2 33.8 13.2 26.4c0-6.8 4.1-11.6 10.8-11.6Z" fill="#FFFDF9" stroke="#1F1B16" stroke-width="1.6"/>
        <path d="M17.1 14.9 19.2 9.8l2.8 2.9L24 8.6l2 4.1 2.8-2.9 2.1 5.1Z" fill="#F9D878" stroke="#1F1B16" stroke-width="1.2" stroke-linejoin="round"/>
        <circle cx="20.4" cy="27" r="1.25" fill="#1F1B16"/><circle cx="27.6" cy="27" r="1.25" fill="#1F1B16"/>
        <path d="M24 30.2 22.7 31.8h2.6Z" fill="#BF7370" stroke="#1F1B16" stroke-width=".8" stroke-linejoin="round"/>
        <path d="M21.2 32.8c1.7 1.1 3.9 1.1 5.6 0" fill="none" stroke="#1F1B16" stroke-width="1.1" stroke-linecap="round"/>
        <circle cx="15.8" cy="30.4" r="1.9" fill="#9DDCBF" opacity=".85"/><circle cx="32.2" cy="30.4" r="1.9" fill="#9DDCBF" opacity=".85"/>
      </svg>
    </span>
    <span><span class="brand-name">King Malhare</span><span class="brand-sub">Developer API</span></span>
  </a>
  <a class="pill" href="/api/v1/openapi.yaml">OpenAPI 3.1 <span>→</span></a>
</div>

<div class="hero">
  <div class="eyebrow">Developer API</div>
  <h1>Build on the same authorized assessment engine.</h1>
  <p class="lead">Versioned REST API used by the King Malhare console. The OpenAPI 3.1 description is served at <a href="/api/v1/openapi.yaml"><code>/api/v1/openapi.yaml</code></a>. All endpoints return JSON and errors use a consistent envelope.</p>
</div>

<div class="grid">
  <div class="card rose">
    <h3>Authentication</h3>
    <p>Browser sessions use the <code>km_session</code> HttpOnly cookie and must send <code>X-CSRF-Token</code> (value of the <code>km_csrf</code> cookie) on every mutating request. Automation uses <code>Authorization: Bearer km_...</code> keys created under Integrations → API keys. Every key is bound to an organization and a scope list.</p>
  </div>
  <div class="card mint">
    <h3>Quick start</h3>
    <pre><code>curl -s -H "Authorization: Bearer km_prefix_secret" \
  https://your-host/api/v1/scanners

curl -s -X POST https://your-host/api/v1/scans \
  -H "Authorization: Bearer km_prefix_secret" \
  -H "Content-Type: application/json" \
  -d '{"asset_id":"...","authorization_id":"...","scanner":"ffuf","category":"web"}'</code></pre>
  </div>
</div>

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
<tr><td><span class="m get">GET</span><span class="m patch">PATCH</span></td><td><code>/findings/{id}</code></td><td>Detail, triage, assignment and recommendation</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/findings/{id}/evidence</code></td><td>Multipart evidence upload (25 MB)</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/findings/{id}/verify</code></td><td>Confirm verification</td></tr>
<tr><td><span class="m post">POST</span></td><td><code>/findings/{id}/remediation</code></td><td>Record a remediation action, owner and deadline</td></tr>
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

<div class="note"><strong>Tool catalog.</strong> <code>GET /scanners</code> reports availability for the bundled worker toolset, including information gathering, web, network, container, infrastructure-as-code and API testing tools. Missing binaries are reported as unavailable, never simulated.</div>
<div class="note mint"><strong>Recommendations.</strong> Findings include technical and business impact, evidence, CVE/CWE identifiers and remediation guidance. Use <code>GET /findings/{id}</code> to read the recommendation and <code>POST /findings/{id}/remediation</code> to record an action.</div>
<div class="note">Worker callbacks under <code>/internal/worker/*</code> are not part of the public API. They require the <code>X-Service-Token</code> shared secret and are bound to the internal listener only.</div>

<div class="footer"><span>King Malhare · Authorized testing only · v1.0.0</span><span><a href="/privacy">Privacy Policy</a> · <a href="/terms">Terms of Service</a> · <a href="/api/v1/openapi.yaml">API</a> · <a href="/login">Sign in</a></span></div>
</div></body></html>`

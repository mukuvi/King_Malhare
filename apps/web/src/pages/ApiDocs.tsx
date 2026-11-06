import { Link } from "react-router-dom";
import { Code2, ExternalLink, KeyRound, LockKeyhole, ShieldCheck, Terminal } from "lucide-react";
import { api } from "@/lib/api";
import { PageHeader, PageTransition, Badge, Card, CardContent, CardHeader, CardTitle } from "@/components/ui";

const groups = [
  { title: "Authentication", rows: [["POST", "/auth/register", "Create organization and owner"], ["POST", "/auth/login", "Create a session and CSRF token"], ["GET", "/auth/me", "Current user, role and permissions"], ["POST", "/auth/logout", "Revoke the session"]] },
  { title: "Assets and authorization", rows: [["GET", "/assets", "List and filter assets"], ["POST", "/assets", "Register an asset"], ["GET", "/assets/{id}", "Asset detail and ownership"], ["POST", "/assets/{id}/authorizations", "Record written approval"], ["PATCH", "/authorizations/{id}", "Revoke approval"]] },
  { title: "Assessments", rows: [["GET", "/scans", "List assessments"], ["POST", "/scans", "Queue an assessment"], ["GET", "/scans/{id}", "Scope, config and executions"], ["GET", "/scans/{id}/events", "Server-Sent Events progress"], ["POST", "/scans/{id}/cancel", "Cancel queued or running work"], ["GET", "/scans/compare", "Diff findings by fingerprint"]] },
  { title: "Findings and reports", rows: [["GET", "/findings", "Filter the finding register"], ["PATCH", "/findings/{id}", "Triage and assignment"], ["POST", "/findings/{id}/evidence", "Upload evidence (multipart)"], ["POST", "/findings/{id}/verify", "Record verification"], ["POST", "/reports", "Generate HTML and PDF"], ["GET", "/reports/{id}/pdf", "Download PDF"]] },
  { title: "Intelligence and operations", rows: [["GET", "/intel/cve/{cveId}", "CIRCL lookup with local cache"], ["GET", "/intel/cwes", "CWE catalogue"], ["GET", "/stats/overview", "Dashboard metrics"], ["GET", "/scanners", "Worker-detected availability"], ["GET", "/integrations", "Connections and queue state"], ["GET", "/audit-events", "Organization audit trail"]] },
];

export function ApiDocsPage() {
  return (
    <PageTransition>
      <PageHeader
        eyebrow="Developers"
        title="API"
        description="Versioned REST API with cookie sessions for the console and scoped bearer keys for automation."
        actions={
          <a href={`${api.base}/openapi.yaml`} target="_blank" rel="noopener noreferrer"><span className="inline-flex h-9 items-center gap-2 rounded-lg border border-ink-600 bg-ink-800 px-3.5 text-[13px] text-ink-100 hover:border-ink-500 hover:bg-ink-750"><ExternalLink className="h-3.5 w-3.5" /> OpenAPI 3.1</span></a>
        }
      />

      <div className="mt-6 grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle subtitle="Consistent envelope and organization scoping">Authentication</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-ink-700 bg-ink-900/50 p-3">
                  <div className="flex items-center gap-2 text-[11.5px] font-medium text-ink-100"><KeyRound className="h-3.5 w-3.5 text-amber-400" /> Browser session</div>
                  <p className="mt-1.5 text-[10.5px] leading-relaxed text-ink-400">HttpOnly <code className="font-mono text-ink-300">km_session</code> cookie. Every mutating request sends <code className="font-mono text-ink-300">X-CSRF-Token</code> with the value of the <code className="font-mono text-ink-300">km_csrf</code> cookie.</p>
                </div>
                <div className="rounded-lg border border-ink-700 bg-ink-900/50 p-3">
                  <div className="flex items-center gap-2 text-[11.5px] font-medium text-ink-100"><Terminal className="h-3.5 w-3.5 text-amber-400" /> API key</div>
                  <p className="mt-1.5 text-[10.5px] leading-relaxed text-ink-400">Create a scoped key under Integrations, then send <code className="font-mono text-ink-300">Authorization: Bearer km_…</code>. Only the SHA-256 hash is stored.</p>
                </div>
              </div>
              <pre className="overflow-x-auto rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-[10px] leading-relaxed text-ink-300">{`# queue a real assessment
curl -X POST ${window.location.origin}${api.base}/scans \\
  -H "Authorization: Bearer km_prefix_secret" \\
  -H "Content-Type: application/json" \\
  -d '{
    "asset_id": "…",
    "authorization_id": "…",
    "scanner": "nuclei",
    "params": {"severity": ["high","critical"], "rate_limit": 40}
  }'`}</pre>
              <p className="flex items-start gap-2 text-[10.5px] leading-relaxed text-ink-500"><LockKeyhole className="mt-0.5 h-3 w-3 shrink-0" /> API keys inherit your permission set at creation time. Requests are still limited by organization scope and asset authorization.</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle subtitle="Base path /api/v1 · JSON · RFC 3339 timestamps">Endpoints</CardTitle></CardHeader>
            <CardContent className="space-y-5">
              {groups.map((group) => (
                <div key={group.title}>
                  <p className="text-[9.5px] font-semibold uppercase tracking-[0.14em] text-ink-500">{group.title}</p>
                  <div className="mt-2 divide-y divide-ink-700/50">
                    {group.rows.map(([method, path, description]) => (
                      <div key={`${method}-${path}`} className="flex flex-col gap-1 py-2 sm:flex-row sm:items-center sm:gap-3">
                        <span className={`inline-flex w-fit rounded px-1.5 py-0.5 font-mono text-[9px] font-bold ${method === "GET" ? "bg-lime-500/10 text-lime-300" : method === "POST" ? "bg-amber-500/10 text-amber-300" : "bg-sky-500/10 text-sky-300"}`}>{method}</span>
                        <code className="font-mono text-[10.5px] text-ink-200">{path}</code>
                        <span className="text-[10.5px] text-ink-500 sm:ml-auto sm:text-right">{description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle subtitle="Typed and predictable">Error contract</CardTitle></CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-[10px] leading-relaxed text-ink-300">{`{
  "error": {
    "code": "authorization_required",
    "message": "A valid, active authorization record is required.",
    "details": {}
  }
}`}</pre>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {["validation_error", "authorization_required", "intrusive_not_authorized", "rate_limited", "csrf_failed", "not_found"].map((code) => <Badge key={code} className="font-mono text-[9px]">{code}</Badge>)}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle subtitle="Safety properties preserved through the API">Guardrails</CardTitle></CardHeader>
            <CardContent className="space-y-2.5">
              {[
                "A scan cannot be created without an active authorization tied to the asset.",
                "Private targets require allow_private on the authorization.",
                "Intrusive scanners require scans:intrusive, an intrusive authorization and confirm_intrusive.",
                "Worker callbacks use a separate internal listener and service token; they are not part of the public API.",
              ].map((item) => (
                <p key={item} className="flex items-start gap-2 text-[10.5px] leading-relaxed text-ink-400"><ShieldCheck className="mt-0.5 h-3 w-3 shrink-0 text-lime-400/70" /> {item}</p>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle subtitle="Also available">Interactive docs</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              <a href="/api/v1/docs" target="_blank" rel="noopener noreferrer" className="flex items-center justify-between rounded-lg border border-ink-700 bg-ink-900/50 px-3 py-2.5 text-[11.5px] text-ink-200 hover:border-ink-500">
                Human-readable API reference <ExternalLink className="h-3.5 w-3.5" />
              </a>
              <Link to="/integrations?tab=keys" className="flex items-center justify-between rounded-lg border border-ink-700 bg-ink-900/50 px-3 py-2.5 text-[11.5px] text-ink-200 hover:border-ink-500">
                Manage API keys <Code2 className="h-3.5 w-3.5" />
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    </PageTransition>
  );
}

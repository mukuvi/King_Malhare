import { useMemo, useState } from "react";
import { ArrowUpRight, BookOpenCheck, Search } from "lucide-react";
import { useCVELookup, useCWEs, useRecentIntel } from "@/hooks/queries";
import { ApiError } from "@/lib/api";
import { cn, formatDate, severityStyles } from "@/lib/utils";
import type { CVE, Severity } from "@/types";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, EmptyState, Input, PageHeader, PageTransition, QueryState, SeverityBadge, Skeleton } from "@/components/ui";

export function IntelPage() {
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [cweQuery, setCweQuery] = useState("");
  const lookup = useCVELookup();
  const recent = useRecentIntel();
  const cwes = useCWEs();
  const result = lookup.data;

  const submit = (id?: string) => {
    const value = (id ?? query).trim().toUpperCase();
    if (!value) return;
    setQuery(value);
    lookup.mutate(value);
  };

  const filteredRecent = useMemo(
    () => (recent.data?.items ?? []).filter((item) => !severityFilter || item.severity === severityFilter),
    [recent.data, severityFilter],
  );
  const filteredCWEs = useMemo(
    () => (cwes.data?.items ?? []).filter((item) => !cweQuery || `${item.id} ${item.name} ${item.description}`.toLowerCase().includes(cweQuery.toLowerCase())),
    [cwes.data, cweQuery],
  );

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Vulnerability intelligence"
        title="CVE and CWE intelligence"
        description="CVE records are retrieved from CIRCL CVE Search and cached locally for seven days. CWE classification is stored in the platform schema."
      />

      <div className="mt-6 grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <Card>
            <CardContent className="py-4">
              <form onSubmit={(event) => { event.preventDefault(); submit(); }} className="flex flex-col gap-2 sm:flex-row">
                <div className="relative flex-1">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
                  <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE-2024-3094" className="pl-9 font-mono uppercase" />
                </div>
                <Button type="submit" loading={lookup.isPending} disabled={!query.trim()}>Look up CVE</Button>
              </form>
              <p className="mt-2 text-[10.5px] text-ink-500">Requires outbound HTTPS from the API. Cached records remain available during provider outages and are marked stale.</p>
              {lookup.isError ? <p className="mt-3 rounded-lg border border-red-500/25 bg-red-500/10 px-3 py-2 text-[11.5px] text-red-200">{lookup.error instanceof ApiError ? lookup.error.message : "Lookup failed."}</p> : null}
            </CardContent>
          </Card>

          {lookup.isPending ? <Skeleton className="h-64 w-full rounded-xl" /> : null}

          {result ? <CveCard cve={result} /> : !lookup.isPending ? (
            <Card>
              <EmptyState icon={<BookOpenCheck className="h-4 w-4" />} title="Look up a CVE" description="Enter a CVE identifier to retrieve its description, CVSS score, CWE classification, affected configurations and references." />
            </Card>
          ) : null}

          <Card>
            <CardHeader>
              <CardTitle subtitle="Cached records from previous lookups">Recent intelligence</CardTitle>
              <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} className="input-base h-8 w-auto border-ink-700 bg-ink-900 text-[11px]">
                <option value="">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </CardHeader>
            <QueryState loading={recent.isLoading} error={recent.error} skeleton={<div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, index) => <Skeleton key={index} className="h-14 w-full" />)}</div>}>
              {filteredRecent.length === 0 ? (
                <p className="px-5 py-6 text-[11.5px] text-ink-400">No cached records yet. Look up a CVE to populate the local intelligence history.</p>
              ) : (
                <div className="divide-y divide-ink-700/60">
                  {filteredRecent.map((cve) => (
                    <button key={cve.id} onClick={() => submit(cve.id)} className="flex w-full items-start justify-between gap-3 px-5 py-3 text-left transition-colors hover:bg-ink-800/60">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[11.5px] text-amber-300">{cve.id}</span>
                          <SeverityBadge severity={normalizeSeverity(cve.severity)} />
                        </div>
                        <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-ink-400">{cve.summary}</p>
                      </div>
                      <div className="shrink-0 text-right">
                        <span className="font-mono text-[11px] text-ink-300">{cve.cvss ?? "—"}</span>
                        <p className="mt-0.5 text-[9px] text-ink-500">{cve.fetched_at ? formatDate(cve.fetched_at) : ""}</p>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </QueryState>
          </Card>
        </div>

        <Card className="h-fit">
          <CardHeader><CardTitle subtitle="Weakness classifications used by findings">CWE catalogue</CardTitle></CardHeader>
          <div className="border-b border-ink-700/60 p-3">
            <Input value={cweQuery} onChange={(event) => setCweQuery(event.target.value)} placeholder="Filter CWE" className="h-8 border-ink-700 bg-ink-900 text-[11.5px]" />
          </div>
          <QueryState loading={cwes.isLoading} error={cwes.error} skeleton={<div className="space-y-2 p-3">{Array.from({ length: 5 }).map((_, index) => <Skeleton key={index} className="h-10 w-full" />)}</div>}>
            <div className="max-h-[620px] divide-y divide-ink-700/50 overflow-y-auto">
              {filteredCWEs.map((cwe) => (
                <div key={cwe.id} className="px-4 py-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[10.5px] text-amber-300">{cwe.id}</span>
                    <Badge className="text-[9px]">{cwe.category}</Badge>
                  </div>
                  <p className="mt-1 text-[11px] font-medium text-ink-200">{cwe.name}</p>
                  <p className="mt-1 text-[10px] leading-relaxed text-ink-500">{cwe.description}</p>
                </div>
              ))}
              {filteredCWEs.length === 0 ? <p className="px-4 py-6 text-center text-[11px] text-ink-400">No matching CWE.</p> : null}
            </div>
          </QueryState>
        </Card>
      </div>
    </PageTransition>
  );
}

function normalizeSeverity(value: string): Severity {
  return (["critical", "high", "medium", "low", "info"].includes(value) ? value : "info") as Severity;
}

function CveCard({ cve }: { cve: CVE }) {
  const severity = normalizeSeverity(cve.severity);
  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[14px] font-semibold text-ink-50">{cve.id}</span>
            <SeverityBadge severity={severity} />
            {cve.cached ? <Badge className="text-[9px]">cached</Badge> : <Badge className="border-sky-500/25 bg-sky-500/10 text-[9px] text-sky-300">live</Badge>}
            {cve.stale ? <Badge className="border-amber-500/25 bg-amber-500/10 text-[9px] text-amber-300">stale</Badge> : null}
            {cve.known_exploited ? <Badge className="border-red-500/25 bg-red-500/10 text-[9px] text-red-300">known exploited</Badge> : null}
          </div>
          <p className="mt-2 text-[12px] leading-relaxed text-ink-300">{cve.summary}</p>
        </div>
        {cve.cvss !== undefined && cve.cvss !== null ? (
          <div className="shrink-0 text-right">
            <p className={cn("font-mono text-[24px] font-semibold leading-none", severityStyles[severity].split(" ").slice(-1)[0])}>{cve.cvss.toFixed(1)}</p>
            <p className="mt-1 text-[8.5px] uppercase tracking-wider text-ink-500">CVSS {cve.cvss_version ?? ""}</p>
          </div>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <Info label="Published" value={cve.published ? formatDate(cve.published) : "Unknown"} />
          <Info label="Modified" value={cve.modified ? formatDate(cve.modified) : "Unknown"} />
          <Info label="Source" value={cve.source} />
        </div>
        {cve.cwe.length ? (
          <div>
            <p className="text-[9.5px] font-semibold uppercase tracking-[0.13em] text-ink-500">CWE classification</p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">{cve.cwe.map((item) => <Badge key={item} className="font-mono">{item}</Badge>)}</div>
          </div>
        ) : null}
        {cve.cvss_vector ? (
          <div>
            <p className="text-[9.5px] font-semibold uppercase tracking-[0.13em] text-ink-500">CVSS vector</p>
            <p className="mt-1 break-all font-mono text-[10px] text-ink-300">{cve.cvss_vector}</p>
          </div>
        ) : null}
        {cve.affected.length ? (
          <div>
            <p className="text-[9.5px] font-semibold uppercase tracking-[0.13em] text-ink-500">Affected configurations</p>
            <ul className="mt-1.5 space-y-1 text-[10.5px] text-ink-300">{cve.affected.slice(0, 12).map((item) => <li key={item} className="truncate font-mono">{item}</li>)}</ul>
          </div>
        ) : null}
        {cve.references.length ? (
          <div>
            <p className="text-[9.5px] font-semibold uppercase tracking-[0.13em] text-ink-500">References</p>
            <div className="mt-1.5 space-y-1">
              {cve.references.slice(0, 8).map((reference) => (
                <a key={reference} href={reference} target="_blank" rel="noopener noreferrer" className="flex items-start gap-1.5 text-[10.5px] text-amber-300 hover:text-amber-200">
                  <ArrowUpRight className="mt-0.5 h-3 w-3 shrink-0" /><span className="break-all">{reference}</span>
                </a>
              ))}
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-ink-500">{label}</p>
      <p className="mt-1 truncate text-[11px] text-ink-200">{value}</p>
    </div>
  );
}

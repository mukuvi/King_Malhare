import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Ban,
  Clock,
  Code2,
  FileText,
  GitCompareArrows,
  ListChecks,
  Radar,
  ShieldAlert,
  Terminal,
} from "lucide-react";
import { api, ApiError, queryString, scanEventsUrl } from "@/lib/api";
import { useMe, useScan, useScans } from "@/hooks/queries";
import { categoryLabel, cn, formatDateTime, relativeTime, scannerLabel, severityOrder } from "@/lib/utils";
import type { ScanDetail, ScanResult, Severity } from "@/types";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, EmptyState, Field, Input, Modal, PageHeader, PageTransition, Progress, QueryState, ScanStatusBadge, SeverityBadge, Skeleton, StatCard, TableShell, Tabs } from "@/components/ui";
import { SeverityDonut } from "@/components/domain/charts";

type Tab = "overview" | "executions" | "results" | "findings";

interface LiveEvent {
  status?: string;
  progress?: number;
  phase?: string;
  message?: string;
  type?: string;
  at?: string;
}

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const me = useMe();
  const scan = useScan(id, true);
  const client = useQueryClient();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("overview");
  const [live, setLive] = useState<LiveEvent | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const [compareOpen, setCompareOpen] = useState(false);
  const [reportTitle, setReportTitle] = useState("");
  const [clientName, setClientName] = useState("");
  const [assessorName, setAssessorName] = useState(me.data?.user.name ?? "");

  const results = useQuery({
    queryKey: ["scan-results", id],
    queryFn: () => api.get<{ items: ScanResult[] }>(`/scans/${id}/results${queryString({ per_page: 100 })}`),
    enabled: Boolean(id),
  });
  const findings = useQuery({
    queryKey: ["scan-findings", id],
    queryFn: () => api.get<{ items: Array<{ id: string; title: string; severity: Severity; status: string; endpoint: string; cve?: string }> }>(`/scans/${id}/findings`),
    enabled: Boolean(id),
  });

  useEffect(() => {
    if (!id) return;
    const source = new EventSource(scanEventsUrl(id), { withCredentials: true });
    source.addEventListener("update", (event) => {
      try {
        const payload = JSON.parse((event as MessageEvent).data) as LiveEvent;
        setLive(payload);
        if (["completed", "failed", "cancelled"].includes(payload.status ?? "")) {
          void client.invalidateQueries({ queryKey: ["scan", id] });
          void client.invalidateQueries({ queryKey: ["scan-results", id] });
          void client.invalidateQueries({ queryKey: ["scan-findings", id] });
          void client.invalidateQueries({ queryKey: ["findings"] });
          void client.invalidateQueries({ queryKey: ["overview"] });
        }
      } catch {
        // ignore malformed stream frames
      }
    });
    source.onerror = () => source.close();
    return () => source.close();
  }, [id, client]);

  useEffect(() => {
    if (scan.data) {
      setReportTitle(`Security assessment - ${scan.data.asset_name}`);
      setAssessorName((current) => current || me.data?.user.name || "");
    }
  }, [scan.data, me.data]);

  const cancel = useMutation({
    mutationFn: () => api.post(`/scans/${id}/cancel`),
    onSuccess: () => {
      toast.success("Cancellation requested");
      void client.invalidateQueries({ queryKey: ["scan", id] });
      void client.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not cancel the assessment."),
  });

  const report = useMutation({
    mutationFn: () =>
      api.post<{ id: string }>("/reports", {
        title: reportTitle,
        client_name: clientName,
        assessor_name: assessorName,
        scan_id: id,
      }),
    onSuccess: (result) => {
      toast.success("Report generated", { description: "HTML and PDF artefacts are ready." });
      setReportOpen(false);
      navigate(`/reports/${result.id}`);
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Report generation failed."),
  });

  if (scan.isLoading) return <ScanDetailSkeleton />;
  if (scan.isError || !scan.data) {
    return (
      <div className="rounded-xl border border-ink-650 bg-ink-850">
        <EmptyState icon={<Radar className="h-4 w-4" />} title="Assessment not found" description="The scan may not exist in this organization." action={<Link to="/scans"><Button variant="secondary">Back to scan center</Button></Link>} />
      </div>
    );
  }

  const data = scan.data;
  const status = (live?.status as ScanDetail["status"]) || data.status;
  const progress = live?.progress ?? data.progress;
  const phase = live?.phase ?? data.phase;
  const active = ["pending", "queued", "initializing", "running"].includes(status);
  const canWrite = me.data?.permissions.includes("scans:write");
  const totalFindings = data.findings;
  const severityTotal = Object.values(data.severity_counts ?? {}).reduce((a, b) => a + b, 0);

  return (
    <PageTransition>
      <Link to="/scans" className="mb-4 inline-flex items-center gap-1.5 text-[11.5px] text-ink-400 hover:text-ink-100">
        <ArrowLeft className="h-3.5 w-3.5" /> Scan center
      </Link>

      <PageHeader
        eyebrow={`${categoryLabel(data.category)} · ${scannerLabel(data.scanner)}`}
        title={data.asset_name}
        description={data.target}
        actions={
          <>
            {active && canWrite ? (
              <Button variant="danger" size="sm" onClick={() => { if (window.confirm("Cancel this assessment? The worker will terminate its scanner process.")) cancel.mutate(); }} loading={cancel.isPending}>
                <Ban className="h-3.5 w-3.5" /> Cancel
              </Button>
            ) : null}
            {data.status === "completed" ? (
              <>
                <Button variant="secondary" size="sm" onClick={() => setCompareOpen(true)}><GitCompareArrows className="h-3.5 w-3.5" /> Compare</Button>
                <Button size="sm" onClick={() => setReportOpen(true)}><FileText className="h-3.5 w-3.5" /> Generate report</Button>
              </>
            ) : null}
          </>
        }
      />

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <ScanStatusBadge status={status} />
        <Badge>queued {formatDateTime(data.created_at)}</Badge>
        {data.started_at ? <Badge>started {formatDateTime(data.started_at)}</Badge> : null}
        {data.finished_at ? <Badge>finished {formatDateTime(data.finished_at)}</Badge> : null}
        {data.intrusive ? <Badge className="border-orange-500/25 bg-orange-500/10 text-orange-700">intrusive</Badge> : null}
        <span className="font-mono text-[10px] text-ink-400">{data.id}</span>
      </div>

      {active ? (
        <Card className="mt-5 border-amber-500/25 bg-amber-500/[0.025]">
          <CardContent className="py-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-3">
                <span className="relative flex h-8 w-8 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-500/10">
                  <Radar className="h-4 w-4 animate-pulseSoft text-amber-700" />
                </span>
                <div>
                  <p className="text-[12.5px] font-medium text-ink-100">{phase || "Waiting for worker"}</p>
                  <p className="mt-0.5 text-[10.5px] text-ink-400">{live?.message || (status === "queued" ? "Queued for a scanner worker." : "Progress is streamed from the worker.")}</p>
                </div>
              </div>
              <div className="text-right">
                <span className="font-mono text-[18px] font-semibold text-amber-700">{progress}%</span>
                <p className="text-[9px] uppercase tracking-wider text-ink-400">worker progress</p>
              </div>
            </div>
            <Progress value={progress} className="mt-3" />
          </CardContent>
        </Card>
      ) : null}

      {status === "failed" ? (
        <div className="mt-5 rounded-xl border border-red-500/30 bg-red-500/[0.05] px-4 py-3">
          <div className="flex items-center gap-2 text-[12px] font-medium text-red-700"><AlertTriangle className="h-4 w-4" /> Assessment failed</div>
          <p className="mt-1.5 whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-red-700/80">{data.error || "The worker reported a failure without an error message."}</p>
        </div>
      ) : null}

      {status === "cancelled" ? (
        <div className="mt-5 rounded-xl border border-ink-600 bg-ink-850 px-4 py-3 text-[12px] text-ink-300">
          This assessment was cancelled. Partial results received before cancellation are retained below.
        </div>
      ) : null}

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Findings" value={totalFindings} hint={`${data.result_count} normalized results`} icon={<ShieldAlert className="h-4 w-4" />} tone={data.critical > 0 ? "danger" : "default"} />
        <StatCard label="Critical" value={data.critical} hint={`${data.high} high severity`} icon={<AlertTriangle className="h-4 w-4" />} tone={data.critical ? "danger" : "default"} />
        <StatCard label="Duration" value={duration(data.started_at, data.finished_at)} hint={data.started_at ? "From worker start to finish" : "Not started yet"} icon={<Clock className="h-4 w-4" />} />
        <StatCard label="Authorization" value={data.authorization.reference} hint={`Expires ${formatDateTime(data.authorization.expires_at)}`} icon={<ListChecks className="h-4 w-4" />} />
      </div>

      <div className="mt-6">
        <Tabs<Tab>
          value={tab}
          onChange={setTab}
          tabs={[
            { label: "Overview", value: "overview" },
            { label: "Executions", value: "executions", count: data.executions.length },
            { label: "Normalized output", value: "results", count: data.result_count },
            { label: "Findings", value: "findings", count: findings.data?.items.length },
          ]}
        />
      </div>

      <div className="mt-5">
        {tab === "overview" ? (
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
            <div className="min-w-0 space-y-4">
              <Card>
                <CardHeader><CardTitle subtitle="Exact snapshot recorded at queue time">Scope and authorization</CardTitle></CardHeader>
                <CardContent className="grid gap-4 sm:grid-cols-2">
                  <Info label="Target" value={data.target} mono />
                  <Info label="Authorization reference" value={data.authorization.reference} />
                  <Info label="Approved by" value={data.authorization.approved_by_name} />
                  <Info label="Expires" value={formatDateTime(data.authorization.expires_at)} />
                  <Info label="Intrusive permitted" value={data.authorization.intrusive_allowed ? "Yes" : "No"} />
                  <Info label="Private targets" value={data.authorization.allow_private ? "Permitted" : "Not permitted"} />
                  <div className="sm:col-span-2">
                    <Info label="Resolved addresses" value={(data.scope?.resolved_ips ?? []).join(", ") || "Network target or not recorded"} mono />
                  </div>
                  {data.scope?.scope_notes ? <div className="sm:col-span-2"><Info label="Scope notes" value={data.scope.scope_notes} /></div> : null}
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle subtitle="Validated server-side before enqueue">Configuration</CardTitle></CardHeader>
                <CardContent>
                  <pre className="max-h-72 overflow-auto rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-[10.5px] leading-relaxed text-ink-300">{JSON.stringify(data.config, null, 2)}</pre>
                </CardContent>
              </Card>
              {data.summary && Object.keys(data.summary).length > 0 ? (
                <Card>
                  <CardHeader><CardTitle subtitle="Worker-reported summary">Execution summary</CardTitle></CardHeader>
                  <CardContent>
                    <pre className="max-h-64 overflow-auto rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-[10.5px] leading-relaxed text-ink-300">{JSON.stringify(data.summary, null, 2)}</pre>
                  </CardContent>
                </Card>
              ) : null}
            </div>
            <div className="min-w-0 space-y-4">
              <Card>
                <CardHeader><CardTitle subtitle="Findings produced by this scan">Severity distribution</CardTitle></CardHeader>
                <CardContent className="flex flex-col items-center">
                  <SeverityDonut counts={data.severity_counts} total={severityTotal} />
                  <div className="mt-3 grid w-full grid-cols-5 gap-1 border-t border-ink-700/60 pt-3">
                    {severityOrder.map((severity) => (
                      <div key={severity} className="text-center">
                        <div className="text-[12px] font-semibold text-ink-100">{data.severity_counts[severity] ?? 0}</div>
                        <div className="mt-0.5 text-[8.5px] uppercase tracking-wider text-ink-400">{severity}</div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle subtitle="Scanner processes launched">Execution timeline</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {data.executions.length === 0 ? (
                    <p className="text-[11.5px] text-ink-400">No execution records yet. Built-in HTTP checks report results without spawning a binary.</p>
                  ) : (
                    data.executions.map((execution) => (
                      <div key={execution.id} className="flex gap-2.5">
                        <span className={cn("mt-1 h-1.5 w-1.5 shrink-0 rounded-full", execution.status === "completed" ? "bg-lime-400" : execution.status === "failed" ? "bg-red-400" : "bg-amber-400")} />
                        <div className="min-w-0">
                          <p className="text-[11.5px] font-medium text-ink-200">{execution.scanner}</p>
                          <p className="truncate text-[10px] text-ink-400">{execution.status} · {relativeTime(execution.started_at)}{execution.exit_code !== undefined && execution.exit_code !== null ? ` · exit ${execution.exit_code}` : ""}</p>
                        </div>
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        ) : null}

        {tab === "executions" ? (
          <div className="space-y-3">
            {data.executions.length === 0 ? (
              <div className="rounded-xl border border-ink-650 bg-ink-850"><EmptyState icon={<Terminal className="h-4 w-4" />} title="No separate process" description="This assessment used a built-in engine that does not invoke an external binary, or it has not started yet." /></div>
            ) : (
              data.executions.map((execution) => (
                <Card key={execution.id}>
                  <CardHeader>
                    <CardTitle subtitle={execution.command}>{execution.scanner}</CardTitle>
                    <Badge className={execution.status === "completed" ? "border-lime-500/25 bg-lime-500/10 text-lime-700" : execution.status === "failed" ? "border-red-500/25 bg-red-500/10 text-red-700" : ""}>{execution.status}</Badge>
                  </CardHeader>
                  <CardContent>
                    <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-ink-400">
                      <span>started {formatDateTime(execution.started_at)}</span>
                      {execution.finished_at ? <span>finished {formatDateTime(execution.finished_at)}</span> : null}
                      {execution.exit_code !== undefined && execution.exit_code !== null ? <span>exit {execution.exit_code}</span> : null}
                    </div>
                    {execution.error ? <p className="mb-2 rounded border border-red-500/20 bg-red-500/5 px-2 py-1.5 text-[11px] text-red-700">{execution.error}</p> : null}
                    <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-[10px] leading-relaxed text-ink-300">{execution.output_excerpt || "No output captured."}</pre>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        ) : null}

        {tab === "results" ? (
          <QueryState loading={results.isLoading} error={results.error} onRetry={() => void results.refetch()} skeleton={<div className="space-y-2">{Array.from({ length: 3 }).map((_, index) => <Skeleton key={index} className="h-24 w-full rounded-xl" />)}</div>}>
            {(results.data?.items.length ?? 0) === 0 ? (
              <div className="rounded-xl border border-ink-650 bg-ink-850"><EmptyState icon={<Code2 className="h-4 w-4" />} title="No normalized results" description="The scan produced no confirmed findings, or it has not completed." /></div>
            ) : (
              <div className="space-y-2">
                {results.data?.items.map((result) => (
                  <Card key={result.id}>
                    <CardContent className="py-3.5">
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <SeverityBadge severity={result.severity} />
                            <span className="text-[12.5px] font-medium text-ink-100">{result.title}</span>
                          </div>
                          <p className="mt-1 max-w-3xl truncate font-mono text-[10.5px] text-ink-400">{result.endpoint}</p>
                        </div>
                        <div className="flex items-center gap-2 text-[10px] text-ink-400">
                          {result.cve ? <Badge>{result.cve}</Badge> : null}
                          {result.cwe ? <Badge>{result.cwe}</Badge> : null}
                          {result.cvss ? <Badge>CVSS {result.cvss}</Badge> : null}
                        </div>
                      </div>
                      <p className="mt-2 line-clamp-3 text-[11.5px] leading-relaxed text-ink-300">{result.description}</p>
                      {Object.keys(result.evidence ?? {}).length ? (
                        <details className="mt-2">
                          <summary className="cursor-pointer text-[10.5px] text-ink-400 hover:text-ink-300">Evidence</summary>
                          <pre className="mt-1.5 max-h-48 overflow-auto rounded border border-ink-700 bg-ink-950 p-2 font-mono text-[9.5px] leading-relaxed text-ink-400">{JSON.stringify(result.evidence, null, 2)}</pre>
                        </details>
                      ) : null}
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </QueryState>
        ) : null}

        {tab === "findings" ? (
          <TableShell>
            <QueryState loading={findings.isLoading} error={findings.error} skeleton={<Skeleton className="h-40 w-full" />}>
              {(findings.data?.items.length ?? 0) === 0 ? (
                <EmptyState icon={<ShieldAlert className="h-4 w-4" />} title="No findings" description="Findings are linked here after normalization. Run a new assessment after remediating to verify the fix." />
              ) : (
                <table className="table-base">
                  <thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Endpoint</th><th /></tr></thead>
                  <tbody>
                    {findings.data?.items.map((finding) => (
                      <tr key={finding.id}>
                        <td><span className="text-[12px] font-medium text-ink-100">{finding.title}</span>{finding.cve ? <span className="ml-2 font-mono text-[10px] text-ink-400">{finding.cve}</span> : null}</td>
                        <td><SeverityBadge severity={finding.severity} /></td>
                        <td className="text-[11px] capitalize text-ink-300">{finding.status.replace(/_/g, " ")}</td>
                        <td className="max-w-[300px] truncate font-mono text-[10.5px] text-ink-400">{finding.endpoint}</td>
                        <td><Link to={`/findings/${finding.id}`} className="inline-flex items-center gap-1 text-[11px] text-amber-700 hover:text-amber-700">Open <ArrowRight className="h-3 w-3" /></Link></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </QueryState>
          </TableShell>
        ) : null}
      </div>

      <Modal
        open={reportOpen}
        onClose={() => setReportOpen(false)}
        title="Generate assessment report"
        description="Produces a client-ready HTML document and PDF from the findings and evidence linked to this scan."
        footer={
          <>
            <Button variant="ghost" onClick={() => setReportOpen(false)}>Cancel</Button>
            <Button loading={report.isPending} onClick={() => report.mutate()} disabled={reportTitle.trim().length < 3}><FileText className="h-3.5 w-3.5" /> Generate</Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Report title">
            <Input value={reportTitle} onChange={(event) => setReportTitle(event.target.value)} />
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Client name" hint="Optional">
              <Input value={clientName} onChange={(event) => setClientName(event.target.value)} placeholder="Client or business unit" />
            </Field>
            <Field label="Assessor" hint="Optional">
              <Input value={assessorName} onChange={(event) => setAssessorName(event.target.value)} placeholder="Lead assessor" />
            </Field>
          </div>
          <div className="rounded-lg border border-ink-700 bg-ink-900/50 p-3 text-[11px] leading-relaxed text-ink-400">
            The report includes the authorization snapshot, scope, methodology, scanner executions and every finding with its evidence. It is stored immutably with SHA-256 hashes.
          </div>
        </div>
      </Modal>

      {compareOpen ? <CompareModal baseId={data.id} assetId={data.asset_id} onClose={() => setCompareOpen(false)} /> : null}
    </PageTransition>
  );
}

function Info({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-[9px] font-semibold uppercase tracking-[0.13em] text-ink-400">{label}</p>
      <p className={cn("mt-1 break-words text-[11.5px] text-ink-200", mono && "font-mono text-[10.5px] text-ink-300")}>{value || "-"}</p>
    </div>
  );
}

function duration(start?: string, end?: string): string {
  if (!start) return "-";
  const finish = end ? new Date(end).getTime() : Date.now();
  const seconds = Math.max(0, Math.round((finish - new Date(start).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

function CompareModal({ baseId, assetId, onClose }: { baseId: string; assetId: string; onClose: () => void }) {
  const [other, setOther] = useState("");
  const scans = useScans({ asset_id: assetId, per_page: 50, status: "completed" });
  const comparison = useMutation({
    mutationFn: (compareId: string) => api.get<{ new: CompareRow[]; resolved: CompareRow[]; persisting: CompareRow[] }>(`/scans/compare${queryString({ base: baseId, compare: compareId })}`),
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Comparison failed."),
  });
  const rows = comparison.data;
  return (
    <Modal open onClose={onClose} title="Compare assessments" description="Diff by normalized finding fingerprint. Runs against the same asset only." width="max-w-3xl" footer={<Button variant="secondary" onClick={onClose}>Close</Button>}>
      <div className="space-y-4">
        <Field label="Compare with">
          <select value={other} onChange={(event) => { setOther(event.target.value); if (event.target.value) comparison.mutate(event.target.value); }} className="input-base">
            <option value="">Select a completed assessment</option>
            {scans.data?.items.filter((scan) => scan.id !== baseId).map((scan) => (
              <option key={scan.id} value={scan.id}>{scannerLabel(scan.scanner)} · {formatDateTime(scan.created_at)} · {scan.findings} findings</option>
            ))}
          </select>
        </Field>
        {comparison.isPending ? <p className="text-[12px] text-ink-400">Comparing…</p> : null}
        {rows ? (
          <div className="grid gap-3 sm:grid-cols-3">
            <CompareList title="New" tone="red" items={rows.new} />
            <CompareList title="Resolved" tone="lime" items={rows.resolved} />
            <CompareList title="Persisting" tone="amber" items={rows.persisting} />
          </div>
        ) : null}
      </div>
    </Modal>
  );
}

interface CompareRow { fingerprint: string; title: string; severity: Severity; endpoint: string; cve?: string }

function CompareList({ title, tone, items }: { title: string; tone: "red" | "lime" | "amber"; items: CompareRow[] }) {
  const colors = { red: "text-red-700", lime: "text-lime-700", amber: "text-amber-700" };
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900/50 p-3">
      <p className={cn("text-[10px] font-semibold uppercase tracking-[0.12em]", colors[tone])}>{title} · {items.length}</p>
      <div className="mt-2 space-y-2">
        {items.length === 0 ? <p className="text-[10.5px] text-ink-400">None</p> : items.slice(0, 20).map((item) => (
          <div key={item.fingerprint}>
            <p className="line-clamp-2 text-[10.5px] leading-snug text-ink-200">{item.title}</p>
            <p className="mt-0.5 truncate font-mono text-[9px] text-ink-400">{item.endpoint}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function ScanDetailSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-56" />
      <Skeleton className="h-16 w-full rounded-xl" />
      <div className="grid gap-3 sm:grid-cols-4">{Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-24 rounded-xl" />)}</div>
      <Skeleton className="h-72 w-full rounded-xl" />
    </div>
  );
}

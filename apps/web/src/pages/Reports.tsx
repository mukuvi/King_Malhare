import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, ArrowUpRight, Download, ExternalLink, FileText, Plus, Search, ShieldCheck, Trash2 } from "lucide-react";
import { api, ApiError, downloadUrl } from "@/lib/api";
import { useCreateReport, useMe, useReport, useReports, useScans } from "@/hooks/queries";
import { formatDateTime, scannerLabel } from "@/lib/utils";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, EmptyState, Field, Input, Modal, PageHeader, PageTransition, Pagination, QueryState, Select, Skeleton, SkeletonTable, StatCard, TableShell } from "@/components/ui";

export function ReportsPage() {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const reports = useReports({ search, page, per_page: 20, status });
  const me = useMe();
  const canGenerate = Boolean(me.data?.permissions.includes("reports:write"));

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Deliverables"
        title="Report center"
        description="Immutable HTML and PDF reports assembled from real findings, evidence and the authorization snapshot of the assessment."
        actions={canGenerate ? <Button onClick={() => setCreateOpen(true)}><Plus className="h-3.5 w-3.5" /> Generate report</Button> : null}
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-3">
        <StatCard label="Reports" value={reports.data?.total ?? "-"} hint="All generated in this organization" icon={<FileText className="h-4 w-4" />} loading={reports.isLoading} />
        <StatCard label="Ready" value={(reports.data?.items ?? []).filter((report) => report.status === "ready").length} hint="HTML and PDF artifacts stored" icon={<ShieldCheck className="h-4 w-4" />} loading={reports.isLoading} />
        <StatCard label="Assets in view" value={new Set((reports.data?.items ?? []).map((report) => report.asset_id).filter(Boolean)).size} hint="Distinct assessed assets on this page" icon={<FileText className="h-4 w-4" />} loading={reports.isLoading} />
      </div>

      <div className="mt-5 flex flex-col gap-3 rounded-xl border border-ink-650 bg-ink-850 p-3 sm:flex-row sm:items-center">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
          <Input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} placeholder="Search title or client" className="border-ink-700 bg-ink-900 pl-9" />
        </div>
        <Select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1); }} className="w-auto border-ink-700 bg-ink-900">
          <option value="">All states</option>
          <option value="generating">Generating</option>
          <option value="ready">Ready</option>
          <option value="failed">Failed</option>
        </Select>
      </div>

      <div className="mt-4">
        <QueryState loading={reports.isLoading} error={reports.error} onRetry={() => void reports.refetch()} skeleton={<div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-850"><SkeletonTable rows={6} columns={6} /></div>}>
          <TableShell footer={<Pagination page={reports.data?.page ?? 1} perPage={reports.data?.per_page ?? 20} total={reports.data?.total ?? 0} onPage={setPage} />}>
            {(reports.data?.items.length ?? 0) === 0 ? (
              <EmptyState icon={<FileText className="h-4 w-4" />} title={search || status ? "No reports match" : "No reports generated"} description="Generate a report from a completed assessment. The report preserves scope, methodology, evidence and findings at that point in time." action={<Button size="sm" onClick={() => setCreateOpen(true)}>Generate report</Button>} />
            ) : (
              <table className="table-base">
                <thead><tr><th>Report</th><th>Assessment</th><th>State</th><th>Findings</th><th>Created</th><th /></tr></thead>
                <tbody>
                  {reports.data?.items.map((report) => (
                    <tr key={report.id}>
                      <td>
                        <Link to={`/reports/${report.id}`} className="block">
                          <span className="text-[12.5px] font-medium text-ink-100 hover:text-amber-700">{report.title}</span>
                          <span className="mt-0.5 block text-[10px] text-ink-400">{report.client_name || "Internal"} · {report.created_by ?? "Unknown"}</span>
                        </Link>
                      </td>
                      <td className="text-[11.5px] text-ink-300">{report.asset_name ?? "Finding set"}{report.scanner ? <span className="block text-[10px] text-ink-400">{scannerLabel(report.scanner)}</span> : null}</td>
                      <td><Badge className={report.status === "ready" ? "border-lime-500/25 bg-lime-500/10 text-lime-700" : report.status === "failed" ? "border-red-500/25 bg-red-500/10 text-red-700" : "border-amber-500/25 bg-amber-500/10 text-amber-700"}>{report.status}</Badge></td>
                      <td className="font-mono text-[11.5px] text-ink-200">{report.summary?.findings ?? "-"}</td>
                      <td className="whitespace-nowrap text-[11px] text-ink-400">{formatDateTime(report.created_at)}</td>
                      <td>
                        <div className="flex items-center justify-end gap-1">
                          {report.status === "ready" ? (
                            <>
                              <a href={downloadUrl(`/reports/${report.id}/pdf`)} className="rounded p-1.5 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="Download PDF"><Download className="h-3.5 w-3.5" /></a>
                              <a href={downloadUrl(`/reports/${report.id}/html`)} target="_blank" rel="noopener noreferrer" className="rounded p-1.5 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="Open HTML report"><ExternalLink className="h-3.5 w-3.5" /></a>
                            </>
                          ) : null}
                          <Link to={`/reports/${report.id}`} className="rounded p-1.5 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="View report"><ArrowUpRight className="h-3.5 w-3.5" /></Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </TableShell>
        </QueryState>
      </div>

      <CreateReportModal open={createOpen} onClose={() => setCreateOpen(false)} />
    </PageTransition>
  );
}

function CreateReportModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const scans = useScans({ status: "completed", per_page: 100 });
  const create = useCreateReport();
  const navigate = useNavigate();
  const [scanId, setScanId] = useState("");
  const [title, setTitle] = useState("");
  const [client, setClient] = useState("");
  const [assessor, setAssessor] = useState("");

  const selected = scans.data?.items.find((scan) => scan.id === scanId);

  useEffect(() => {
    if (selected) setTitle(`Security assessment - ${selected.asset_name}`);
  }, [selected]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Generate assessment report"
      description="A complete fourteen-section report is rendered from the selected scan's findings and evidence."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button
            disabled={!title.trim() || !scanId}
            loading={create.isPending}
            onClick={() =>
              create.mutate(
                { title, client_name: client, assessor_name: assessor, scan_id: scanId },
                {
                  onSuccess: (result) => { toast.success("Report generated"); onClose(); navigate(`/reports/${result.id}`); },
                  onError: (err) => toast.error(err instanceof ApiError ? err.message : "Report generation failed."),
                },
              )
            }
          >
            Generate report
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Completed assessment">
          <Select value={scanId} onChange={(event) => setScanId(event.target.value)}>
            <option value="">Select an assessment</option>
            {scans.data?.items.map((scan) => <option key={scan.id} value={scan.id}>{scan.asset_name} · {scannerLabel(scan.scanner)} · {formatDateTime(scan.created_at)}</option>)}
          </Select>
        </Field>
        {scans.data?.items.length === 0 ? <p className="rounded border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-700">No completed assessments yet. Run and finish a scan first.</p> : null}
        <Field label="Report title"><Input value={title} onChange={(event) => setTitle(event.target.value)} /></Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Client" hint="Optional"><Input value={client} onChange={(event) => setClient(event.target.value)} /></Field>
          <Field label="Assessor" hint="Optional"><Input value={assessor} onChange={(event) => setAssessor(event.target.value)} /></Field>
        </div>
        <p className="text-[10.5px] leading-relaxed text-ink-400">Generation is synchronous and may take a few seconds for large scans. Both HTML and PDF artefacts are stored with SHA-256 hashes.</p>
      </div>
    </Modal>
  );
}

export function ReportDetailPage() {
  const { id } = useParams<{ id: string }>();
  const report = useReport(id);
  const client = useQueryClient();
  const navigate = useNavigate();

  const remove = useMutation({
    mutationFn: () => api.delete(`/reports/${id}`),
    onSuccess: () => { toast.success("Report deleted"); void client.invalidateQueries({ queryKey: ["reports"] }); navigate("/reports"); },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not delete the report."),
  });

  if (report.isLoading) return <div className="space-y-4"><Skeleton className="h-8 w-64" /><Skeleton className="h-40 w-full rounded-xl" /><Skeleton className="h-64 w-full rounded-xl" /></div>;
  if (report.isError || !report.data) {
    return <div className="rounded-xl border border-ink-650 bg-ink-850"><EmptyState icon={<FileText className="h-4 w-4" />} title="Report not found" description="This report is unavailable in the current organization." action={<Link to="/reports"><Button variant="secondary">Back to reports</Button></Link>} /></div>;
  }
  const data = report.data;
  const counts = data.summary?.counts ?? {};

  return (
    <PageTransition>
      <Link to="/reports" className="mb-4 inline-flex items-center gap-1.5 text-[11.5px] text-ink-400 hover:text-ink-100"><ArrowLeft className="h-3.5 w-3.5" /> Reports</Link>
      <PageHeader
        eyebrow={data.status === "ready" ? "Ready" : data.status}
        title={data.title}
        description={`${data.client_name || "Internal"} · generated ${formatDateTime(data.created_at)}`}
        actions={
          data.status === "ready" ? (
            <>
              <a href={downloadUrl(`/reports/${data.id}/html`)} target="_blank" rel="noopener noreferrer"><Button variant="secondary" size="sm"><ExternalLink className="h-3.5 w-3.5" /> Open HTML</Button></a>
              <a href={downloadUrl(`/reports/${data.id}/pdf`)}><Button size="sm"><Download className="h-3.5 w-3.5" /> Download PDF</Button></a>
              <Button variant="ghost" size="sm" className="text-ink-400 hover:text-red-700" onClick={() => { if (window.confirm(`Delete report "${data.title}"?`)) remove.mutate(); }}><Trash2 className="h-3.5 w-3.5" /></Button>
            </>
          ) : null
        }
      />
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Badge className={data.status === "ready" ? "border-lime-500/25 bg-lime-500/10 text-lime-700" : "border-red-500/25 bg-red-500/10 text-red-700"}>{data.status}</Badge>
        {data.scanner ? <Badge>{scannerLabel(data.scanner)}</Badge> : null}
        {data.asset_name ? <Link to={`/assets/${data.asset_id}`}><Badge>{data.asset_name}</Badge></Link> : null}
        {data.created_by ? <Badge>by {data.created_by}</Badge> : null}
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {(["critical", "high", "medium", "low"] as const).map((severity) => (
          <Card key={severity} className="p-4">
            <p className="text-[10px] font-semibold uppercase tracking-[0.13em] text-ink-400">{severity}</p>
            <p className="mt-2 text-[26px] font-semibold leading-none text-ink-50">{counts[severity] ?? 0}</p>
          </Card>
        ))}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader><CardTitle subtitle="Artefact integrity and coverage">Report record</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-[11.5px]">
            <Row label="Findings" value={String(data.summary?.findings ?? 0)} />
            <Row label="Scope entries" value={String(data.summary?.scope ?? 0)} />
            <Row label="Posture score" value={`${data.summary?.posture_score ?? "-"}/100`} />
            <Row label="Period" value={`${data.period_start ? formatDateTime(data.period_start) : "-"} → ${data.period_end ? formatDateTime(data.period_end) : "-"}`} />
            <Row label="HTML SHA-256" value={data.summary?.html_sha256 ? `${data.summary.html_sha256.slice(0, 24)}…` : "-"} mono />
            <Row label="PDF SHA-256" value={data.summary?.pdf_sha256 ? `${data.summary.pdf_sha256.slice(0, 24)}…` : "-"} mono />
            {data.scan_id ? <Row label="Assessment" value="Open scan" link={`/scans/${data.scan_id}`} /> : null}
            {data.error ? <p className="rounded border border-red-500/25 bg-red-500/10 px-2 py-1.5 text-[11px] text-red-700">{data.error}</p> : null}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle subtitle="Share with stakeholders">Delivery</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <p className="text-[11.5px] leading-relaxed text-ink-400">The HTML report is self-contained and suitable for browser delivery. The PDF is generated server-side with the same findings and is intended for management and client distribution.</p>
            {data.status === "ready" ? (
              <div className="flex flex-col gap-2">
                <a href={downloadUrl(`/reports/${data.id}/pdf`)} className="w-full"><Button className="w-full"><Download className="h-3.5 w-3.5" /> Download PDF</Button></a>
                <a href={downloadUrl(`/reports/${data.id}/html`)} target="_blank" rel="noopener noreferrer" className="w-full"><Button variant="secondary" className="w-full">Open HTML in new tab</Button></a>
              </div>
            ) : (
              <p className="rounded border border-ink-700 bg-ink-900/50 px-2.5 py-2 text-[11px] text-ink-400">Artefacts are not available because generation did not complete.</p>
            )}
            <div className="flex items-start gap-2 rounded border border-ink-700 bg-ink-900/40 px-2.5 py-2 text-[10.5px] leading-relaxed text-ink-400"><ShieldCheck className="mt-0.5 h-3 w-3 shrink-0" /> Access is restricted to this organization. Reports contain sensitive weakness detail.</div>
          </CardContent>
        </Card>
      </div>
    </PageTransition>
  );
}

function Row({ label, value, mono, link }: { label: string; value: string; mono?: boolean; link?: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-ink-700/50 pb-2">
      <span className="text-ink-400">{label}</span>
      {link ? <Link to={link} className="text-amber-700 hover:text-amber-700">{value}</Link> : <span className={`max-w-[70%] break-all text-right text-ink-200 ${mono ? "font-mono text-[10px]" : ""}`}>{value}</span>}
    </div>
  );
}

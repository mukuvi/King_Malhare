import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Activity,
  ArrowRight,
  Boxes,
  CircleAlert,
  FileText,
  Plus,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Target,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { useMe, useOverview, useTrends } from "@/hooks/queries";
import { categoryLabel, formatDate, formatDateTime, relativeTime, scannerLabel, severityOrder } from "@/lib/utils";
import { Button, Card, CardContent, CardHeader, CardTitle, EmptyState, Input, Modal, PageHeader, PageTransition, Progress, QueryState, ScanStatusBadge, Skeleton, StatCard, TableShell } from "@/components/ui";
import { PostureGauge, SeverityDonut, TrendChart } from "@/components/domain/charts";

function humanizeAction(action: string): string {
  return action.replace(/[._]/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export function DashboardPage() {
  const overview = useOverview();
  const trends = useTrends(30);
  const me = useMe();
  const canStop = me.data?.permissions.includes("org:manage");
  const canScan = me.data?.permissions.includes("scans:write");
  const [stopOpen, setStopOpen] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const client = useQueryClient();

  const stop = useMutation({
    mutationFn: (clear: boolean) => (clear ? api.delete("/emergency-stop") : api.post<{ cancelled: number }>("/scans/emergency-stop")),
    onSuccess: (result, clear) => {
      if (clear) {
        toast.success("Emergency stop cleared", { description: "Assessments can be started again." });
      } else {
        const cancelled = (result as { cancelled?: number })?.cancelled ?? 0;
        toast.warning("Emergency stop activated", { description: `${cancelled} active assessment${cancelled === 1 ? "" : "s"} cancelled. New scans are blocked.` });
      }
      setStopOpen(false);
      setConfirmText("");
      void client.invalidateQueries({ queryKey: ["overview"] });
      void client.invalidateQueries({ queryKey: ["org"] });
      void client.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not update the emergency stop."),
  });

  const chartData = useMemo(
    () =>
      (trends.data?.items ?? []).map((point) => ({
        label: new Date(point.date).toLocaleDateString("en-GB", { day: "2-digit", month: "short" }),
        critical: point.critical,
        high: point.high,
        medium: point.medium,
        low: point.low,
        scans: point.scans,
      })),
    [trends.data],
  );

  const data = overview.data;
  const critical = data?.findings.critical ?? 0;
  const high = data?.findings.high ?? 0;
  const openFindings = data?.findings.open ?? 0;

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Operations"
        title="Security overview"
        description="Live posture across the assets and assessments in this organization. Every value is computed from the database."
        actions={
          <>
            {canStop ? (
              data?.emergency_stop ? (
                <Button variant="secondary" size="sm" onClick={() => stop.mutate(true)} loading={stop.isPending}>
                  <ShieldCheck className="h-3.5 w-3.5" /> Clear emergency stop
                </Button>
              ) : (
                <Button variant="danger" size="sm" onClick={() => setStopOpen(true)}>
                  <Siren className="h-3.5 w-3.5" /> Emergency stop
                </Button>
              )
            ) : null}
            {canScan ? <Link to="/scans/new"><Button size="sm"><Plus className="h-3.5 w-3.5" /> New assessment</Button></Link> : null}
          </>
        }
      />

      <QueryState
        loading={overview.isLoading}
        error={overview.error}
        onRetry={() => void overview.refetch()}
        skeleton={
          <div className="mt-8 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-[112px] rounded-xl" />)}
          </div>
        }
      >
        {data ? (
          <div className="mt-7 space-y-4">
            {data.assets.active === 0 ? (
              <Card className="border-amber-500/25 bg-amber-500/[0.035]">
                <CardContent className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-300">
                      <Target className="h-4 w-4" />
                    </div>
                    <div>
                      <p className="text-[13px] font-semibold text-ink-50">Start with an authorized target</p>
                      <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-ink-300">
                        Register an asset, attach written authorization, then choose a non-intrusive profile. Findings and statistics only appear after real scanner output.
                      </p>
                    </div>
                  </div>
                  <Link to="/assets?new=1"><Button size="sm">Register asset <ArrowRight className="h-3.5 w-3.5" /></Button></Link>
                </CardContent>
              </Card>
            ) : null}

            {data.assets.without_authorization > 0 ? (
              <Link to="/assets" className="block">
                <Card className="border-orange-500/25 bg-orange-500/[0.035] transition-colors hover:border-orange-500/40">
                  <CardContent className="flex items-center justify-between gap-4 px-5 py-3.5">
                    <div className="flex items-center gap-2.5 text-[12px] text-orange-200">
                      <CircleAlert className="h-4 w-4" />
                      {data.assets.without_authorization} active asset{data.assets.without_authorization === 1 ? "" : "s"} cannot be assessed until an authorization is recorded.
                    </div>
                    <ArrowRight className="h-3.5 w-3.5 text-orange-300" />
                  </CardContent>
                </Card>
              </Link>
            ) : null}

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard label="Posture score" value={`${data.posture_score}/100`} hint="Weighted by severity against active assets" icon={<ShieldCheck className="h-4 w-4" />} tone={data.posture_score >= 70 ? "good" : data.posture_score >= 50 ? "warn" : "danger"} />
              <StatCard label="Active assets" value={data.assets.active} hint={`${data.assets.without_authorization} without authorization`} icon={<Boxes className="h-4 w-4" />} to="/assets" />
              <StatCard label="Critical findings" value={critical} hint={`${high} high · ${openFindings} open in total`} icon={<ShieldAlert className="h-4 w-4" />} tone={critical > 0 ? "danger" : "default"} to="/findings?severity=critical" />
              <StatCard label="Active assessments" value={data.scans.active} hint={`${data.scans.last_24h} started in the last 24 hours`} icon={<Radar className="h-4 w-4" />} tone={data.scans.failed_24h > 0 ? "warn" : "default"} to="/scans" />
            </div>

            <div className="grid gap-4 xl:grid-cols-[1.55fr_1fr]">
              <Card>
                <CardHeader>
                  <CardTitle subtitle="Confirmed findings first seen each day">Vulnerability trend · 30 days</CardTitle>
                  <Link to="/findings" className="text-[11px] text-ink-400 hover:text-ink-100">View findings</Link>
                </CardHeader>
                <CardContent>
                  <TrendChart data={chartData} loading={trends.isLoading} />
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle subtitle="Open findings by severity">Current exposure</CardTitle>
                  <Link to="/findings" className="text-[11px] text-ink-400 hover:text-ink-100">Details</Link>
                </CardHeader>
                <CardContent className="flex flex-col items-center">
                  <SeverityDonut counts={data.findings} total={openFindings} />
                  <div className="mt-2 grid w-full grid-cols-5 gap-1 border-t border-ink-700/70 pt-3">
                    {severityOrder.map((severity) => (
                      <Link key={severity} to={`/findings?severity=${severity}`} className="group text-center">
                        <div className="text-[12px] font-semibold text-ink-100">{data.findings[severity]}</div>
                        <div className="mt-0.5 text-[8.5px] uppercase tracking-wider text-ink-500 group-hover:text-ink-300">{severity}</div>
                      </Link>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="grid gap-4 xl:grid-cols-[1.55fr_1fr]">
              <div>
                <div className="mb-2.5 flex items-center justify-between">
                  <h2 className="text-[13px] font-semibold text-ink-100">Recent assessments</h2>
                  <Link to="/scans" className="text-[11px] text-ink-400 hover:text-ink-100">Scan center</Link>
                </div>
                <TableShell>
                  {data.recent_scans.length === 0 ? (
                    <EmptyState icon={<Radar className="h-4 w-4" />} title="No assessments yet" description="Once an authorized scan runs, its real progress and findings appear here." action={<Link to="/scans/new"><Button size="sm">Start an assessment</Button></Link>} />
                  ) : (
                    <table className="table-base">
                      <thead><tr><th>Assessment</th><th>Status</th><th>Findings</th><th>Started</th></tr></thead>
                      <tbody>
                        {data.recent_scans.map((scan) => (
                          <tr key={scan.id}>
                            <td>
                              <Link to={`/scans/${scan.id}`} className="block">
                                <div className="text-[12.5px] font-medium text-ink-100">{scan.asset_name}</div>
                                <div className="mt-0.5 text-[10.5px] text-ink-400">{scannerLabel(scan.scanner)} · {categoryLabel(scan.category)}</div>
                              </Link>
                            </td>
                            <td>
                              <ScanStatusBadge status={scan.status} />
                              {scan.status === "running" || scan.status === "queued" ? <div className="mt-1.5 w-20"><Progress value={scan.progress} /></div> : null}
                            </td>
                            <td className="font-mono text-[11.5px] text-ink-200">{scan.findings}</td>
                            <td className="text-[11px] text-ink-400">{relativeTime(scan.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </TableShell>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle subtitle="Audit events across the workspace">Recent activity</CardTitle>
                  <Link to="/audit" className="text-[11px] text-ink-400 hover:text-ink-100">Audit</Link>
                </CardHeader>
                <CardContent className="p-0">
                  {data.activity.length === 0 ? (
                    <div className="px-5 py-8 text-center text-[12px] text-ink-400">No activity has been recorded yet.</div>
                  ) : (
                    <div className="divide-y divide-ink-700/60">
                      {data.activity.slice(0, 7).map((event) => (
                        <div key={event.id} className="flex gap-2.5 px-4 py-2.5">
                          <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-amber-400/70" />
                          <div className="min-w-0">
                            <p className="truncate text-[11.5px] text-ink-200">{humanizeAction(event.action)}</p>
                            <p className="mt-0.5 text-[10px] text-ink-500">{event.actor ?? "System"} · {relativeTime(event.created_at)}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <Card>
                <CardContent className="flex items-center gap-4 py-5">
                  <PostureGauge score={data.posture_score} size={116} />
                  <div>
                    <p className="text-[12px] font-medium text-ink-100">Posture is a trend signal</p>
                    <p className="mt-1 text-[11px] leading-relaxed text-ink-400">It weights open findings by severity and normalises against active assets. Review the finding register before drawing conclusions.</p>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="flex items-start gap-3 py-5">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-ink-600 bg-ink-800 text-ink-300"><FileText className="h-4 w-4" /></div>
                  <div>
                    <p className="text-[12px] font-medium text-ink-100">{data.reports} report{data.reports === 1 ? "" : "s"} generated</p>
                    <p className="mt-1 text-[11px] leading-relaxed text-ink-400">Reports preserve the scope, methodology and evidence for the assessment that produced them.</p>
                    <Link to="/reports" className="mt-2 inline-flex items-center gap-1 text-[11px] text-amber-300 hover:text-amber-200">Report center <ArrowRight className="h-3 w-3" /></Link>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="flex items-start gap-3 py-5">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-ink-600 bg-ink-800 text-ink-300"><Activity className="h-4 w-4" /></div>
                  <div>
                    <p className="text-[12px] font-medium text-ink-100">Scanner fleet</p>
                    <p className="mt-1 text-[11px] leading-relaxed text-ink-400">Tool availability comes from worker heartbeats. Missing binaries are reported honestly, never simulated.</p>
                    <Link to="/integrations" className="mt-2 inline-flex items-center gap-1 text-[11px] text-amber-300 hover:text-amber-200">Check integrations <ArrowRight className="h-3 w-3" /></Link>
                  </div>
                </CardContent>
              </Card>
            </div>

            {data.scans.last_at ? <p className="text-[10.5px] text-ink-500">Last assessment queued {formatDateTime(data.scans.last_at)} · last data refresh {formatDate(new Date().toISOString())}</p> : null}
          </div>
        ) : null}
      </QueryState>

      <Modal
        open={stopOpen}
        onClose={() => { setStopOpen(false); setConfirmText(""); }}
        title="Activate emergency stop"
        description="This cancels every queued and running assessment in the organization and blocks new ones."
        footer={
          <>
            <Button variant="ghost" onClick={() => setStopOpen(false)}>Cancel</Button>
            <Button variant="danger" disabled={confirmText !== "STOP"} loading={stop.isPending} onClick={() => stop.mutate(false)}>
              <Siren className="h-3.5 w-3.5" /> Activate stop
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="rounded-lg border border-red-500/25 bg-red-500/5 p-3 text-[12px] leading-relaxed text-red-200">
            Running scanner processes are terminated by the worker. Partial results already submitted remain in the finding register. This action is audited.
          </div>
          <div>
            <p className="mb-2 text-[11.5px] text-ink-300">Type <span className="font-mono text-red-300">STOP</span> to confirm.</p>
            <Input value={confirmText} onChange={(event) => setConfirmText(event.target.value.toUpperCase())} placeholder="STOP" autoFocus />
          </div>
        </div>
      </Modal>
    </PageTransition>
  );
}

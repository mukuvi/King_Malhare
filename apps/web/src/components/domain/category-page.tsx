import { Link } from "react-router-dom";
import { ArrowRight, CheckCircle2, CircleSlash, FileSearch, Info, Radar, ShieldAlert, ShieldCheck } from "lucide-react";
import { useMe, useProfiles, useScans, useScanners } from "@/hooks/queries";
import { categoryLabel, formatDateTime, scannerLabel } from "@/lib/utils";
import type { Category } from "@/types";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, EmptyState, PageHeader, PageTransition, Progress, QueryState, ScanStatusBadge, Skeleton, SkeletonTable, StatCard, TableShell } from "@/components/ui";

export function CategoryPage({
  category,
  eyebrow,
  title,
  description,
  capabilities,
  warning,
  extra,
}: {
  category: Category;
  eyebrow: string;
  title: string;
  description: string;
  capabilities: Array<{ title: string; text: string; scanner?: string }>;
  warning?: string;
  extra?: React.ReactNode;
}) {
  const scanners = useScanners();
  const profiles = useProfiles();
  const scans = useScans({ category, per_page: 10 });
  const me = useMe();
  const available = (scanners.data?.items ?? []).filter((scanner) => scanner.category === category);
  const online = available.filter((scanner) => scanner.status === "available").length;
  const categoryProfiles = (profiles.data?.items ?? []).filter((profile) => profile.category === category);
  const canScan = me.data?.permissions.includes("scans:write");

  return (
    <PageTransition>
      <PageHeader
        eyebrow={eyebrow}
        title={title}
        description={description}
        actions={canScan ? <Link to={`/scans/new?category=${category}`}><Button><Radar className="h-3.5 w-3.5" /> Start assessment</Button></Link> : null}
      />

      {warning ? (
        <div className="mt-5 flex items-start gap-2.5 rounded-xl border border-amber-500/25 bg-amber-500/[0.045] px-4 py-3 text-[11.5px] leading-relaxed text-amber-100">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          {warning}
        </div>
      ) : null}

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Tools available" value={`${online}/${available.length}`} hint="Live heartbeat from scanner workers" icon={<ShieldCheck className="h-4 w-4" />} tone={online === available.length && available.length > 0 ? "good" : "warn"} loading={scanners.isLoading} />
        <StatCard label="Profiles" value={categoryProfiles.length} hint={`${categoryProfiles.filter((profile) => profile.is_system).length} system presets`} icon={<FileSearch className="h-4 w-4" />} loading={profiles.isLoading} />
        <StatCard label="Assessments" value={scans.data?.total ?? "—"} hint="All time in this category" icon={<Radar className="h-4 w-4" />} loading={scans.isLoading} />
        <StatCard label="Active" value={(scans.data?.items ?? []).filter((scan) => ["queued", "initializing", "running"].includes(scan.status)).length} hint="Currently queued or executing" icon={<Radar className="h-4 w-4" />} loading={scans.isLoading} />
      </div>

      {extra ? <div className="mt-4">{extra}</div> : null}

      <div className="mt-6 grid gap-4 xl:grid-cols-[1.25fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle subtitle="Implemented checks and the tool responsible">Assessment coverage</CardTitle>
            <Badge>{categoryLabel(category)}</Badge>
          </CardHeader>
          <CardContent className="divide-y divide-ink-700/60 p-0">
            {capabilities.map((capability) => {
              const scanner = capability.scanner ? available.find((item) => item.name === capability.scanner) : undefined;
              return (
                <div key={capability.title} className="flex items-start gap-3 px-5 py-3.5">
                  <div className="mt-0.5">
                    {scanner && scanner.status !== "available" ? <CircleSlash className="h-4 w-4 text-ink-500" /> : <CheckCircle2 className="h-4 w-4 text-lime-400/80" />}
                  </div>
                  <div className="min-w-0">
                    <p className="text-[12px] font-medium text-ink-100">{capability.title}</p>
                    <p className="mt-0.5 text-[11px] leading-relaxed text-ink-400">{capability.text}</p>
                  </div>
                  {capability.scanner ? (
                    <span className={`ml-auto shrink-0 text-[9.5px] ${scanner?.status === "available" ? "text-ink-500" : "text-orange-400/80"}`}>
                      {scannerLabel(capability.scanner)}
                    </span>
                  ) : null}
                </div>
              );
            })}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle subtitle="Availability is detected by the worker, not assumed">Scanner fleet</CardTitle>
            <Link to="/integrations" className="text-[11px] text-ink-400 hover:text-ink-100">Integrations</Link>
          </CardHeader>
          <QueryState loading={scanners.isLoading} error={scanners.error} skeleton={<div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, index) => <Skeleton key={index} className="h-14 w-full" />)}</div>}>
            <div className="divide-y divide-ink-700/60">
              {available.length === 0 ? (
                <div className="px-5 py-8 text-center text-[12px] text-ink-400">No scanners are mapped to this category.</div>
              ) : (
                available.map((scanner) => (
                  <div key={scanner.name} className="px-5 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[12px] font-medium text-ink-100">{scanner.label}</span>
                      <span className={`inline-flex items-center gap-1.5 text-[9.5px] uppercase tracking-wider ${scanner.status === "available" ? "text-lime-300" : scanner.status === "offline" ? "text-ink-500" : "text-orange-300"}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${scanner.status === "available" ? "bg-lime-400" : scanner.status === "offline" ? "bg-ink-500" : "bg-orange-400"}`} />
                        {scanner.status}
                      </span>
                    </div>
                    <p className="mt-1 text-[10.5px] leading-relaxed text-ink-400">{scanner.detail}</p>
                    {scanner.version ? <p className="mt-1 truncate font-mono text-[9.5px] text-ink-500">{scanner.version}</p> : null}
                  </div>
                ))
              )}
            </div>
          </QueryState>
        </Card>
      </div>

      <div className="mt-5">
        <div className="mb-2.5 flex items-center justify-between">
          <h2 className="text-[13px] font-semibold text-ink-100">Recent {categoryLabel(category).toLowerCase()} assessments</h2>
          <Link to={`/scans`} className="text-[11px] text-ink-400 hover:text-ink-100">Scan center <ArrowRight className="ml-1 inline h-3 w-3" /></Link>
        </div>
        <TableShell>
          <QueryState loading={scans.isLoading} error={scans.error} skeleton={<SkeletonTable rows={4} columns={5} />}>
            {(scans.data?.items.length ?? 0) === 0 ? (
              <EmptyState icon={<Radar className="h-4 w-4" />} title={`No ${categoryLabel(category).toLowerCase()} assessments`} description="Queue a real assessment against an authorized asset to see execution state and findings here." action={canScan ? <Link to={`/scans/new?category=${category}`}><Button size="sm">Start assessment</Button></Link> : undefined} />
            ) : (
              <table className="table-base">
                <thead><tr><th>Asset</th><th>Scanner</th><th>Status</th><th>Progress</th><th>Findings</th><th>Queued</th></tr></thead>
                <tbody>
                  {scans.data?.items.map((scan) => (
                    <tr key={scan.id}>
                      <td><Link to={`/scans/${scan.id}`} className="text-[12px] font-medium text-ink-100 hover:text-amber-300">{scan.asset_name}</Link><div className="mt-0.5 max-w-[300px] truncate font-mono text-[10px] text-ink-500">{scan.target}</div></td>
                      <td className="text-[11.5px] text-ink-300">{scannerLabel(scan.scanner)}</td>
                      <td><ScanStatusBadge status={scan.status} /></td>
                      <td><div className="w-24"><Progress value={scan.progress} tone={scan.status === "failed" ? "red" : scan.status === "completed" ? "lime" : "amber"} /></div></td>
                      <td className="font-mono text-[11.5px] text-ink-200">{scan.findings}</td>
                      <td className="text-[11px] text-ink-400">{formatDateTime(scan.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </QueryState>
        </TableShell>
      </div>

      <div className="mt-5 flex items-start gap-2 rounded-lg border border-ink-700 bg-ink-850/50 px-4 py-3 text-[10.5px] leading-relaxed text-ink-400">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        Assessment results reflect the configured profile and the reachability of the target from the scanner worker. A clean result does not prove the absence of vulnerabilities.
      </div>
    </PageTransition>
  );
}

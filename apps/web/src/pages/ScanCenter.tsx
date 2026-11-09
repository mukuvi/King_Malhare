import { useDeferredValue, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Activity, ArrowRight, Plus, Radar, Search, ShieldAlert } from "lucide-react";
import { useOverview, useScans, useMe } from "@/hooks/queries";
import { categoryLabel, formatDateTime, scannerLabel } from "@/lib/utils";
import { Badge, Button, EmptyState, Input, PageHeader, PageTransition, Pagination, Progress, QueryState, ScanStatusBadge, SkeletonTable, Stagger, StaggerItem, StatCard, TableShell, Tabs } from "@/components/ui";

type Tab = "all" | "active" | "completed" | "failed";

export function ScanCenterPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const initialTab = (params.get("status") as Tab) || "all";
  const [tab, setTab] = useState<Tab>(["all", "active", "completed", "failed"].includes(initialTab) ? initialTab : "all");
  const [search, setSearch] = useState("");
  const searchValue = useDeferredValue(search);
  const [scanner, setScanner] = useState("");
  const [category, setCategory] = useState("");
  const [page, setPage] = useState(1);
  const assetId = params.get("asset_id") ?? "";
  const overview = useOverview();
  const me = useMe();
  const canScan = Boolean(me.data?.permissions.includes("scans:write"));

  const statusParam = useMemo(() => {
    if (tab === "active") return "active";
    if (tab === "completed") return "completed";
    if (tab === "failed") return "failed";
    return "";
  }, [tab]);

  const query = useScans({
    page,
    per_page: 20,
    status: statusParam,
    scanner,
    category,
    search: searchValue,
    asset_id: assetId || undefined,
  });

  useEffect(() => {
    setPage(1);
  }, [tab, searchValue, scanner, category]);

  const scans = query.data?.items ?? [];
  const running = overview.data?.scans.active ?? 0;

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Assessments"
        title="Scan center"
        description="Every scan is a real queued job with an authorization snapshot, live worker state and normalized output."
        actions={canScan ? <Link to="/scans/new"><Button><Plus className="h-3.5 w-3.5" /> New assessment</Button></Link> : undefined}
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Active now" value={running} hint="Queued, initializing or running" icon={<Activity className="h-4 w-4" />} tone={running > 0 ? "warn" : "default"} loading={overview.isLoading} />
        <StatCard label="Completed" value={overview.data?.scans.completed ?? "-"} hint="Finished with real scanner output" icon={<Radar className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Failed (24h)" value={overview.data?.scans.failed_24h ?? "-"} hint="Check execution output for cause" icon={<ShieldAlert className="h-4 w-4" />} tone={(overview.data?.scans.failed_24h ?? 0) > 0 ? "danger" : "default"} loading={overview.isLoading} />
        <StatCard label="Last 24 hours" value={overview.data?.scans.last_24h ?? "-"} hint={overview.data?.scans.last_at ? `Last queued ${formatDateTime(overview.data.scans.last_at)}` : "No assessments yet"} icon={<Radar className="h-4 w-4" />} loading={overview.isLoading} />
      </div>

      <div className="mt-6">
        <Tabs<Tab>
          tabs={[
            { label: "All assessments", value: "all" },
            { label: "Active", value: "active", count: running },
            { label: "Completed", value: "completed" },
            { label: "Failed", value: "failed" },
          ]}
          value={tab}
          onChange={(value) => {
            setTab(value);
            if (value === "all") params.delete("status");
            else params.set("status", value);
            setParams(params, { replace: true });
          }}
        />
      </div>

      <div className="mt-4 flex flex-col gap-3 rounded-xl border border-ink-650 bg-ink-850 p-3 lg:flex-row lg:items-center">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
          <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search asset or target" className="border-ink-700 bg-ink-900 pl-9" />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select value={scanner} onChange={(event) => setScanner(event.target.value)} className="input-base w-auto border-ink-700 bg-ink-900">
            <option value="">All scanners</option>
            {["nmap", "nuclei", "http-baseline", "zap", "nikto", "gobuster", "testssl", "sqlmap", "trivy", "prowler", "scoutsuite", "checkov", "aws-posture", "auth-baseline"].map((name) => <option key={name} value={name}>{scannerLabel(name)}</option>)}
          </select>
          <select value={category} onChange={(event) => setCategory(event.target.value)} className="input-base w-auto border-ink-700 bg-ink-900">
            <option value="">All categories</option>
            <option value="web">Web</option>
            <option value="network">Network</option>
            <option value="cloud">Cloud</option>
            <option value="authentication">Authentication</option>
            <option value="infrastructure">Infrastructure</option>
          </select>
          {assetId ? (
            <Button variant="ghost" size="sm" onClick={() => { params.delete("asset_id"); setParams(params, { replace: true }); }}>
              Asset filter active
            </Button>
          ) : null}
        </div>
      </div>

      <div className="mt-4">
        <QueryState loading={query.isLoading} error={query.error} onRetry={() => void query.refetch()} skeleton={<div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-850"><SkeletonTable rows={7} columns={6} /></div>}>
          <TableShell footer={<Pagination page={query.data?.page ?? 1} perPage={query.data?.per_page ?? 20} total={query.data?.total ?? 0} onPage={setPage} />}>
            {scans.length === 0 ? (
              <EmptyState icon={<Radar className="h-4 w-4" />} title={tab === "all" ? "No assessments found" : `No ${tab} assessments`} description={tab === "all" ? "Queue a scan against an authorized asset. Nothing runs until an authorization record is active." : "Try another tab, or adjust the search and filters."} action={<Link to="/scans/new"><Button size="sm">New assessment</Button></Link>} />
            ) : (
              <>
              <div className="hidden md:block">
              <table className="table-base">
                <thead><tr><th>Assessment</th><th>Status</th><th>Progress</th><th>Findings</th><th>Queued</th><th /></tr></thead>
                <tbody>
                  {scans.map((scan) => (
                    <tr key={scan.id} className="cursor-pointer" onClick={() => navigate(`/scans/${scan.id}`)}>
                      <td>
                        <div className="flex items-start gap-2.5">
                          <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400/70" />
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-[12.5px] font-medium text-ink-100">{scan.asset_name}</span>
                              {scan.intrusive ? <Badge className="border-orange-500/25 bg-orange-500/10 text-[9px] text-orange-700">intrusive</Badge> : null}
                            </div>
                            <div className="mt-0.5 max-w-[360px] truncate font-mono text-[10px] text-ink-400">{scan.target}</div>
                            <div className="mt-1 text-[10px] text-ink-400">{scannerLabel(scan.scanner)} · {categoryLabel(scan.category)}</div>
                          </div>
                        </div>
                      </td>
                      <td><ScanStatusBadge status={scan.status} /></td>
                      <td>
                        <div className="w-28">
                          <Progress value={scan.progress} tone={scan.status === "failed" ? "red" : scan.status === "completed" ? "lime" : "amber"} />
                          <span className="mt-1 block truncate text-[9.5px] text-ink-400">{scan.phase}{scan.status === "running" ? ` · ${scan.progress}%` : ""}</span>
                        </div>
                      </td>
                      <td>
                        <div className="flex items-center gap-1.5 font-mono text-[11.5px]">
                          <span className="text-ink-100">{scan.findings}</span>
                          {scan.critical > 0 ? <span className="text-red-700">· {scan.critical}C</span> : null}
                          {scan.high > 0 ? <span className="text-orange-700">· {scan.high}H</span> : null}
                        </div>
                      </td>
                      <td className="whitespace-nowrap text-[11px] text-ink-400">{formatDateTime(scan.created_at)}</td>
                      <td><Link to={`/scans/${scan.id}`} className="inline-flex items-center gap-1 text-[11px] text-ink-400 hover:text-amber-700">Open <ArrowRight className="h-3 w-3" /></Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
              <Stagger className="divide-y divide-ink-700/70 md:hidden">
                {scans.map((scan) => (
                  <StaggerItem key={scan.id}>
                  <Link to={`/scans/${scan.id}`} className="block px-4 py-3.5 transition-colors hover:bg-ink-800/50">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[12.5px] font-medium text-ink-100">{scan.asset_name}</span>
                          {scan.intrusive ? <Badge className="border-orange-500/25 bg-orange-500/10 text-[9px] text-orange-700">intrusive</Badge> : null}
                        </div>
                        <p className="mt-0.5 break-all font-mono text-[10px] text-ink-400">{scan.target}</p>
                        <p className="mt-1 text-[10px] text-ink-400">{scannerLabel(scan.scanner)} · {categoryLabel(scan.category)}</p>
                      </div>
                      <ScanStatusBadge status={scan.status} />
                    </div>
                    <div className="mt-2 flex items-center gap-3">
                      <div className="min-w-0 flex-1">
                        <Progress value={scan.progress} tone={scan.status === "failed" ? "red" : scan.status === "completed" ? "lime" : "amber"} />
                        <span className="mt-1 block truncate text-[9.5px] text-ink-400">{scan.phase}{scan.status === "running" ? ` · ${scan.progress}%` : ""}</span>
                      </div>
                      <div className="flex items-center gap-1.5 font-mono text-[11.5px]">
                        <span className="text-ink-100">{scan.findings}</span>
                        {scan.critical > 0 ? <span className="text-red-700">· {scan.critical}C</span> : null}
                        {scan.high > 0 ? <span className="text-orange-700">· {scan.high}H</span> : null}
                      </div>
                    </div>
                    <div className="mt-2 flex items-center justify-between text-[10px] text-ink-400">
                      <span>{formatDateTime(scan.created_at)}</span>
                      <span className="inline-flex items-center gap-1 text-amber-700">Open <ArrowRight className="h-3 w-3" /></span>
                    </div>
                  </Link>
                  </StaggerItem>
                ))}
              </Stagger>
              </>
            )}
          </TableShell>
        </QueryState>
      </div>
    </PageTransition>
  );
}

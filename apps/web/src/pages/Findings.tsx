import { useDeferredValue, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AlertTriangle, Filter, Search, ShieldAlert, UserRound } from "lucide-react";
import { useAssets, useFindings, useOverview } from "@/hooks/queries";
import { formatDate, severityOrder } from "@/lib/utils";
import type { FindingStatus } from "@/types";
import { Badge, Button, EmptyState, FindingStatusBadge, Input, PageHeader, PageTransition, Pagination, QueryState, Select, SeverityBadge, SkeletonTable, Stagger, StaggerItem, StatCard, TableShell, Tabs } from "@/components/ui";

export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const [severity, setSeverity] = useState(params.get("severity") ?? "");
  const [status, setStatus] = useState(params.get("status") ?? "");
  const [assetId, setAssetId] = useState(params.get("asset_id") ?? "");
  const [search, setSearch] = useState(params.get("search") ?? "");
  const searchValue = useDeferredValue(search);
  const [sort, setSort] = useState("severity");
  const [page, setPage] = useState(1);
  const findings = useFindings({ severity, status, asset_id: assetId, search: searchValue, sort, order: sort === "severity" ? "asc" : "desc", page, per_page: 25 });
  const assets = useAssets({ per_page: 100, status: "active" });
  const overview = useOverview();

  useEffect(() => {
    setPage(1);
  }, [severity, status, assetId, searchValue, sort]);

  const items = findings.data?.items ?? [];

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Risk register"
        title="Findings"
        description="Deduplicated across scans by fingerprint. Triage survives re-assessment; evidence and scanner output remain traceable."
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Open findings" value={overview.data?.findings.open ?? "-"} hint="Excludes fixed, false positive, accepted risk" icon={<ShieldAlert className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Critical" value={overview.data?.findings.critical ?? "-"} hint="Immediate remediation recommended" tone={(overview.data?.findings.critical ?? 0) > 0 ? "danger" : "default"} icon={<AlertTriangle className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="High" value={overview.data?.findings.high ?? "-"} hint="Prioritise in the current cycle" tone={(overview.data?.findings.high ?? 0) > 0 ? "warn" : "default"} icon={<ShieldAlert className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Total recorded" value={overview.data?.findings.total ?? "-"} hint="Includes fixed and accepted items" icon={<AlertTriangle className="h-4 w-4" />} loading={overview.isLoading} />
      </div>

      <div className="mt-6">
        <Tabs
          value={severity || "all"}
          onChange={(value) => {
            const next = value === "all" ? "" : value;
            setSeverity(next);
            if (next) params.set("severity", next); else params.delete("severity");
            setParams(params, { replace: true });
          }}
          tabs={[
            { label: "All severities", value: "all" },
            ...severityOrder.map((item) => ({ label: item[0].toUpperCase() + item.slice(1), value: item, count: overview.data?.findings[item as keyof typeof overview.data.findings] })),
          ]}
        />
      </div>

      <div className="mt-4 flex flex-col gap-3 rounded-xl border border-ink-650 bg-ink-850 p-3 lg:flex-row lg:items-center">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
          <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search title, endpoint or CVE" className="border-ink-700 bg-ink-900 pl-9" />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5">
            <Filter className="h-3.5 w-3.5 text-ink-400" />
            <Select value={status} onChange={(event) => { setStatus(event.target.value); if (event.target.value) params.set("status", event.target.value); else params.delete("status"); setParams(params, { replace: true }); }} className="w-auto border-ink-700 bg-ink-900">
              <option value="">All statuses</option>
              {(["open", "confirmed", "in_progress", "fixed", "retest_required", "accepted_risk", "false_positive"] as FindingStatus[]).map((item) => <option key={item} value={item}>{item.replace(/_/g, " ")}</option>)}
            </Select>
          </div>
          <Select value={assetId} onChange={(event) => { setAssetId(event.target.value); if (event.target.value) params.set("asset_id", event.target.value); else params.delete("asset_id"); setParams(params, { replace: true }); }} className="w-auto max-w-[190px] border-ink-700 bg-ink-900">
            <option value="">All assets</option>
            {assets.data?.items.map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
          </Select>
          <Select value={sort} onChange={(event) => setSort(event.target.value)} className="w-auto border-ink-700 bg-ink-900">
            <option value="severity">Severity</option>
            <option value="last_seen">Last seen</option>
            <option value="first_seen">First seen</option>
            <option value="title">Title</option>
          </Select>
        </div>
      </div>

      <div className="mt-4">
        <QueryState loading={findings.isLoading} error={findings.error} onRetry={() => void findings.refetch()} skeleton={<div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-850"><SkeletonTable rows={8} columns={6} /></div>}>
          <TableShell footer={<Pagination page={findings.data?.page ?? 1} perPage={findings.data?.per_page ?? 25} total={findings.data?.total ?? 0} onPage={setPage} />}>
            {items.length === 0 ? (
              <EmptyState
                icon={<ShieldAlert className="h-4 w-4" />}
                title={searchValue || severity || status || assetId ? "No findings match these filters" : "No findings recorded"}
                description={searchValue || severity || status || assetId ? "Clear one or more filters to widen the result set." : "Findings are created only when a scanner produces a confirmed condition. Run an authorized assessment to populate the register."}
                action={<Link to="/scans/new"><Button size="sm">Start an assessment</Button></Link>}
              />
            ) : (
              <>
              <div className="hidden md:block">
              <table className="table-base">
                <thead><tr><th>Finding</th><th>Asset</th><th>Severity</th><th>Status</th><th>Assignee</th><th>Last seen</th></tr></thead>
                <tbody>
                  {items.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <Link to={`/findings/${finding.id}`} className="block max-w-[430px]">
                          <span className="block truncate text-[12.5px] font-medium text-ink-100 hover:text-amber-700">{finding.title}</span>
                          <span className="mt-0.5 block truncate font-mono text-[10px] text-ink-400">{finding.endpoint}</span>
                          <span className="mt-1 flex flex-wrap items-center gap-1.5">
                            {finding.cve ? <Badge className="text-[9px]">{finding.cve}</Badge> : null}
                            {finding.cwe ? <Badge className="text-[9px]">{finding.cwe}</Badge> : null}
                            {finding.cvss ? <Badge className="text-[9px]">CVSS {finding.cvss}</Badge> : null}
                            {finding.evidence_count > 0 ? <Badge className="text-[9px]">{finding.evidence_count} evidence</Badge> : null}
                          </span>
                        </Link>
                      </td>
                      <td><Link to={`/assets/${finding.asset_id}`} className="text-[11.5px] text-ink-300 hover:text-ink-100">{finding.asset_name}</Link></td>
                      <td><SeverityBadge severity={finding.severity} /></td>
                      <td><FindingStatusBadge status={finding.status} /></td>
                      <td>{finding.assignee_name ? <span className="flex items-center gap-1.5 text-[11px] text-ink-300"><UserRound className="h-3 w-3" />{finding.assignee_name}</span> : <span className="text-[11px] text-ink-400">Unassigned</span>}</td>
                      <td className="whitespace-nowrap text-[11px] text-ink-400">{formatDate(finding.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
              <Stagger className="divide-y divide-ink-700/70 md:hidden">
                {items.map((finding) => (
                  <StaggerItem key={finding.id}>
                  <Link to={`/findings/${finding.id}`} className="block px-4 py-3.5 transition-colors hover:bg-ink-800/50">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-[12.5px] font-medium text-ink-100">{finding.title}</p>
                        <p className="mt-0.5 break-all font-mono text-[10px] text-ink-400">{finding.endpoint}</p>
                      </div>
                      <SeverityBadge severity={finding.severity} />
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <FindingStatusBadge status={finding.status} />
                      <span className="text-[10.5px] text-ink-400">{finding.asset_name}</span>
                      <span className="ml-auto text-[10px] text-ink-400">{formatDate(finding.last_seen)}</span>
                    </div>
                    {(finding.cve || finding.cwe || finding.cvss || finding.evidence_count > 0) ? (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {finding.cve ? <Badge className="text-[9px]">{finding.cve}</Badge> : null}
                        {finding.cwe ? <Badge className="text-[9px]">{finding.cwe}</Badge> : null}
                        {finding.cvss ? <Badge className="text-[9px]">CVSS {finding.cvss}</Badge> : null}
                        {finding.evidence_count > 0 ? <Badge className="text-[9px]">{finding.evidence_count} evidence</Badge> : null}
                      </div>
                    ) : null}
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

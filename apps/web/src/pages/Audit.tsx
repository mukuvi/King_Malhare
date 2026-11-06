import { useDeferredValue, useState } from "react";
import { ScrollText, Search, ShieldCheck } from "lucide-react";
import { useAuditEvents } from "@/hooks/queries";
import { formatDateTime } from "@/lib/utils";
import { Badge, EmptyState, Input, PageHeader, PageTransition, Pagination, QueryState, Select, SkeletonTable, StatCard, TableShell } from "@/components/ui";

export function AuditPage() {
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [search, setSearch] = useState("");
  const searchValue = useDeferredValue(search);
  const [page, setPage] = useState(1);
  const query = useAuditEvents({ action, resource_type: resourceType, search: searchValue, page, per_page: 30 });

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Accountability"
        title="Audit log"
        description="Authentication, authorization, scan, finding, report and settings events with actor, resource and request context. Entries are append-only."
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-3">
        <StatCard label="Events" value={query.data?.total ?? "—"} hint="Matching the current filters" icon={<ScrollText className="h-4 w-4" />} loading={query.isLoading} />
        <StatCard label="Retention" value="Policy" hint="Organization retention applies to old events" icon={<ShieldCheck className="h-4 w-4" />} />
        <StatCard label="Visibility" value="Org-scoped" hint="Members only see their organization" icon={<ShieldCheck className="h-4 w-4" />} />
      </div>

      <div className="mt-5 flex flex-col gap-3 rounded-xl border border-ink-650 bg-ink-850 p-3 lg:flex-row lg:items-center">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
          <Input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} placeholder="Search actor, resource id or action" className="border-ink-700 bg-ink-900 pl-9" />
        </div>
        <div className="flex flex-wrap gap-2">
          <Input value={action} onChange={(event) => { setAction(event.target.value); setPage(1); }} placeholder="Action contains…" className="w-auto border-ink-700 bg-ink-900" />
          <Select value={resourceType} onChange={(event) => { setResourceType(event.target.value); setPage(1); }} className="w-auto border-ink-700 bg-ink-900">
            <option value="">All resources</option>
            {["user", "organization", "asset", "authorization", "scan", "finding", "evidence", "report", "cloud_connection", "api_credential", "scan_schedule", "scan_profile"].map((item) => <option key={item} value={item}>{item.replace(/_/g, " ")}</option>)}
          </Select>
        </div>
      </div>

      <div className="mt-4">
        <QueryState loading={query.isLoading} error={query.error} onRetry={() => void query.refetch()} skeleton={<div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-850"><SkeletonTable rows={9} columns={5} /></div>}>
          <TableShell footer={<Pagination page={query.data?.page ?? 1} perPage={query.data?.per_page ?? 30} total={query.data?.total ?? 0} onPage={setPage} />}>
            {(query.data?.items.length ?? 0) === 0 ? (
              <EmptyState icon={<ScrollText className="h-4 w-4" />} title="No audit events" description="Events appear as members sign in, register assets, record authorizations and run assessments." />
            ) : (
              <table className="table-base">
                <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Context</th></tr></thead>
                <tbody>
                  {query.data?.items.map((event) => (
                    <tr key={event.id}>
                      <td className="whitespace-nowrap text-[11px] text-ink-400">{formatDateTime(event.created_at)}</td>
                      <td>
                        <div className="text-[11.5px] text-ink-200">{event.actor ?? "System"}</div>
                        <div className="mt-0.5 text-[9.5px] text-ink-500">{event.actor_email ?? event.ip ?? ""}</div>
                      </td>
                      <td><span className="font-mono text-[10.5px] text-amber-200">{event.action}</span></td>
                      <td>
                        <Badge>{event.resource_type.replace(/_/g, " ")}</Badge>
                        {event.resource_id ? <div className="mt-1 max-w-[150px] truncate font-mono text-[9px] text-ink-500">{event.resource_id}</div> : null}
                      </td>
                      <td>
                        {event.metadata && Object.keys(event.metadata).length ? (
                          <details>
                            <summary className="cursor-pointer text-[10px] text-ink-500 hover:text-ink-300">View metadata</summary>
                            <pre className="mt-1 max-h-40 max-w-lg overflow-auto rounded border border-ink-700 bg-ink-950 p-2 font-mono text-[9px] leading-relaxed text-ink-400">{JSON.stringify(event.metadata, null, 2)}</pre>
                          </details>
                        ) : <span className="text-[10px] text-ink-600">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </TableShell>
        </QueryState>
      </div>
    </PageTransition>
  );
}

import { useDeferredValue, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  AppWindow,
  Boxes,
  BoxSelect,
  Cloud,
  Container,
  Globe2,
  KeyRound,
  Network,
  Plus,
  Search,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Waypoints,
} from "lucide-react";
import { useMe, useAssets, useOverview } from "@/hooks/queries";
import { cn, formatDate, riskTone } from "@/lib/utils";
import type { Asset, AssetType } from "@/types";
import { AssetFormModal } from "@/components/domain/assets";
import { Badge, Button, EmptyState, Input, PageHeader, PageTransition, Pagination, QueryState, Select, SeverityBadge, SkeletonTable, StatCard } from "@/components/ui";

const typeMeta: Record<AssetType, { label: string; icon: typeof Globe2 }> = {
  website: { label: "Website", icon: Globe2 },
  web_app: { label: "Web app", icon: AppWindow },
  api: { label: "REST API", icon: Waypoints },
  graphql_api: { label: "GraphQL", icon: Waypoints },
  ip: { label: "IP address", icon: Network },
  network: { label: "Network", icon: Network },
  cloud: { label: "Cloud", icon: Cloud },
  server: { label: "Server", icon: Server },
  container: { label: "Container", icon: Container },
  internal: { label: "Internal", icon: BoxSelect },
};

export function AssetsPage() {
  const [params, setParams] = useSearchParams();
  const [createOpen, setCreateOpen] = useState(params.get("new") === "1");
  const [search, setSearch] = useState("");
  const searchValue = useDeferredValue(search);
  const [type, setType] = useState("");
  const [environment, setEnvironment] = useState("");
  const [status, setStatus] = useState("active");
  const [sort, setSort] = useState("created_at");
  const [page, setPage] = useState(1);
  const me = useMe();
  const overview = useOverview();
  const query = useAssets({ search: searchValue, type, environment, status, sort, order: sort === "name" ? "asc" : "desc", page, per_page: 20 });

  useEffect(() => {
    if (params.get("new") === "1") setCreateOpen(true);
  }, [params]);

  useEffect(() => {
    setPage(1);
  }, [searchValue, type, environment, status, sort]);

  const closeCreate = () => {
    setCreateOpen(false);
    if (params.get("new")) {
      params.delete("new");
      setParams(params, { replace: true });
    }
  };

  const canWrite = me.data?.permissions.includes("assets:write");
  const assets = query.data?.items ?? [];

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Inventory"
        title="Assets"
        description="Systems registered for assessment. An asset cannot be scanned until a current authorization is attached."
        actions={canWrite ? <Button onClick={() => setCreateOpen(true)}><Plus className="h-3.5 w-3.5" /> Register asset</Button> : null}
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Active assets" value={overview.data?.assets.active ?? "—"} hint="Registered and not archived" icon={<Boxes className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Awaiting authorization" value={overview.data?.assets.without_authorization ?? "—"} hint="Assessments are blocked" icon={<KeyRound className="h-4 w-4" />} tone={(overview.data?.assets.without_authorization ?? 0) > 0 ? "warn" : "default"} loading={overview.isLoading} />
        <StatCard label="Critical findings" value={overview.data?.findings.critical ?? "—"} hint="Across all active assets" icon={<ShieldCheck className="h-4 w-4" />} tone={(overview.data?.findings.critical ?? 0) > 0 ? "danger" : "default"} loading={overview.isLoading} />
        <StatCard label="Archived" value={overview.data?.assets.archived ?? "—"} hint="Excluded from active posture" icon={<Boxes className="h-4 w-4" />} loading={overview.isLoading} />
      </div>

      <div className="mt-6 flex flex-col gap-3 rounded-xl border border-ink-650 bg-ink-850 p-3 sm:flex-row sm:items-center">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
          <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search by name or target" className="border-ink-700 bg-ink-900 pl-9" />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select value={type} onChange={(event) => setType(event.target.value)} className="w-auto min-w-[130px] border-ink-700 bg-ink-900">
            <option value="">All types</option>
            {Object.entries(typeMeta).map(([value, meta]) => <option key={value} value={value}>{meta.label}</option>)}
          </Select>
          <Select value={environment} onChange={(event) => setEnvironment(event.target.value)} className="w-auto min-w-[120px] border-ink-700 bg-ink-900">
            <option value="">All environments</option>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
            <option value="lab">Lab</option>
            <option value="internal">Internal</option>
          </Select>
          <Select value={status} onChange={(event) => setStatus(event.target.value)} className="w-auto border-ink-700 bg-ink-900">
            <option value="active">Active</option>
            <option value="archived">Archived</option>
          </Select>
          <div className="hidden items-center gap-1.5 sm:flex">
            <SlidersHorizontal className="h-3.5 w-3.5 text-ink-500" />
            <Select value={sort} onChange={(event) => setSort(event.target.value)} className="w-auto border-ink-700 bg-ink-900">
              <option value="created_at">Newest</option>
              <option value="last_assessed_at">Last assessed</option>
              <option value="risk">Highest risk</option>
              <option value="name">Name</option>
            </Select>
          </div>
        </div>
      </div>

      <div className="mt-4">
        <QueryState
          loading={query.isLoading}
          error={query.error}
          onRetry={() => void query.refetch()}
          skeleton={<div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-850"><SkeletonTable rows={7} columns={6} /></div>}
        >
          {assets.length === 0 ? (
            <div className="rounded-xl border border-ink-650 bg-ink-850">
              <EmptyState
                icon={<Boxes className="h-4 w-4" />}
                title={searchValue || type || environment ? "No assets match these filters" : "No assets registered"}
                description={searchValue || type || environment ? "Adjust the filters or search term. Archived assets are in a separate view." : "Add the first system you are authorized to test. Linux, Windows, cloud and container targets are supported."}
                action={canWrite ? <Button onClick={() => setCreateOpen(true)}><Plus className="h-3.5 w-3.5" /> Register asset</Button> : undefined}
              />
            </div>
          ) : (
            <>
              <div className="hidden overflow-hidden rounded-xl border border-ink-650 bg-ink-850 md:block">
                <div className="overflow-x-auto">
                  <table className="table-base">
                    <thead>
                      <tr><th>Asset</th><th>Type</th><th>Authorization</th><th>Findings</th><th>Posture</th><th>Last assessed</th></tr>
                    </thead>
                    <tbody>
                      {assets.map((asset) => <AssetRow key={asset.id} asset={asset} />)}
                    </tbody>
                  </table>
                </div>
              </div>
              <div className="space-y-2.5 md:hidden">
                {assets.map((asset) => <AssetCard key={asset.id} asset={asset} />)}
              </div>
              <div className="rounded-b-xl border-x border-b border-ink-650 bg-ink-850">
                <Pagination page={query.data?.page ?? 1} perPage={query.data?.per_page ?? 20} total={query.data?.total ?? 0} onPage={setPage} />
              </div>
            </>
          )}
        </QueryState>
      </div>

      <AssetFormModal open={createOpen} onClose={closeCreate} />
    </PageTransition>
  );
}

function AssetRow({ asset }: { asset: Asset }) {
  const meta = typeMeta[asset.type];
  const Icon = meta.icon;
  return (
    <tr>
      <td>
        <Link to={`/assets/${asset.id}`} className="flex items-center gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-ink-600 bg-ink-800 text-ink-300"><Icon className="h-3.5 w-3.5" /></span>
          <span className="min-w-0">
            <span className="block truncate text-[12.5px] font-medium text-ink-100">{asset.name}</span>
            <span className="mt-0.5 block max-w-[340px] truncate font-mono text-[10.5px] text-ink-400">{asset.target}</span>
          </span>
        </Link>
      </td>
      <td>
        <div className="text-[11.5px] text-ink-200">{meta.label}</div>
        <div className="mt-0.5 text-[10px] capitalize text-ink-400">{asset.environment}</div>
      </td>
      <td>
        {asset.active_authorizations > 0 ? (
          <span className="inline-flex items-center gap-1 text-[10.5px] text-lime-300"><ShieldCheck className="h-3 w-3" /> Authorized</span>
        ) : (
          <span className="inline-flex items-center gap-1 text-[10.5px] text-amber-300"><KeyRound className="h-3 w-3" /> Missing</span>
        )}
        {asset.tags.length ? <div className="mt-1 flex flex-wrap gap-1">{asset.tags.slice(0, 2).map((tag) => <Badge key={tag} className="text-[9px]">{tag}</Badge>)}</div> : null}
      </td>
      <td>
        <div className="flex items-center gap-1.5">
          {asset.critical_findings > 0 ? <SeverityBadge severity="critical" /> : null}
          {asset.high_findings > 0 ? <SeverityBadge severity="high" /> : null}
          <span className="font-mono text-[11px] text-ink-300">{asset.open_findings} open</span>
        </div>
      </td>
      <td>
        <div className={cn("font-mono text-[12.5px] font-medium", riskTone(asset.posture_score))}>{asset.posture_score}</div>
        <div className="mt-1 h-1 w-16 overflow-hidden rounded-full bg-ink-700">
          <div className={cn("h-full rounded-full", asset.posture_score >= 80 ? "bg-lime-400" : asset.posture_score >= 60 ? "bg-amber-400" : asset.posture_score >= 40 ? "bg-orange-400" : "bg-red-400")} style={{ width: `${asset.posture_score}%` }} />
        </div>
      </td>
      <td className="text-[11px] text-ink-400">{asset.last_assessed_at ? formatDate(asset.last_assessed_at) : "Never"}</td>
    </tr>
  );
}

function AssetCard({ asset }: { asset: Asset }) {
  const meta = typeMeta[asset.type];
  const Icon = meta.icon;
  return (
    <Link to={`/assets/${asset.id}`} className="block rounded-xl border border-ink-650 bg-ink-850 p-4 transition-colors hover:border-ink-500">
      <div className="flex items-start gap-3">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-ink-600 bg-ink-800 text-ink-300"><Icon className="h-3.5 w-3.5" /></span>
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-2">
            <p className="truncate text-[13px] font-medium text-ink-100">{asset.name}</p>
            <span className={cn("font-mono text-[12px]", riskTone(asset.posture_score))}>{asset.posture_score}</span>
          </div>
          <p className="mt-0.5 truncate font-mono text-[10.5px] text-ink-400">{asset.target}</p>
          <div className="mt-2.5 flex flex-wrap items-center gap-2">
            <Badge>{meta.label}</Badge>
            <Badge>{asset.environment}</Badge>
            {asset.active_authorizations ? <Badge className="border-lime-500/25 bg-lime-500/10 text-lime-300">authorized</Badge> : <Badge className="border-amber-500/25 bg-amber-500/10 text-amber-300">no authorization</Badge>}
          </div>
          <div className="mt-2.5 flex items-center justify-between text-[10.5px] text-ink-400">
            <span>{asset.open_findings} open findings</span>
            <span>{asset.last_assessed_at ? formatDate(asset.last_assessed_at) : "Never assessed"}</span>
          </div>
        </div>
      </div>
    </Link>
  );
}

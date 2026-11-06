import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, FileSearch, KeyRound, Pencil, Plus, Radar, ShieldCheck } from "lucide-react";
import { useAsset, useAuthorizations, useFindings, useMe, useScans } from "@/hooks/queries";
import { api, ApiError } from "@/lib/api";
import { categoryLabel, cn, formatDate, formatDateTime, scannerLabel } from "@/lib/utils";
import { AssetFormModal, AuthorizationList, AuthorizationModal, AuthorizationStatus } from "@/components/domain/assets";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, EmptyState, PageHeader, PageTransition, Progress, ScanStatusBadge, SeverityBadge, Skeleton, StatCard, TableShell, Tabs } from "@/components/ui";

type TabValue = "overview" | "authorizations" | "scans" | "findings";

export function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const me = useMe();
  const asset = useAsset(id);
  const authorizations = useAuthorizations(id);
  const scans = useScans({ asset_id: id, per_page: 20 });
  const findings = useFindings({ asset_id: id, per_page: 20 });
  const [tab, setTab] = useState<TabValue>("overview");
  const [editOpen, setEditOpen] = useState(false);
  const [authOpen, setAuthOpen] = useState(false);
  const client = useQueryClient();
  const canWrite = me.data?.permissions.includes("assets:write");

  const archive = useMutation({
    mutationFn: () => api.delete(`/assets/${id}`),
    onSuccess: () => {
      toast.success("Asset archived");
      void client.invalidateQueries({ queryKey: ["assets"] });
      void client.invalidateQueries({ queryKey: ["asset", id] });
      navigate("/assets");
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not archive the asset."),
  });

  if (asset.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-52" />
        <Skeleton className="h-24 w-full rounded-xl" />
        <div className="grid gap-3 sm:grid-cols-4">{Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-24 rounded-xl" />)}</div>
        <Skeleton className="h-64 w-full rounded-xl" />
      </div>
    );
  }

  if (asset.isError || !asset.data) {
    return (
      <div className="rounded-xl border border-ink-650 bg-ink-850">
        <EmptyState icon={<FileSearch className="h-4 w-4" />} title="Asset not found" description="The asset may have been removed or belongs to another organization." action={<Link to="/assets"><Button variant="secondary">Back to assets</Button></Link>} />
      </div>
    );
  }

  const data = asset.data;
  const auths = authorizations.data ?? [];
  const activeAuth = auths.find((auth) => auth.effective_status === "active");

  return (
    <PageTransition>
      <Link to="/assets" className="mb-4 inline-flex items-center gap-1.5 text-[11.5px] text-ink-400 transition-colors hover:text-ink-100">
        <ArrowLeft className="h-3.5 w-3.5" /> Assets
      </Link>

      <PageHeader
        eyebrow={`${data.type.replace(/_/g, " ")} · ${data.environment}`}
        title={data.name}
        description={data.target}
        actions={
          <>
            {canWrite ? <Button variant="secondary" size="sm" onClick={() => setEditOpen(true)}><Pencil className="h-3.5 w-3.5" /> Edit</Button> : null}
            {canWrite ? <Button variant="secondary" size="sm" onClick={() => setAuthOpen(true)}><ShieldCheck className="h-3.5 w-3.5" /> Authorization</Button> : null}
            {activeAuth ? <Link to={`/scans/new?asset=${data.id}`}><Button size="sm"><Radar className="h-3.5 w-3.5" /> Assess</Button></Link> : null}
          </>
        }
      />

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Badge>{data.type.replace(/_/g, " ")}</Badge>
        <Badge>{data.environment}</Badge>
        {data.tags.map((tag) => <Badge key={tag}><span className="text-ink-400">#</span>{tag}</Badge>)}
        <AuthorizationStatus authorizations={auths} />
        {data.status === "archived" ? <Badge className="border-orange-500/30 bg-orange-500/10 text-orange-300">archived</Badge> : null}
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Posture score" value={`${data.posture_score}/100`} hint="Weighted open findings for this asset" icon={<ShieldCheck className="h-4 w-4" />} tone={data.posture_score >= 70 ? "good" : data.posture_score >= 50 ? "warn" : "danger"} />
        <StatCard label="Open findings" value={data.open_findings} hint={`${data.critical_findings} critical · ${data.high_findings} high`} icon={<FileSearch className="h-4 w-4" />} tone={data.critical_findings ? "danger" : "default"} />
        <StatCard label="Assessments" value={data.scan_count} hint={data.last_assessed_at ? `Last ${formatDate(data.last_assessed_at)}` : "Never assessed"} icon={<Radar className="h-4 w-4" />} />
        <StatCard label="Authorization" value={activeAuth ? "Active" : "Missing"} hint={activeAuth ? `Expires ${formatDate(activeAuth.expires_at)}` : "Scans are blocked"} icon={<KeyRound className="h-4 w-4" />} tone={activeAuth ? "good" : "warn"} />
      </div>

      <Card className="mt-4">
        <CardContent className="grid gap-5 py-5 sm:grid-cols-2 lg:grid-cols-4">
          <Detail label="Owner" value={data.owner_name ?? "Unassigned"} />
          <Detail label="Registered" value={formatDateTime(data.created_at)} />
          <Detail label="Last assessed" value={data.last_assessed_at ? formatDateTime(data.last_assessed_at) : "Never"} />
          <Detail label="Active authorizations" value={`${data.active_authorizations}`} />
          {data.description ? <div className="sm:col-span-2 lg:col-span-4"><Detail label="Description" value={data.description} /></div> : null}
        </CardContent>
      </Card>

      <div className="mt-6">
        <Tabs<TabValue>
          value={tab}
          onChange={setTab}
          tabs={[
            { label: "Overview", value: "overview" },
            { label: "Authorizations", value: "authorizations", count: auths.length },
            { label: "Assessments", value: "scans", count: scans.data?.total },
            { label: "Findings", value: "findings", count: findings.data?.total },
          ]}
        />
      </div>

      <div className="mt-5">
        {tab === "overview" ? (
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
            <Card>
              <CardHeader>
                <CardTitle subtitle="Most recent executions for this asset">Recent assessments</CardTitle>
                <Link to={`/scans?asset_id=${data.id}`} className="text-[11px] text-ink-400 hover:text-ink-100">All</Link>
              </CardHeader>
              {(scans.data?.items.length ?? 0) === 0 ? (
                <EmptyState icon={<Radar className="h-4 w-4" />} title="No assessments" description={activeAuth ? "Start a non-intrusive baseline assessment against this authorized target." : "Record an authorization, then start an assessment."} action={activeAuth ? <Link to={`/scans/new?asset=${data.id}`}><Button size="sm">Start assessment</Button></Link> : <Button size="sm" onClick={() => setAuthOpen(true)}>Record authorization</Button>} />
              ) : (
                <div className="divide-y divide-ink-700/60">
                  {scans.data?.items.slice(0, 5).map((scan) => (
                    <Link key={scan.id} to={`/scans/${scan.id}`} className="flex items-center justify-between gap-3 px-5 py-3 transition-colors hover:bg-ink-800/60">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-[12px] font-medium text-ink-100">{scannerLabel(scan.scanner)}</span>
                          <ScanStatusBadge status={scan.status} />
                        </div>
                        <p className="mt-1 text-[10.5px] text-ink-400">{categoryLabel(scan.category)} · {formatDateTime(scan.created_at)}</p>
                      </div>
                      <div className="text-right">
                        <p className="font-mono text-[12px] text-ink-200">{scan.findings}</p>
                        <p className="text-[9px] uppercase tracking-wider text-ink-500">findings</p>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </Card>
            <Card>
              <CardHeader>
                <CardTitle subtitle="Approval lifecycle">Authorization</CardTitle>
                <Button size="sm" variant="secondary" onClick={() => setAuthOpen(true)}><Plus className="h-3.5 w-3.5" /> Add</Button>
              </CardHeader>
              <CardContent>
                {activeAuth ? (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2 text-[12px] text-lime-300"><ShieldCheck className="h-4 w-4" /> Active authorization</div>
                    <div className="space-y-2 text-[11.5px]">
                      <div className="flex justify-between gap-3"><span className="text-ink-400">Reference</span><span className="font-mono text-ink-100">{activeAuth.reference}</span></div>
                      <div className="flex justify-between gap-3"><span className="text-ink-400">Approved by</span><span className="text-ink-100">{activeAuth.approved_by_name}</span></div>
                      <div className="flex justify-between gap-3"><span className="text-ink-400">Expires</span><span className="text-ink-100">{formatDateTime(activeAuth.expires_at)}</span></div>
                      <div className="flex justify-between gap-3"><span className="text-ink-400">Intrusive</span><span className={activeAuth.intrusive_allowed ? "text-orange-300" : "text-ink-300"}>{activeAuth.intrusive_allowed ? "Permitted" : "Not permitted"}</span></div>
                      <div className="flex justify-between gap-3"><span className="text-ink-400">Private ranges</span><span className={activeAuth.allow_private ? "text-amber-300" : "text-ink-300"}>{activeAuth.allow_private ? "Permitted" : "Not permitted"}</span></div>
                    </div>
                    {activeAuth.scope_notes ? <p className="rounded border border-ink-700 bg-ink-900/50 p-2 text-[11px] leading-relaxed text-ink-300">{activeAuth.scope_notes}</p> : null}
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2 text-[12px] text-amber-300"><KeyRound className="h-4 w-4" /> No active authorization</div>
                    <p className="text-[11.5px] leading-relaxed text-ink-400">Assessments cannot be queued until a current approval is recorded. Expired approvals remain visible for audit.</p>
                    <Button size="sm" onClick={() => setAuthOpen(true)}>Record authorization</Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        ) : null}

        {tab === "authorizations" ? <AuthorizationList asset={data} authorizations={auths} onAdd={() => setAuthOpen(true)} /> : null}

        {tab === "scans" ? (
          <TableShell>
            {(scans.data?.items.length ?? 0) === 0 ? (
              <EmptyState icon={<Radar className="h-4 w-4" />} title="No assessments" description="Assessments run against the authorization active at creation time." action={<Link to={`/scans/new?asset=${data.id}`}><Button size="sm">Start assessment</Button></Link>} />
            ) : (
              <table className="table-base">
                <thead><tr><th>Assessment</th><th>Status</th><th>Progress</th><th>Findings</th><th>Started</th></tr></thead>
                <tbody>
                  {scans.data?.items.map((scan) => (
                    <tr key={scan.id}>
                      <td><Link to={`/scans/${scan.id}`} className="font-medium text-ink-100 hover:text-amber-300">{scannerLabel(scan.scanner)}</Link><div className="mt-0.5 text-[10.5px] text-ink-400">{categoryLabel(scan.category)}</div></td>
                      <td><ScanStatusBadge status={scan.status} /></td>
                      <td><div className="w-24"><Progress value={scan.progress} tone={scan.status === "failed" ? "red" : scan.status === "completed" ? "lime" : "amber"} /><span className="mt-1 block font-mono text-[9.5px] text-ink-400">{scan.phase}</span></div></td>
                      <td className="font-mono text-[11.5px]">{scan.findings}</td>
                      <td className="text-[11px] text-ink-400">{formatDateTime(scan.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </TableShell>
        ) : null}

        {tab === "findings" ? (
          <TableShell>
            {(findings.data?.items.length ?? 0) === 0 ? (
              <EmptyState icon={<FileSearch className="h-4 w-4" />} title="No findings" description="Findings appear after a scanner produces a confirmed condition. Absence of findings is not proof of security." />
            ) : (
              <table className="table-base">
                <thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Endpoint</th><th>Last seen</th></tr></thead>
                <tbody>
                  {findings.data?.items.map((finding) => (
                    <tr key={finding.id}>
                      <td><Link to={`/findings/${finding.id}`} className="font-medium text-ink-100 hover:text-amber-300">{finding.title}</Link><div className="mt-0.5 text-[10px] text-ink-500">{finding.cve ?? finding.cwe ?? "No external reference"}</div></td>
                      <td><SeverityBadge severity={finding.severity} /></td>
                      <td className="text-[11px] capitalize text-ink-300">{finding.status.replace(/_/g, " ")}</td>
                      <td className="max-w-[280px] truncate font-mono text-[10.5px] text-ink-400">{finding.endpoint}</td>
                      <td className="text-[11px] text-ink-400">{formatDate(finding.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </TableShell>
        ) : null}
      </div>

      <AssetFormModal open={editOpen} onClose={() => setEditOpen(false)} asset={data} />
      <AuthorizationModal open={authOpen} onClose={() => setAuthOpen(false)} asset={data} />

      {canWrite ? (
        <div className="mt-10 flex items-center justify-between rounded-lg border border-ink-700 bg-ink-850/50 px-4 py-3">
          <div>
            <p className="text-[11.5px] font-medium text-ink-200">Archive asset</p>
            <p className="mt-0.5 text-[10.5px] text-ink-500">Archived assets keep their findings and reports but cannot be assessed.</p>
          </div>
          <Button variant="ghost" size="sm" className="text-ink-400 hover:text-red-300" onClick={() => { if (window.confirm(`Archive ${data.name}?`)) archive.mutate(); }} loading={archive.isPending}>
            Archive
          </Button>
        </div>
      ) : null}
    </PageTransition>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[9.5px] font-semibold uppercase tracking-[0.13em] text-ink-500">{label}</div>
      <div className={cn("mt-1 text-[12px] text-ink-200", label === "Description" && "whitespace-pre-wrap leading-relaxed")}>{value}</div>
    </div>
  );
}

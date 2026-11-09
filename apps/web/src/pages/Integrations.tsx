import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Activity,
  CalendarClock,
  Cloud,
  Copy,
  KeyRound,
  Plug,
  Plus,
  Radio,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  Trash2,
  Users,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { useApiKeys, useAssets, useAuthorizations, useCloudConnections, useIntegrations, useMe, useProfiles, useSchedules } from "@/hooks/queries";
import { categoryLabel, formatDateTime, relativeTime, scannerLabel } from "@/lib/utils";
import type { ScannerInfo } from "@/types";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, EmptyState, Field, Input, Modal, PageHeader, PageTransition, QueryState, Select, Skeleton, SkeletonTable, StatCard, TableShell, Tabs, Textarea } from "@/components/ui";

type Tab = "scanners" | "cloud" | "keys" | "schedules";

export function IntegrationsPage() {
  const [params, setParams] = useSearchParams();
  const initial = (params.get("tab") as Tab) || "scanners";
  const [tab, setTab] = useState<Tab>(["scanners", "cloud", "keys", "schedules"].includes(initial) ? initial : "scanners");
  const [cloudOpen, setCloudOpen] = useState(false);
  const [keyOpen, setKeyOpen] = useState(false);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const me = useMe();
  const integrations = useIntegrations();
  const canManage = Boolean(me.data?.permissions.includes("integrations:manage"));
  const canKeys = Boolean(me.data?.permissions.includes("api_keys:manage"));

  const changeTab = (value: Tab) => {
    setTab(value);
    params.set("tab", value);
    setParams(params, { replace: true });
  };

  const actions = (() => {
    if (tab === "cloud" && canManage) return <Button onClick={() => setCloudOpen(true)}><Plus className="h-3.5 w-3.5" /> Cloud connection</Button>;
    if (tab === "keys" && canKeys) return <Button onClick={() => setKeyOpen(true)}><Plus className="h-3.5 w-3.5" /> Create API key</Button>;
    if (tab === "schedules" && canManage) return <Button onClick={() => setScheduleOpen(true)}><Plus className="h-3.5 w-3.5" /> Schedule assessment</Button>;
    return null;
  })();

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Configuration"
        title="Integrations"
        description="Scanner availability, cloud credentials, API keys and scheduled assessments. Missing tools are reported as unavailable, never simulated."
        actions={actions}
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Scanner worker" value={integrations.data?.worker_online ? "Online" : "Offline"} hint={integrations.data?.worker_online ? "Heartbeat within 90 seconds" : "Start the scanner worker service"} icon={<Radio className="h-4 w-4" />} tone={integrations.data?.worker_online ? "good" : "danger"} loading={integrations.isLoading} />
        <StatCard label="Queue depth" value={integrations.data?.queue_depth ?? "-"} hint="Jobs waiting for a worker" icon={<Activity className="h-4 w-4" />} loading={integrations.isLoading} />
        <StatCard label="Available tools" value={`${integrations.data?.scanners.filter((scanner) => scanner.status === "available").length ?? 0}/${integrations.data?.scanners.length ?? 0}`} hint="Detected at worker startup" icon={<Plug className="h-4 w-4" />} loading={integrations.isLoading} />
        <StatCard label="Storage" value={integrations.data?.storage_driver ?? "-"} hint={`Environment: ${integrations.data?.environment ?? "-"}`} icon={<ShieldCheck className="h-4 w-4" />} loading={integrations.isLoading} />
      </div>

      <div className="mt-6">
        <Tabs<Tab>
          value={tab}
          onChange={changeTab}
          tabs={[
            { label: "Scanners", value: "scanners" },
            { label: "Cloud", value: "cloud" },
            { label: "API keys", value: "keys" },
            { label: "Schedules", value: "schedules" },
          ]}
        />
      </div>

      <div className="mt-5">
        {tab === "scanners" ? <ScannersTab /> : null}
        {tab === "cloud" ? <CloudTab canManage={canManage} onAdd={() => setCloudOpen(true)} /> : null}
        {tab === "keys" ? <KeysTab canManage={canKeys} onAdd={() => setKeyOpen(true)} /> : null}
        {tab === "schedules" ? <SchedulesTab canManage={canManage} onAdd={() => setScheduleOpen(true)} /> : null}
      </div>

      <CloudModal open={cloudOpen} onClose={() => setCloudOpen(false)} />
      <ApiKeyModal open={keyOpen} onClose={() => setKeyOpen(false)} />
      <ScheduleModal open={scheduleOpen} onClose={() => setScheduleOpen(false)} />
    </PageTransition>
  );
}

function ScannersTab() {
  const integrations = useIntegrations();
  const grouped = useMemo(() => {
    const groups = new Map<string, ScannerInfo[]>();
    for (const scanner of integrations.data?.scanners ?? []) {
      const list = groups.get(scanner.category) ?? [];
      list.push(scanner as unknown as ScannerInfo);
      groups.set(scanner.category, list);
    }
    return [...groups.entries()];
  }, [integrations.data]);

  return (
    <QueryState loading={integrations.isLoading} error={integrations.error} onRetry={() => void integrations.refetch()} skeleton={<div className="space-y-3">{Array.from({ length: 3 }).map((_, index) => <Skeleton key={index} className="h-40 w-full rounded-xl" />)}</div>}>
      <div className="space-y-4">
        {!integrations.data?.worker_online ? (
          <div className="flex items-start gap-2.5 rounded-xl border border-amber-500/25 bg-amber-500/[0.04] px-4 py-3 text-[11.5px] leading-relaxed text-amber-100">
            <ShieldX className="mt-0.5 h-4 w-4 shrink-0 text-amber-700" />
            No worker heartbeat in the last 90 seconds. Scans can still be queued, but nothing will execute until a worker connects.
          </div>
        ) : null}
        {grouped.map(([category, scanners]) => (
          <Card key={category}>
            <CardHeader>
              <CardTitle subtitle={`${scanners.filter((scanner) => scanner.status === "available").length} of ${scanners.length} available`}>{categoryLabel(category)}</CardTitle>
              <Badge>{category}</Badge>
            </CardHeader>
            <div className="grid gap-px bg-ink-700/60 sm:grid-cols-2 xl:grid-cols-3">
              {scanners.map((scanner) => (
                <div key={scanner.name} className="bg-ink-850 p-4">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className="text-[12px] font-medium text-ink-100">{scanner.label}</p>
                      <p className="mt-0.5 font-mono text-[9px] text-ink-400">{scanner.name}</p>
                    </div>
                    <span className={`inline-flex items-center rounded-full border px-1.5 py-0.5 text-[8.5px] uppercase tracking-wider ${scanner.status === "available" ? "border-lime-500/25 bg-lime-500/10 text-lime-700" : scanner.status === "offline" ? "border-ink-500 bg-ink-800 text-ink-400" : "border-orange-500/25 bg-orange-500/10 text-orange-700"}`}>
                      {scanner.status}
                    </span>
                  </div>
                  <p className="mt-2 text-[10.5px] leading-relaxed text-ink-400">{scanner.description}</p>
                  <p className="mt-2 text-[9.5px] leading-relaxed text-ink-400">{scanner.detail}</p>
                  <div className="mt-2 flex items-center gap-2">
                    {scanner.intrusive ? <Badge className="border-orange-500/25 bg-orange-500/10 text-[9px] text-orange-700">intrusive</Badge> : null}
                    {scanner.version ? <span className="truncate font-mono text-[8.5px] text-ink-400">{scanner.version}</span> : null}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        ))}
        <Card>
          <CardHeader><CardTitle subtitle="Heartbeats from the internal network">Workers</CardTitle></CardHeader>
          <CardContent>
            {integrations.data?.workers.length ? (
              <div className="space-y-2">
                {integrations.data.workers.map((worker, index) => (
                  <div key={index} className="flex items-center justify-between gap-3 rounded-lg border border-ink-700 bg-ink-900/50 px-3 py-2.5">
                    <div className="min-w-0">
                      <p className="truncate font-mono text-[10.5px] text-ink-200">{String(worker.worker_id ?? "worker")}</p>
                      <p className="mt-0.5 text-[9.5px] text-ink-400">pid {String(worker.pid ?? "-")} · concurrency {String(worker.concurrency ?? "-")} · {String(worker.active_jobs ?? 0)} active</p>
                    </div>
                    <span className="shrink-0 text-[9.5px] text-ink-400">{worker.at ? relativeTime(String(worker.at)) : ""}</span>
                  </div>
                ))}
              </div>
            ) : <p className="text-[11.5px] text-ink-400">No worker has registered a heartbeat.</p>}
          </CardContent>
        </Card>
      </div>
    </QueryState>
  );
}

function CloudTab({ canManage, onAdd }: { canManage: boolean; onAdd: () => void }) {
  const connections = useCloudConnections();
  const client = useQueryClient();
  const validate = useMutation({
    mutationFn: (id: string) => api.post<{ message: string; decryptable: boolean }>(`/cloud-connections/${id}/validate`),
    onSuccess: (data) => toast.info("Credentials checked", { description: data.message }),
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Validation failed."),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/cloud-connections/${id}`),
    onSuccess: () => { toast.success("Cloud connection deleted"); void client.invalidateQueries({ queryKey: ["cloud-connections"] }); void client.invalidateQueries({ queryKey: ["integrations"] }); },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not delete the connection."),
  });

  return (
    <QueryState loading={connections.isLoading} error={connections.error} skeleton={<SkeletonTable rows={3} columns={4} />}>
      <div className="mb-4 flex items-start gap-2.5 rounded-xl border border-amber-500/20 bg-amber-500/[0.035] px-4 py-3 text-[11px] leading-relaxed text-ink-300">
        <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-700" />
        Credentials are encrypted with AES-256-GCM before storage and never returned by the API. Use read-only credentials scoped to the minimum permissions. Live access is verified by running a cloud posture assessment.
      </div>
      <TableShell>
        {(connections.data?.items.length ?? 0) === 0 ? (
          <EmptyState icon={<Cloud className="h-4 w-4" />} title="No cloud connections" description="Add read-only AWS, Azure or GCP credentials to run posture assessments. Connections are never exposed to workers except in the job payload." action={canManage ? <Button size="sm" onClick={onAdd}>Add connection</Button> : undefined} />
        ) : (
          <table className="table-base">
            <thead><tr><th>Connection</th><th>Provider</th><th>Status</th><th>Added</th><th /></tr></thead>
            <tbody>
              {connections.data?.items.map((connection) => (
                <tr key={connection.id}>
                  <td><span className="text-[12px] font-medium text-ink-100">{connection.name}</span><div className="mt-0.5 font-mono text-[9.5px] text-ink-400">{connection.account_id || "account not set"}</div></td>
                  <td><Badge>{connection.provider.toUpperCase()}</Badge></td>
                  <td><Badge className={connection.status === "verified" ? "border-lime-500/25 bg-lime-500/10 text-lime-700" : connection.status === "error" ? "border-red-500/25 bg-red-500/10 text-red-700" : "border-amber-500/25 bg-amber-500/10 text-amber-700"}>{connection.status}</Badge></td>
                  <td className="text-[11px] text-ink-400">{formatDateTime(connection.created_at)}</td>
                  <td>
                    <div className="flex justify-end gap-1">
                      <Button variant="ghost" size="sm" onClick={() => validate.mutate(connection.id)} loading={validate.isPending && validate.variables === connection.id}><RefreshCw className="h-3 w-3" /> Check</Button>
                      {canManage ? <Button variant="ghost" size="icon" className="h-8 w-8 text-ink-400 hover:text-red-700" onClick={() => { if (window.confirm(`Delete cloud connection ${connection.name}?`)) remove.mutate(connection.id); }}><Trash2 className="h-3.5 w-3.5" /></Button> : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </TableShell>
    </QueryState>
  );
}

function KeysTab({ canManage, onAdd }: { canManage: boolean; onAdd: () => void }) {
  const keys = useApiKeys();
  const client = useQueryClient();
  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/api-keys/${id}`),
    onSuccess: () => { toast.success("API key revoked"); void client.invalidateQueries({ queryKey: ["api-keys"] }); },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not revoke the key."),
  });

  return (
    <QueryState loading={keys.isLoading} error={keys.error} skeleton={<SkeletonTable rows={3} columns={4} />}>
      <TableShell>
        {(keys.data?.items.length ?? 0) === 0 ? (
          <EmptyState icon={<KeyRound className="h-4 w-4" />} title="No API keys" description="Issue a scoped key for CI pipelines, scheduled imports or automation. The secret is shown once and stored only as a hash." action={canManage ? <Button size="sm" onClick={onAdd}>Create API key</Button> : undefined} />
        ) : (
          <table className="table-base">
            <thead><tr><th>Key</th><th>Scopes</th><th>Last used</th><th>Expires</th><th /></tr></thead>
            <tbody>
              {keys.data?.items.map((key) => (
                <tr key={key.id}>
                  <td><span className="text-[12px] font-medium text-ink-100">{key.name}</span><div className="mt-0.5 font-mono text-[9.5px] text-ink-400">{key.token_prefix}••••</div></td>
                  <td><div className="flex max-w-[360px] flex-wrap gap-1">{key.scopes.slice(0, 4).map((scope) => <Badge key={scope} className="font-mono text-[8.5px]">{scope}</Badge>)}{key.scopes.length > 4 ? <Badge className="text-[8.5px]">+{key.scopes.length - 4}</Badge> : null}</div></td>
                  <td className="text-[11px] text-ink-400">{key.last_used_at ? relativeTime(key.last_used_at) : "Never"}</td>
                  <td className="text-[11px] text-ink-400">{key.expires_at ? formatDateTime(key.expires_at) : "No expiry"}</td>
                  <td>{key.revoked ? <Badge>revoked</Badge> : canManage ? <Button variant="ghost" size="sm" className="text-ink-400 hover:text-red-700" onClick={() => { if (window.confirm(`Revoke API key ${key.name}?`)) revoke.mutate(key.id); }} loading={revoke.isPending && revoke.variables === key.id}>Revoke</Button> : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </TableShell>
    </QueryState>
  );
}

function SchedulesTab({ canManage, onAdd }: { canManage: boolean; onAdd: () => void }) {
  const schedules = useSchedules();
  const client = useQueryClient();
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.patch(`/schedules/${id}`, { enabled }),
    onSuccess: () => { toast.success("Schedule updated"); void client.invalidateQueries({ queryKey: ["schedules"] }); },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not update the schedule."),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/schedules/${id}`),
    onSuccess: () => { toast.success("Schedule deleted"); void client.invalidateQueries({ queryKey: ["schedules"] }); },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not delete the schedule."),
  });

  return (
    <QueryState loading={schedules.isLoading} error={schedules.error} skeleton={<SkeletonTable rows={3} columns={5} />}>
      <TableShell>
        {(schedules.data?.items.length ?? 0) === 0 ? (
          <EmptyState icon={<CalendarClock className="h-4 w-4" />} title="No scheduled assessments" description="Schedule repeatable non-intrusive checks. Intrusive and cloud scanners must be run manually with explicit approval." action={canManage ? <Button size="sm" onClick={onAdd}>Schedule assessment</Button> : undefined} />
        ) : (
          <table className="table-base">
            <thead><tr><th>Assessment</th><th>Schedule</th><th>Next run</th><th>Enabled</th><th /></tr></thead>
            <tbody>
              {schedules.data?.items.map((schedule) => (
                <tr key={schedule.id}>
                  <td><span className="text-[12px] font-medium text-ink-100">{schedule.asset_name}</span><div className="mt-0.5 text-[9.5px] text-ink-400">{scannerLabel(schedule.scanner)} · {categoryLabel(schedule.category)}</div></td>
                  <td><code className="font-mono text-[10.5px] text-ink-200">{schedule.cron}</code><div className="mt-0.5 text-[9.5px] text-ink-400">last {schedule.last_run_at ? relativeTime(schedule.last_run_at) : "never"}</div></td>
                  <td className="text-[11px] text-ink-300">{schedule.next_run_at ? formatDateTime(schedule.next_run_at) : "-"}</td>
                  <td>
                    <button
                      onClick={() => toggle.mutate({ id: schedule.id, enabled: !schedule.enabled })}
                      disabled={!canManage}
                      className={`relative h-4 w-7 rounded-full border transition-colors ${schedule.enabled ? "border-lime-400/50 bg-lime-400/70" : "border-ink-500 bg-ink-700"}`}
                      aria-label={schedule.enabled ? "Disable schedule" : "Enable schedule"}
                    >
                      <span className={`block h-3 w-3 rounded-full bg-ink-950 transition-transform ${schedule.enabled ? "translate-x-3.5" : "translate-x-0.5"}`} />
                    </button>
                  </td>
                  <td>{canManage ? <Button variant="ghost" size="icon" className="h-8 w-8 text-ink-400 hover:text-red-700" onClick={() => { if (window.confirm("Delete this schedule?")) remove.mutate(schedule.id); }}><Trash2 className="h-3.5 w-3.5" /></Button> : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </TableShell>
    </QueryState>
  );
}

function CloudModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const client = useQueryClient();
  const [provider, setProvider] = useState<"aws" | "azure" | "gcp">("aws");
  const [name, setName] = useState("");
  const [accountId, setAccountId] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({ region: "us-east-1" });

  const create = useMutation({
    mutationFn: () => api.post<{ id: string }>("/cloud-connections", { provider, name, account_id: accountId, credentials: fields }),
    onSuccess: () => {
      toast.success("Cloud connection encrypted and stored");
      void client.invalidateQueries({ queryKey: ["cloud-connections"] });
      void client.invalidateQueries({ queryKey: ["integrations"] });
      onClose();
      setName("");
      setAccountId("");
      setFields({ region: "us-east-1" });
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not store the connection."),
  });

  const update = (key: string, value: string) => setFields((current) => ({ ...current, [key]: value }));
  const providerFields: Record<string, Array<[string, string, string]>> = {
    aws: [["access_key_id", "Access key id", "AKIA…"], ["secret_access_key", "Secret access key", "••••••••"], ["session_token", "Session token (optional)", ""], ["region", "Region", "us-east-1"]],
    azure: [["tenant_id", "Tenant id", ""], ["client_id", "Client id", ""], ["client_secret", "Client secret", ""], ["subscription_id", "Subscription id", ""]],
    gcp: [],
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add cloud connection"
      description="Credentials are encrypted before they touch the database and never returned to this page."
      width="max-w-2xl"
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button loading={create.isPending} disabled={!name.trim()} onClick={() => create.mutate()}>Store connection</Button></>}
    >
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Provider"><Select value={provider} onChange={(event) => { setProvider(event.target.value as typeof provider); setFields({ region: "us-east-1" }); }}><option value="aws">Amazon Web Services</option><option value="azure">Microsoft Azure</option><option value="gcp">Google Cloud Platform</option></Select></Field>
          <Field label="Connection name"><Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Production AWS" /></Field>
        </div>
        <Field label="Account identifier" hint="Optional"><Input value={accountId} onChange={(event) => setAccountId(event.target.value)} placeholder="123456789012" /></Field>
        {provider === "gcp" ? (
          <Field label="Service account JSON"><Textarea value={fields.service_account_json ?? ""} onChange={(event) => update("service_account_json", event.target.value)} placeholder='{"type":"service_account", …}' className="font-mono text-[10.5px]" rows={8} /></Field>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {providerFields[provider].map(([key, label, placeholder]) => (
              <Field key={key} label={label}><Input type={key.includes("secret") || key.includes("token") ? "password" : "text"} value={fields[key] ?? ""} onChange={(event) => update(key, event.target.value)} placeholder={placeholder} autoComplete="off" /></Field>
            ))}
          </div>
        )}
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-[10.5px] leading-relaxed text-amber-100"><ShieldCheck className="mt-0.5 h-3 w-3 shrink-0" /> Use read-only credentials. The platform cannot enforce the scope of the credential; that responsibility stays with the operator.</div>
      </div>
    </Modal>
  );
}

function ApiKeyModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const me = useMe();
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>(["assets:read", "scans:read", "findings:read", "reports:read"]);
  const [days, setDays] = useState(90);
  const [token, setToken] = useState("");
  const create = useMutation({
    mutationFn: () => api.post<{ token: string; prefix: string; scopes: string[] }>("/api-keys", { name, scopes, expires_in_days: days }),
    onSuccess: (data) => {
      setToken(data.token);
      void client.invalidateQueries({ queryKey: ["api-keys"] });
      toast.success("API key created", { description: "Copy it now; it will not be shown again." });
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not create the key."),
  });

  const availableScopes = me.data?.permissions ?? [];
  const close = () => {
    onClose();
    setToken("");
    setName("");
    setScopes(["assets:read", "scans:read", "findings:read", "reports:read"]);
    setDays(90);
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title={token ? "API key created" : "Create API key"}
      description={token ? "This secret is displayed once. Store it in a secrets manager." : "The key inherits only the scopes you select. It cannot exceed your own permissions."}
      footer={token ? <Button onClick={close}>Done</Button> : <><Button variant="ghost" onClick={close}>Cancel</Button><Button loading={create.isPending} disabled={!name.trim() || scopes.length === 0} onClick={() => create.mutate()}>Create key</Button></>}
    >
      {token ? (
        <div className="space-y-3">
          <div className="rounded-lg border border-amber-500/25 bg-amber-500/5 p-3">
            <p className="text-[10px] uppercase tracking-wider text-amber-700">Token</p>
            <p className="mt-1 break-all font-mono text-[11px] text-ink-100">{token}</p>
          </div>
          <Button variant="secondary" size="sm" onClick={() => { void navigator.clipboard.writeText(token); toast.success("Token copied"); }}><Copy className="h-3.5 w-3.5" /> Copy token</Button>
        </div>
      ) : (
        <div className="space-y-4">
          <Field label="Key name"><Input value={name} onChange={(event) => setName(event.target.value)} placeholder="CI report export" /></Field>
          <Field label="Lifetime" hint="Days"><Input type="number" min={1} max={730} value={days} onChange={(event) => setDays(Number(event.target.value))} /></Field>
          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-[12px] font-medium text-ink-200">Scopes</span>
              <button onClick={() => setScopes(scopes.length === availableScopes.length ? [] : [...availableScopes])} className="text-[10.5px] text-amber-700 hover:text-amber-700">{scopes.length === availableScopes.length ? "Clear all" : "Select all"}</button>
            </div>
            <div className="grid max-h-64 gap-1 overflow-y-auto rounded-lg border border-ink-700 bg-ink-900/40 p-2 sm:grid-cols-2">
              {availableScopes.map((scope) => (
                <label key={scope} className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[10.5px] text-ink-300 hover:bg-ink-800">
                  <input type="checkbox" checked={scopes.includes(scope)} onChange={(event) => setScopes(event.target.checked ? [...scopes, scope] : scopes.filter((item) => item !== scope))} className="h-3 w-3 accent-amber-400" />
                  <span className="font-mono">{scope}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
      )}
    </Modal>
  );
}

function ScheduleModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const client = useQueryClient();
  const assets = useAssets({ status: "active", per_page: 100 });
  const scanners = useIntegrations();
  const profiles = useProfiles();
  const [assetId, setAssetId] = useState("");
  const [authId, setAuthId] = useState("");
  const [scannerName, setScannerName] = useState("http-baseline");
  const [profileId, setProfileId] = useState("");
  const [cron, setCron] = useState("0 3 * * 1");
  const auths = useAuthorizations(assetId || undefined);
  const activeAuths = (auths.data ?? []).filter((auth) => auth.effective_status === "active");
  const scanner = scanners.data?.scanners.find((item) => item.name === scannerName);
  const available = (scanners.data?.scanners ?? []).filter((item) => !item.intrusive && item.category !== "cloud" && item.status !== "offline");
  const filteredProfiles = (profiles.data?.items ?? []).filter((profile) => profile.scanner === scannerName);
  const selectedProfile = profiles.data?.items.find((profile) => profile.id === profileId);

  const create = useMutation({
    mutationFn: () => api.post("/schedules", {
      asset_id: assetId,
      authorization_id: authId,
      scanner: scannerName,
      category: scanner?.category,
      profile_id: profileId || null,
      config: selectedProfile?.config ?? {},
      cron,
    }),
    onSuccess: () => {
      toast.success("Assessment scheduled");
      void client.invalidateQueries({ queryKey: ["schedules"] });
      onClose();
      setAssetId("");
      setAuthId("");
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not create the schedule."),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Schedule assessment"
      description="Scheduled runs use the same authorization, scope and concurrency checks as manual runs."
      width="max-w-2xl"
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button loading={create.isPending} disabled={!assetId || !authId || !cron} onClick={() => create.mutate()}>Create schedule</Button></>}
    >
      <div className="space-y-4">
        <Field label="Asset"><Select value={assetId} onChange={(event) => { setAssetId(event.target.value); setAuthId(""); }}><option value="">Select asset</option>{assets.data?.items.map((asset) => <option key={asset.id} value={asset.id}>{asset.name} - {asset.target}</option>)}</Select></Field>
        <Field label="Authorization">
          <Select value={authId} onChange={(event) => setAuthId(event.target.value)} disabled={!assetId}>
            <option value="">{assetId ? (activeAuths.length ? "Select authorization" : "No active authorization") : "Select an asset first"}</option>
            {activeAuths.map((auth) => <option key={auth.id} value={auth.id}>{auth.reference} - expires {formatDateTime(auth.expires_at)}</option>)}
          </Select>
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Scanner"><Select value={scannerName} onChange={(event) => { setScannerName(event.target.value); setProfileId(""); }}>{available.map((item) => <option key={item.name} value={item.name}>{item.label} - {item.status}</option>)}</Select></Field>
          <Field label="Profile" hint="Optional"><Select value={profileId} onChange={(event) => setProfileId(event.target.value)}><option value="">Scanner defaults</option>{filteredProfiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</Select></Field>
        </div>
        <Field label="Cron expression" hint="UTC, five fields">
          <Input value={cron} onChange={(event) => setCron(event.target.value)} className="font-mono" />
        </Field>
        <div className="flex flex-wrap gap-1.5">
          {[["Daily 03:00", "0 3 * * *"], ["Weekly Monday 03:00", "0 3 * * 1"], ["Every 6 hours", "0 */6 * * *"], ["Monthly 1st 04:00", "0 4 1 * *"]].map(([label, value]) => (
            <button key={value} onClick={() => setCron(value)} className="rounded-full border border-ink-600 bg-ink-900 px-2.5 py-1 text-[10px] text-ink-300 hover:border-ink-500 hover:text-ink-100">{label}</button>
          ))}
        </div>
        <div className="rounded-lg border border-ink-700 bg-ink-900/50 p-3 text-[10.5px] leading-relaxed text-ink-400">
          <Users className="mb-1 h-3.5 w-3.5 text-amber-700" />
          Schedules run as the member who created them, using their permissions. Intrusive scanners cannot be scheduled. The scheduler checks the authorization again at run time.
        </div>
      </div>
    </Modal>
  );
}

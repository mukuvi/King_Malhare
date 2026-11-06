import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { CalendarClock, KeyRound, Plus, ShieldCheck, ShieldOff, Trash2 } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { formatDate, formatDateTime } from "@/lib/utils";
import type { Asset, Authorization, Environment } from "@/types";
import { Badge, Button, Card, Field, Input, Modal, Select, Textarea, Toggle } from "@/components/ui";

const assetTypeLabels: Record<string, string> = {
  website: "Website or domain",
  web_app: "Web application",
  api: "REST API",
  graphql_api: "GraphQL API",
  ip: "IP address",
  network: "Network range",
  cloud: "Cloud account",
  server: "Server",
  container: "Container image",
  internal: "Internal service",
};

const environments: Environment[] = ["production", "staging", "development", "lab", "internal"];

function defaultExpiry(days = 30): string {
  const date = new Date();
  date.setDate(date.getDate() + days);
  return date.toISOString().slice(0, 10);
}

export function AssetFormModal({
  open,
  onClose,
  asset,
}: {
  open: boolean;
  onClose: () => void;
  asset?: Asset;
}) {
  const editing = Boolean(asset);
  const client = useQueryClient();
  const [name, setName] = useState(asset?.name ?? "");
  const [type, setType] = useState(asset?.type ?? "web_app");
  const [target, setTarget] = useState(asset?.target ?? "");
  const [environment, setEnvironment] = useState<Environment>(asset?.environment ?? "production");
  const [description, setDescription] = useState(asset?.description ?? "");
  const [tags, setTags] = useState((asset?.tags ?? []).join(", "));
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      const payload = {
        name: name.trim(),
        type,
        target: target.trim(),
        environment,
        description: description.trim(),
        tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean),
      };
      if (editing && asset) {
        await api.patch(`/assets/${asset.id}`, {
          name: payload.name,
          description: payload.description,
          environment: payload.environment,
          tags: payload.tags,
        });
        return { id: asset.id };
      }
      return api.post<{ id: string }>("/assets", payload);
    },
    onSuccess: (result) => {
      toast.success(editing ? "Asset updated" : "Asset registered");
      void client.invalidateQueries({ queryKey: ["assets"] });
      void client.invalidateQueries({ queryKey: ["asset", result.id] });
      void client.invalidateQueries({ queryKey: ["overview"] });
      onClose();
      if (!editing) {
        setName("");
        setTarget("");
        setDescription("");
        setTags("");
        setError(null);
      }
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Could not save the asset."),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={editing ? "Edit asset" : "Register asset"}
      description={editing ? "Update inventory metadata. Target type cannot be changed after registration." : "Add a system you own or are explicitly authorized to assess."}
      width="max-w-2xl"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button loading={mutation.isPending} onClick={() => mutation.mutate()} disabled={!name.trim() || !target.trim()}>
            {editing ? "Save changes" : "Register asset"}
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Field label="Asset name" hint="Human-readable">
            <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Customer portal" maxLength={160} autoFocus />
          </Field>
        </div>
        <Field label="Type">
          <Select value={type} onChange={(event) => setType(event.target.value as Asset["type"])} disabled={editing}>
            {Object.entries(assetTypeLabels).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </Select>
        </Field>
        <Field label="Environment">
          <Select value={environment} onChange={(event) => setEnvironment(event.target.value as Environment)}>
            {environments.map((env) => <option key={env} value={env}>{env[0].toUpperCase() + env.slice(1)}</option>)}
          </Select>
        </Field>
        <div className="sm:col-span-2">
          <Field
            label="Target"
            hint={editing ? "Change from the asset page if required" : "URL, host, IP, CIDR, image or account"}
          >
            <Input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://app.example.com" disabled={editing} className="font-mono text-[12.5px]" />
          </Field>
          <p className="mt-1.5 text-[11px] leading-relaxed text-ink-400">
            Targets are validated server-side. Cloud metadata addresses are always rejected. Private ranges require an authorization that explicitly allows internal systems.
          </p>
        </div>
        <div className="sm:col-span-2">
          <Field label="Description" hint="Optional">
            <Textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder="What the asset does, who owns it, and anything that constrains testing." maxLength={4000} />
          </Field>
        </div>
        <div className="sm:col-span-2">
          <Field label="Tags" hint="Comma separated">
            <Input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="public, customer-facing, pci" />
          </Field>
        </div>
      </div>
      {error ? <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[12px] text-red-200">{error}</div> : null}
      {!editing ? (
        <div className="mt-4 flex items-start gap-2.5 rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2.5 text-[11.5px] leading-relaxed text-ink-300">
          <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" />
          Registering an asset does not authorize testing. Add a signed authorization record with a validity window before starting any assessment.
        </div>
      ) : null}
    </Modal>
  );
}

export function AuthorizationModal({
  open,
  onClose,
  asset,
}: {
  open: boolean;
  onClose: () => void;
  asset: Asset;
}) {
  const client = useQueryClient();
  const [reference, setReference] = useState("");
  const [approver, setApprover] = useState("");
  const [approverEmail, setApproverEmail] = useState("");
  const [expiry, setExpiry] = useState(defaultExpiry());
  const [notes, setNotes] = useState("");
  const [intrusive, setIntrusive] = useState(false);
  const [allowPrivate, setAllowPrivate] = useState(asset.environment === "lab" || asset.environment === "internal");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      api.post<{ id: string }>(`/assets/${asset.id}/authorizations`, {
        reference: reference.trim(),
        approved_by_name: approver.trim(),
        approved_by_email: approverEmail.trim(),
        scope_notes: notes.trim(),
        intrusive_allowed: intrusive,
        allow_private: allowPrivate,
        expires_at: new Date(`${expiry}T23:59:59Z`).toISOString(),
      }),
    onSuccess: () => {
      toast.success("Authorization recorded");
      void client.invalidateQueries({ queryKey: ["authorizations", asset.id] });
      void client.invalidateQueries({ queryKey: ["asset", asset.id] });
      void client.invalidateQueries({ queryKey: ["assets"] });
      onClose();
      setReference("");
      setApprover("");
      setApproverEmail("");
      setNotes("");
      setIntrusive(false);
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Could not record authorization."),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Record authorization"
      description={`Document written approval to assess ${asset.name}. This record gates every scan.`}
      width="max-w-2xl"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button loading={mutation.isPending} onClick={() => mutation.mutate()} disabled={!reference.trim() || !approver.trim()}>
            Save authorization
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="rounded-lg border border-ink-600 bg-ink-900/60 p-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-[12px] font-medium text-ink-100">{asset.name}</p>
              <p className="mt-0.5 font-mono text-[11px] text-ink-400">{asset.target}</p>
            </div>
            <Badge>{asset.environment}</Badge>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <Field label="Authorization reference" hint="Contract, ticket, engagement ID">
              <Input value={reference} onChange={(event) => setReference(event.target.value)} placeholder="SEC-ENG-2026-014" />
            </Field>
          </div>
          <Field label="Approved by">
            <Input value={approver} onChange={(event) => setApprover(event.target.value)} placeholder="Full name" />
          </Field>
          <Field label="Approver email" hint="Optional">
            <Input type="email" value={approverEmail} onChange={(event) => setApproverEmail(event.target.value)} placeholder="owner@example.com" />
          </Field>
          <Field label="Valid until">
            <Input type="date" value={expiry} min={new Date().toISOString().slice(0, 10)} onChange={(event) => setExpiry(event.target.value)} />
          </Field>
          <div className="flex items-end">
            <div className="w-full rounded-lg border border-ink-600 bg-ink-900 px-3 py-2">
              <p className="text-[10px] uppercase tracking-wider text-ink-400">Authorization window</p>
              <p className="mt-1 text-[12px] text-ink-100">Today → {formatDate(new Date(`${expiry}T23:59:59Z`).toISOString())}</p>
            </div>
          </div>
          <div className="sm:col-span-2">
            <Field label="Scope notes" hint="Optional">
              <Textarea value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Exclusions, testing windows, targets that must not be touched." />
            </Field>
          </div>
        </div>

        <div className="space-y-2.5">
          <Toggle
            checked={intrusive}
            onChange={setIntrusive}
            label="Permit intrusive testing"
            description="Allows SQLMap, ZAP active scanning and authentication password auditing. Each run still requires the scans:intrusive permission and explicit consent."
          />
          <Toggle
            checked={allowPrivate}
            onChange={setAllowPrivate}
            label="Allow internal / private targets"
            description="Required when the target resolves to loopback, RFC1918 or another private address. Only enable for infrastructure you control."
          />
        </div>
        {error ? <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[12px] text-red-200">{error}</div> : null}
      </div>
    </Modal>
  );
}

export function AuthorizationList({ asset, authorizations, onAdd }: { asset: Asset; authorizations: Authorization[]; onAdd: () => void }) {
  const client = useQueryClient();
  const revoke = useMutation({
    mutationFn: (id: string) => api.patch(`/authorizations/${id}`, { status: "revoked", reason: "Revoked from asset page" }),
    onSuccess: () => {
      toast.success("Authorization revoked");
      void client.invalidateQueries({ queryKey: ["authorizations", asset.id] });
      void client.invalidateQueries({ queryKey: ["asset", asset.id] });
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not revoke authorization."),
  });

  return (
    <Card>
      <div className="flex items-center justify-between gap-3 border-b border-ink-700/70 px-5 py-4">
        <div>
          <h3 className="text-[13px] font-semibold text-ink-50">Authorization records</h3>
          <p className="mt-0.5 text-[11.5px] text-ink-400">Testing is blocked without a current approval.</p>
        </div>
        <Button size="sm" variant="secondary" onClick={onAdd}><Plus className="h-3.5 w-3.5" /> Add</Button>
      </div>
      {authorizations.length === 0 ? (
        <div className="flex flex-col items-start gap-3 px-5 py-6 text-[12px] text-ink-300">
          <div className="flex items-center gap-2 text-amber-300"><ShieldOff className="h-4 w-4" /> No authorization recorded</div>
          <p className="max-w-lg text-[11.5px] leading-relaxed text-ink-400">Add a written approval reference, approver and expiry before running any assessment. The platform re-checks expiry at scan creation and again in the worker.</p>
          <Button size="sm" onClick={onAdd}><ShieldCheck className="h-3.5 w-3.5" /> Record authorization</Button>
        </div>
      ) : (
        <div className="divide-y divide-ink-700/60">
          {authorizations.map((auth) => (
            <div key={auth.id} className="flex flex-col gap-3 px-5 py-3.5 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11.5px] text-ink-100">{auth.reference}</span>
                  <Badge className={
                    auth.effective_status === "active" ? "border-lime-500/30 bg-lime-500/10 text-lime-300" :
                    auth.effective_status === "expired" ? "border-red-500/30 bg-red-500/10 text-red-300" :
                    auth.effective_status === "revoked" ? "border-ink-500 bg-ink-800 text-ink-300" :
                    "border-sky-500/30 bg-sky-500/10 text-sky-300"
                  }>{auth.effective_status}</Badge>
                  {auth.intrusive_allowed ? <Badge className="border-orange-500/30 bg-orange-500/10 text-orange-300">intrusive approved</Badge> : null}
                  {auth.allow_private ? <Badge className="border-amber-500/30 bg-amber-500/10 text-amber-300">private allowed</Badge> : null}
                </div>
                <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-ink-400">
                  <span className="flex items-center gap-1"><CalendarClock className="h-3 w-3" /> {formatDateTime(auth.expires_at)}</span>
                  <span>Approved by {auth.approved_by_name}</span>
                  <span>Added {formatDate(auth.created_at)}</span>
                </div>
                {auth.scope_notes ? <p className="mt-1.5 max-w-2xl text-[11px] leading-relaxed text-ink-300">{auth.scope_notes}</p> : null}
              </div>
              {auth.effective_status === "active" ? (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-ink-400 hover:text-red-300"
                  onClick={() => {
                    if (window.confirm(`Revoke authorization ${auth.reference}? Any queued assessment using it will fail scope re-validation.`)) revoke.mutate(auth.id);
                  }}
                  loading={revoke.isPending && revoke.variables === auth.id}
                >
                  <Trash2 className="h-3.5 w-3.5" /> Revoke
                </Button>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

export function AuthorizationStatus({ authorizations }: { authorizations: Authorization[] }) {
  const active = authorizations.find((auth) => auth.effective_status === "active");
  if (!active) {
    return <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-300"><KeyRound className="h-3 w-3" /> Not authorized</span>;
  }
  return <span className="inline-flex items-center gap-1.5 rounded-full border border-lime-500/25 bg-lime-500/10 px-2 py-0.5 text-[10px] font-medium text-lime-300"><ShieldCheck className="h-3 w-3" /> Authorized to {formatDate(active.expires_at)}</span>;
}

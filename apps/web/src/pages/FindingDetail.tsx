import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  ArrowUpRight,
  CheckCircle2,
  Copy,
  FileSearch,
  History,
  Paperclip,
  Pencil,
  Plus,
  ShieldCheck,
  Upload,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { useFinding, useMe, useMembers } from "@/hooks/queries";
import { cn, formatBytes, formatDate, formatDateTime, severityOrder } from "@/lib/utils";
import type { FindingStatus, Severity } from "@/types";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, EmptyState, Field, FindingStatusBadge, Input, Modal, PageHeader, PageTransition, Select, SeverityBadge, Skeleton, Textarea } from "@/components/ui";

const statuses: FindingStatus[] = ["open", "confirmed", "in_progress", "fixed", "retest_required", "accepted_risk", "false_positive"];

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const me = useMe();
  const finding = useFinding(id);
  const members = useMembers();
  const client = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<FindingStatus>("open");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [editOpen, setEditOpen] = useState(false);
  const [remediationOpen, setRemediationOpen] = useState(false);
  const [fields, setFields] = useState({ description: "", reproduction: "", business_impact: "", technical_impact: "", remediation: "" });
  const [remediationAction, setRemediationAction] = useState("");
  const [remediationNotes, setRemediationNotes] = useState("");
  const [remediationDeadline, setRemediationDeadline] = useState("");

  const canWrite = me.data?.permissions.includes("findings:write");

  useEffect(() => {
    if (!finding.data) return;
    setStatus(finding.data.status);
    setSeverity(finding.data.severity);
    setAssignee(finding.data.assigned_to ?? "");
    setFields({
      description: finding.data.description ?? "",
      reproduction: finding.data.reproduction ?? "",
      business_impact: finding.data.business_impact ?? "",
      technical_impact: finding.data.technical_impact ?? "",
      remediation: finding.data.remediation ?? "",
    });
  }, [finding.data]);

  const invalidate = () => {
    void client.invalidateQueries({ queryKey: ["finding", id] });
    void client.invalidateQueries({ queryKey: ["findings"] });
    void client.invalidateQueries({ queryKey: ["overview"] });
  };

  const update = useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.patch(`/findings/${id}`, payload),
    onSuccess: () => {
      toast.success("Finding updated");
      invalidate();
      setEditOpen(false);
      setNote("");
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not update the finding."),
  });

  const verify = useMutation({
    mutationFn: () => api.post(`/findings/${id}/verify`),
    onSuccess: () => { toast.success("Finding verified"); invalidate(); },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not verify the finding."),
  });

  const remediation = useMutation({
    mutationFn: () => api.post(`/findings/${id}/remediation`, { action: remediationAction, notes: remediationNotes, deadline: remediationDeadline ? new Date(remediationDeadline).toISOString() : undefined }),
    onSuccess: () => {
      toast.success("Remediation recorded");
      setRemediationOpen(false);
      setRemediationAction("");
      setRemediationNotes("");
      setRemediationDeadline("");
      invalidate();
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not record remediation."),
  });

  const upload = useMutation({
    mutationFn: (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      return api.upload(`/findings/${id}/evidence`, formData);
    },
    onSuccess: () => { toast.success("Evidence uploaded"); invalidate(); if (fileRef.current) fileRef.current.value = ""; },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Upload failed."),
  });

  if (finding.isLoading) return <FindingSkeleton />;
  if (finding.isError || !finding.data) {
    return <div className="rounded-xl border border-ink-650 bg-ink-850"><EmptyState icon={<FileSearch className="h-4 w-4" />} title="Finding not found" description="This finding is not available in the current organization." action={<Link to="/findings"><Button variant="secondary">Back to findings</Button></Link>} /></div>;
  }

  const data = finding.data;
  const evidenceJson = data.evidence && Object.keys(data.evidence).length ? JSON.stringify(data.evidence, null, 2) : "";

  return (
    <PageTransition>
      <Link to="/findings" className="mb-4 inline-flex items-center gap-1.5 text-[11.5px] text-ink-400 hover:text-ink-100">
        <ArrowLeft className="h-3.5 w-3.5" /> Findings
      </Link>
      <PageHeader
        eyebrow={`${data.asset_name} · ${data.endpoint}`}
        title={data.title}
        actions={
          <>
            {canWrite ? <Button variant="secondary" size="sm" onClick={() => setEditOpen(true)}><Pencil className="h-3.5 w-3.5" /> Edit assessment</Button> : null}
            {canWrite && data.status !== "false_positive" ? <Button size="sm" onClick={() => verify.mutate()} loading={verify.isPending}><ShieldCheck className="h-3.5 w-3.5" /> Verify finding</Button> : null}
          </>
        }
      />
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <SeverityBadge severity={data.severity} />
        <FindingStatusBadge status={data.status} />
        <Badge>{data.confidence} confidence</Badge>
        {data.cve ? <Badge>{data.cve}</Badge> : null}
        {data.cwe ? <Badge>{data.cwe}</Badge> : null}
        {data.cvss ? <Badge>CVSS {data.cvss}</Badge> : null}
        {data.verified_at ? <Badge className="border-lime-500/25 bg-lime-500/10 text-lime-300"><CheckCircle2 className="h-3 w-3" /> verified {formatDate(data.verified_at)}</Badge> : null}
      </div>

      <div className="mt-6 grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader><CardTitle subtitle="What the scanner proved and why it matters">Description</CardTitle></CardHeader>
            <CardContent className="space-y-5">
              <Section title="Description" body={data.description} />
              <Section title="Technical impact" body={data.technical_impact} />
              <Section title="Business impact" body={data.business_impact} />
            </CardContent>
          </Card>

          {data.reproduction ? (
            <Card>
              <CardHeader><CardTitle subtitle="Steps an engineer can follow to confirm the issue">Reproduction</CardTitle></CardHeader>
              <CardContent><p className="whitespace-pre-wrap text-[12px] leading-relaxed text-ink-200">{data.reproduction}</p></CardContent>
            </Card>
          ) : null}

          <Card>
            <CardHeader>
              <CardTitle subtitle="Scanner output normalized into the finding">Evidence</CardTitle>
              {data.endpoint ? <CopyButton value={data.endpoint} /> : null}
            </CardHeader>
            <CardContent>
              <div className="mb-3 rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-[10.5px] text-ink-300">{data.endpoint}</div>
              {evidenceJson ? <pre className="max-h-80 overflow-auto rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-[10px] leading-relaxed text-ink-300">{evidenceJson}</pre> : <p className="text-[11.5px] text-ink-400">No structured evidence was recorded.</p>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle subtitle="Uploaded screenshots and files, hashed at rest">Evidence attachments</CardTitle>
              {canWrite ? (
                <>
                  <input ref={fileRef} type="file" className="hidden" accept=".png,.jpg,.jpeg,.webp,.gif,.pdf,.txt,.log,.json,.csv" onChange={(event) => { const file = event.target.files?.[0]; if (file) upload.mutate(file); }} />
                  <Button size="sm" variant="secondary" onClick={() => fileRef.current?.click()} loading={upload.isPending}><Upload className="h-3.5 w-3.5" /> Upload</Button>
                </>
              ) : null}
            </CardHeader>
            <CardContent className="space-y-2">
              {data.evidence_files.length === 0 ? (
                <p className="text-[11.5px] text-ink-400">No files attached. PNG, JPEG, WEBP, GIF, PDF, TXT, LOG, JSON and CSV up to 25 MB are accepted.</p>
              ) : (
                data.evidence_files.map((file) => (
                  <div key={file.id} className="flex items-center justify-between gap-3 rounded-lg border border-ink-700 bg-ink-900/40 px-3 py-2.5">
                    <div className="flex min-w-0 items-center gap-2.5">
                      <Paperclip className="h-3.5 w-3.5 shrink-0 text-ink-400" />
                      <div className="min-w-0">
                        <p className="truncate text-[11.5px] text-ink-100">{file.filename}</p>
                        <p className="mt-0.5 truncate font-mono text-[9px] text-ink-500">{file.content_type} · {formatBytes(file.size_bytes)} · SHA-256 {file.sha256.slice(0, 16)}…</p>
                      </div>
                    </div>
                    <a href={`${api.base}/evidence/${file.id}/download`} className="shrink-0 text-[10.5px] text-amber-300 hover:text-amber-200">Download</a>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          {data.references.length ? (
            <Card>
              <CardHeader><CardTitle subtitle="Vendor advisories and external references">References</CardTitle></CardHeader>
              <CardContent className="space-y-1.5">
                {data.references.map((reference) => (
                  <a key={reference} href={reference} target="_blank" rel="noopener noreferrer" className="flex items-start gap-2 text-[11px] text-amber-300 hover:text-amber-200">
                    <ArrowUpRight className="mt-0.5 h-3 w-3 shrink-0" />
                    <span className="break-all">{reference}</span>
                  </a>
                ))}
              </CardContent>
            </Card>
          ) : null}

          <Card>
            <CardHeader><CardTitle subtitle="Every change is attributed and timed">Timeline</CardTitle></CardHeader>
            <CardContent className="p-0">
              {data.events.length === 0 ? <p className="px-5 py-4 text-[11.5px] text-ink-400">No events recorded.</p> : (
                <div className="divide-y divide-ink-700/60">
                  {data.events.map((event) => (
                    <div key={event.id} className="flex gap-3 px-5 py-3">
                      <History className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ink-500" />
                      <div className="min-w-0">
                        <p className="text-[11.5px] text-ink-200">{event.type.replace(/_/g, " ")} {event.from ? <span className="text-ink-400">from {event.from}</span> : null} {event.to ? <span className="text-ink-400">to {event.to}</span> : null}</p>
                        <p className="mt-0.5 text-[10px] text-ink-500">{event.actor ?? "System"} · {formatDateTime(event.created_at)}{event.note ? ` · ${event.note}` : ""}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader><CardTitle subtitle="Status changes are audited">Triage</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <Field label="Status">
                <Select value={status} onChange={(event) => setStatus(event.target.value as FindingStatus)} disabled={!canWrite}>
                  {statuses.map((item) => <option key={item} value={item}>{item.replace(/_/g, " ")}</option>)}
                </Select>
              </Field>
              <Field label="Severity">
                <Select value={severity} onChange={(event) => setSeverity(event.target.value as Severity)} disabled={!canWrite}>
                  {severityOrder.map((item) => <option key={item} value={item}>{item}</option>)}
                </Select>
              </Field>
              <Field label="Assignee">
                <Select value={assignee} onChange={(event) => setAssignee(event.target.value)} disabled={!canWrite || members.isError}>
                  <option value="">Unassigned</option>
                  {members.data?.map((member) => <option key={member.user_id} value={member.user_id}>{member.name}</option>)}
                </Select>
              </Field>
              <Field label="Triage note" hint="Optional">
                <Input value={note} onChange={(event) => setNote(event.target.value)} placeholder="Why this decision was made" disabled={!canWrite} />
              </Field>
              {canWrite ? (
                <Button className="w-full" size="sm" loading={update.isPending} onClick={() => update.mutate({ status, severity, assigned_to: assignee, note })}>Save triage</Button>
              ) : <p className="text-[10.5px] text-ink-500">Read-only access.</p>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle subtitle="Source and lifecycle">Details</CardTitle></CardHeader>
            <CardContent className="space-y-2.5 text-[11.5px]">
              <Meta label="Asset" value={data.asset_name} link={`/assets/${data.asset_id}`} />
              <Meta label="Target" value={data.asset_target} mono />
              <Meta label="Scan" value={data.scan_id ? "View assessment" : "Finding set"} link={data.scan_id ? `/scans/${data.scan_id}` : undefined} />
              <Meta label="First seen" value={formatDateTime(data.first_seen)} />
              <Meta label="Last seen" value={formatDateTime(data.last_seen)} />
              <Meta label="Verified" value={data.verified_at ? `${formatDateTime(data.verified_at)}${data.verified_by ? ` by ${data.verified_by}` : ""}` : "Not verified"} />
              <Meta label="Assigned to" value={data.assignee_name ?? "Unassigned"} />
              <Meta label="Finding ID" value={`${data.id.slice(0, 8)}…`} mono />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle subtitle="Actions taken toward the fix">Remediation</CardTitle>
              <Button size="sm" variant="secondary" onClick={() => setRemediationOpen(true)} disabled={!canWrite}><Plus className="h-3.5 w-3.5" /> Log</Button>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="rounded-lg border border-ink-700 bg-ink-900/40 p-3">
                <p className="text-[9.5px] font-semibold uppercase tracking-[0.13em] text-ink-500">Recommendation</p>
                <p className="mt-1.5 whitespace-pre-wrap text-[11.5px] leading-relaxed text-ink-200">{data.remediation || "No remediation guidance recorded."}</p>
              </div>
              {data.remediation_records.length === 0 ? <p className="text-[10.5px] text-ink-500">No remediation actions logged.</p> : data.remediation_records.map((record) => (
                <div key={record.id} className="border-t border-ink-700/60 pt-2.5">
                  <p className="text-[11px] font-medium text-ink-200">{record.action}</p>
                  {record.notes ? <p className="mt-0.5 text-[10.5px] leading-relaxed text-ink-400">{record.notes}</p> : null}
                  <p className="mt-1 text-[9.5px] text-ink-500">{record.performed_by ?? "Unknown"} · {formatDateTime(record.performed_at)}{record.deadline ? ` · due ${formatDate(record.deadline)}` : ""}</p>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="Edit finding assessment"
        description="Analyst-authored context is preserved across re-scans. Scanner-produced technical evidence is not overwritten."
        width="max-w-3xl"
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditOpen(false)}>Cancel</Button>
            <Button loading={update.isPending} onClick={() => update.mutate({ ...fields, note: "Assessment updated" })}>Save changes</Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Description"><Textarea value={fields.description} onChange={(event) => setFields({ ...fields, description: event.target.value })} /></Field>
          <Field label="Reproduction"><Textarea value={fields.reproduction} onChange={(event) => setFields({ ...fields, reproduction: event.target.value })} placeholder="Exact requests, prerequisites and observed result." /></Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Business impact"><Textarea value={fields.business_impact} onChange={(event) => setFields({ ...fields, business_impact: event.target.value })} /></Field>
            <Field label="Technical impact"><Textarea value={fields.technical_impact} onChange={(event) => setFields({ ...fields, technical_impact: event.target.value })} /></Field>
          </div>
          <Field label="Remediation"><Textarea value={fields.remediation} onChange={(event) => setFields({ ...fields, remediation: event.target.value })} /></Field>
        </div>
      </Modal>

      <Modal
        open={remediationOpen}
        onClose={() => setRemediationOpen(false)}
        title="Record remediation action"
        description="Document what changed, who did it and when the fix is due."
        footer={
          <>
            <Button variant="ghost" onClick={() => setRemediationOpen(false)}>Cancel</Button>
            <Button loading={remediation.isPending} disabled={!remediationAction.trim()} onClick={() => remediation.mutate()}>Record action</Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Action"><Input value={remediationAction} onChange={(event) => setRemediationAction(event.target.value)} placeholder="Upgraded dependency to 2.4.1" /></Field>
          <Field label="Notes" hint="Optional"><Textarea value={remediationNotes} onChange={(event) => setRemediationNotes(event.target.value)} /></Field>
          <Field label="Deadline" hint="Optional"><Input type="date" value={remediationDeadline} onChange={(event) => setRemediationDeadline(event.target.value)} /></Field>
        </div>
      </Modal>
    </PageTransition>
  );
}

function Section({ title, body }: { title: string; body: string }) {
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-[0.13em] text-ink-500">{title}</p>
      <p className="mt-1.5 whitespace-pre-wrap text-[12px] leading-relaxed text-ink-200">{body || "Not recorded."}</p>
    </div>
  );
}

function Meta({ label, value, link, mono }: { label: string; value: string; link?: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <span className="text-ink-500">{label}</span>
      {link ? <Link to={link} className="max-w-[190px] truncate text-right text-amber-300 hover:text-amber-200">{value}</Link> : <span className={cn("max-w-[190px] truncate text-right text-ink-200", mono && "font-mono text-[10px]")}>{value}</span>}
    </div>
  );
}

function CopyButton({ value }: { value: string }) {
  return (
    <button
      onClick={() => { void navigator.clipboard.writeText(value); toast.success("Copied to clipboard"); }}
      className="inline-flex items-center gap-1 rounded border border-ink-600 px-1.5 py-1 text-[9.5px] text-ink-400 transition-colors hover:border-ink-500 hover:text-ink-200"
    >
      <Copy className="h-3 w-3" /> Copy endpoint
    </button>
  );
}

function FindingSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-64" />
      <div className="flex gap-2"><Skeleton className="h-5 w-20" /><Skeleton className="h-5 w-24" /></div>
      <div className="grid gap-4 xl:grid-cols-[1.55fr_1fr]">
        <div className="space-y-4"><Skeleton className="h-56 w-full rounded-xl" /><Skeleton className="h-40 w-full rounded-xl" /></div>
        <div className="space-y-4"><Skeleton className="h-72 w-full rounded-xl" /><Skeleton className="h-56 w-full rounded-xl" /></div>
      </div>
    </div>
  );
}

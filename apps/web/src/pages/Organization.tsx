import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Copy, Save, ShieldCheck, Trash2, UserPlus, Users } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { useMe, useMembers, useOrganization } from "@/hooks/queries";
import { formatDateTime } from "@/lib/utils";
import type { Member } from "@/types";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Field, Input, Modal, PageHeader, PageTransition, QueryState, Select, Skeleton, StatCard } from "@/components/ui";

export function OrganizationPage() {
  const me = useMe();
  const org = useOrganization();
  const members = useMembers();
  const client = useQueryClient();
  const canManage = me.data?.permissions.includes("members:manage");
  const canOrg = me.data?.permissions.includes("org:manage");
  const [name, setName] = useState("");
  const [retention, setRetention] = useState(365);
  const [inviteOpen, setInviteOpen] = useState(false);

  useEffect(() => {
    if (org.data) {
      setName(org.data.name);
      setRetention(org.data.retention_days);
    }
  }, [org.data]);

  const updateOrg = useMutation({
    mutationFn: () => api.patch("/org", { name: name.trim(), retention_days: retention }),
    onSuccess: () => {
      toast.success("Organization updated");
      void client.invalidateQueries({ queryKey: ["org"] });
      void client.invalidateQueries({ queryKey: ["me"] });
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not update the organization."),
  });

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Administration"
        title="Organization"
        description="Members, roles, retention and workspace settings. Data is isolated to this organization at the query layer."
        actions={canManage ? <Button onClick={() => setInviteOpen(true)}><UserPlus className="h-3.5 w-3.5" /> Add member</Button> : null}
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-3">
        <StatCard label="Members" value={org.data?.member_count ?? "-"} hint="Users with access to this workspace" icon={<Users className="h-4 w-4" />} loading={org.isLoading} />
        <StatCard label="Active assets" value={org.data?.asset_count ?? "-"} hint="Registered and currently testable" icon={<ShieldCheck className="h-4 w-4" />} loading={org.isLoading} />
        <StatCard label="Emergency stop" value={org.data?.emergency_stop ? "Active" : "Clear"} hint="Blocks all new assessments" tone={org.data?.emergency_stop ? "danger" : "good"} icon={<ShieldCheck className="h-4 w-4" />} loading={org.isLoading} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle subtitle="Role changes are audited">Members</CardTitle>
            <Badge>{members.data?.length ?? 0}</Badge>
          </CardHeader>
          <QueryState loading={members.isLoading} error={members.error} skeleton={<div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, index) => <Skeleton key={index} className="h-14 w-full" />)}</div>}>
            <div className="divide-y divide-ink-700/60">
              {members.data?.map((member) => (
                <MemberRow key={member.user_id} member={member} canManage={Boolean(canManage)} currentUserId={me.data?.user.id} />
              ))}
            </div>
          </QueryState>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle subtitle={canOrg ? "Owner and admin only" : "Read-only"}>Workspace</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <Field label="Organization name"><Input value={name} onChange={(event) => setName(event.target.value)} disabled={!canOrg} /></Field>
              <Field label="Data retention" hint="Days">
                <Input type="number" min={30} max={3650} value={retention} onChange={(event) => setRetention(Number(event.target.value))} disabled={!canOrg} />
              </Field>
              <p className="text-[10.5px] leading-relaxed text-ink-400">Retention applies to raw scan artefacts and audit history. Findings remain until explicitly removed.</p>
              {canOrg ? <Button size="sm" onClick={() => updateOrg.mutate()} loading={updateOrg.isPending} disabled={!name.trim()}><Save className="h-3.5 w-3.5" /> Save workspace</Button> : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle subtitle="Workspace details">Metadata</CardTitle></CardHeader>
            <CardContent className="space-y-2.5 text-[11.5px]">
              <Row label="Slug" value={org.data?.slug ?? "-"} />
              <Row label="Created" value={org.data?.created_at ? formatDateTime(org.data.created_at) : "-"} />
              <Row label="Your role" value={me.data?.role ?? "-"} />
              <Row label="Retention" value={`${org.data?.retention_days ?? 365} days`} />
            </CardContent>
          </Card>
        </div>
      </div>

      <InviteModal open={inviteOpen} onClose={() => setInviteOpen(false)} />
    </PageTransition>
  );
}

function MemberRow({ member, canManage, currentUserId }: { member: Member; canManage: boolean; currentUserId?: string }) {
  const client = useQueryClient();
  const self = member.user_id === currentUserId;
  const update = useMutation({
    mutationFn: (role: string) => api.patch(`/org/members/${member.user_id}`, { role_id: role }),
    onSuccess: () => { toast.success("Role updated"); void client.invalidateQueries({ queryKey: ["members"] }); },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not update the role."),
  });
  const remove = useMutation({
    mutationFn: () => api.delete(`/org/members/${member.user_id}`),
    onSuccess: () => { toast.success("Member removed"); void client.invalidateQueries({ queryKey: ["members"] }); void client.invalidateQueries({ queryKey: ["org"] }); },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not remove the member."),
  });

  return (
    <div className="flex flex-col gap-2 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold text-ink-50" style={{ backgroundColor: member.avatar_color }}>{member.name.slice(0, 1).toUpperCase()}</div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="truncate text-[12px] font-medium text-ink-100">{member.name}</span>
            {self ? <Badge className="text-[9px]">you</Badge> : null}
            {member.role === "owner" ? <Badge className="border-amber-500/25 bg-amber-500/10 text-[9px] text-amber-700">owner</Badge> : null}
          </div>
          <p className="break-all text-[10.5px] text-ink-400">{member.email} · joined {formatDateTime(member.joined_at)}</p>
          <p className="mt-0.5 text-[9.5px] text-ink-400">{member.open_findings} open findings assigned · last sign-in {member.last_login_at ? formatDateTime(member.last_login_at) : "never"}</p>
        </div>
      </div>
      <div className="flex items-center gap-2 self-end sm:self-auto">
        {canManage && !self && member.role !== "owner" ? (
          <Select value={member.role} onChange={(event) => update.mutate(event.target.value)} className="h-8 w-[120px] border-ink-700 bg-ink-900 text-[11px]" disabled={update.isPending}>
            <option value="admin">Admin</option>
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
          </Select>
        ) : (
          <Badge>{member.role}</Badge>
        )}
        {canManage && !self && member.role !== "owner" ? (
          <Button variant="ghost" size="icon" className="h-8 w-8 text-ink-400 hover:text-red-700" onClick={() => { if (window.confirm(`Remove ${member.name} from the organization?`)) remove.mutate(); }} loading={remove.isPending} aria-label="Remove member">
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function InviteModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("analyst");
  const [temporaryPassword, setTemporaryPassword] = useState("");

  const invite = useMutation({
    mutationFn: () => api.post<{ user_id: string; created: boolean; temporary_password?: string }>("/org/members", { name, email, role_id: role }),
    onSuccess: (data) => {
      void client.invalidateQueries({ queryKey: ["members"] });
      void client.invalidateQueries({ queryKey: ["org"] });
      if (data.temporary_password) {
        setTemporaryPassword(data.temporary_password);
        toast.success("Member created", { description: "Share the temporary password securely. It is shown once." });
      } else {
        toast.success("Member added to the organization");
        onClose();
        setName("");
        setEmail("");
      }
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not add the member."),
  });

  const close = () => {
    onClose();
    setTemporaryPassword("");
    setName("");
    setEmail("");
    setRole("analyst");
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title={temporaryPassword ? "Member account created" : "Add organization member"}
      description={temporaryPassword ? "Provide these credentials to the member through a secure channel." : "New accounts receive a generated temporary password. Existing accounts are added to this organization."}
      footer={temporaryPassword ? <Button onClick={close}>Done</Button> : (
        <>
          <Button variant="ghost" onClick={close}>Cancel</Button>
          <Button loading={invite.isPending} disabled={!name.trim() || !email.trim()} onClick={() => invite.mutate()}><UserPlus className="h-3.5 w-3.5" /> Add member</Button>
        </>
      )}
    >
      {temporaryPassword ? (
        <div className="space-y-3">
          <Field label="Email"><Input value={email} readOnly /></Field>
          <Field label="Temporary password"><Input value={temporaryPassword} readOnly className="font-mono" /></Field>
          <Button variant="secondary" size="sm" onClick={() => { void navigator.clipboard.writeText(`Email: ${email}\nTemporary password: ${temporaryPassword}`); toast.success("Credentials copied"); }}><Copy className="h-3.5 w-3.5" /> Copy credentials</Button>
          <p className="text-[10.5px] text-ink-400">The member should change this password immediately after signing in. It is not retrievable later.</p>
        </div>
      ) : (
        <div className="space-y-4">
          <Field label="Full name"><Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Security engineer" /></Field>
          <Field label="Email"><Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="engineer@example.com" /></Field>
          <Field label="Role" hint="Owner cannot be granted here">
            <Select value={role} onChange={(event) => setRole(event.target.value)}>
              <option value="admin">Admin - manage members and integrations</option>
              <option value="analyst">Analyst - run scans and manage findings</option>
              <option value="viewer">Viewer - read-only access</option>
            </Select>
          </Field>
          <div className="rounded-lg border border-ink-700 bg-ink-900/50 p-3 text-[10.5px] leading-relaxed text-ink-400">
            <ShieldCheck className="mb-1 h-3.5 w-3.5 text-amber-700" />
            Admins cannot grant a role at or above their own level. All role changes are written to the audit log.
          </div>
        </div>
      )}
    </Modal>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-ink-700/50 pb-2">
      <span className="text-ink-400">{label}</span>
      <span className="max-w-[65%] break-all text-right text-ink-200">{value}</span>
    </div>
  );
}

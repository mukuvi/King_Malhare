import { useEffect, useState } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Ban,
  Building2,
  Copy,
  Crown,
  KeyRound,
  LogOut,
  Monitor,
  Pencil,
  Radar,
  Save,
  Search,
  ShieldAlert,
  Trash2,
  Users,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import {
  useMe,
  usePlatformActivity,
  usePlatformOrganization,
  usePlatformOrganizations,
  usePlatformOverview,
  usePlatformSessions,
  usePlatformUser,
  usePlatformUsers,
} from "@/hooks/queries";
import { formatDateTime, relativeTime } from "@/lib/utils";
import type { PlatformOrganization, PlatformUser } from "@/types";
import {
  Badge,
  Button,
  EmptyState,
  Field,
  Input,
  Modal,
  PageHeader,
  PageTransition,
  Pagination,
  QueryState,
  Select,
  Skeleton,
  SkeletonTable,
  StatCard,
  TableShell,
  Tabs,
  Toggle,
} from "@/components/ui";

type Tab = "organizations" | "users" | "sessions" | "activity";

export function PlatformPage() {
  const [params] = useSearchParams();
  const requestedTab = params.get("tab");
  const [tab, setTab] = useState<Tab>(
    requestedTab === "users" || requestedTab === "sessions" || requestedTab === "activity" ? requestedTab : "organizations",
  );
  const openOrgId = params.get("org") ?? "";
  const me = useMe();
  const overview = usePlatformOverview();
  const organizations = usePlatformOrganizations();
  const users = usePlatformUsers();
  const sessions = usePlatformSessions();
  const [manageUserId, setManageUserId] = useState("");
  const [editingOrg, setEditingOrg] = useState<PlatformOrganization | null>(null);
  const [search, setSearch] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [orgFilter, setOrgFilter] = useState("");
  const [page, setPage] = useState(1);
  const activity = usePlatformActivity({ search: searchTerm, org_id: orgFilter, page, per_page: 30 });
  const client = useQueryClient();

  useEffect(() => {
    if (requestedTab === "users" || requestedTab === "sessions" || requestedTab === "activity" || requestedTab === "organizations") {
      setTab(requestedTab);
    }
  }, [requestedTab]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearchTerm(search);
      setPage(1);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [search]);

  const revokeSession = useMutation({
    mutationFn: (id: string) => api.delete(`/platform/sessions/${id}`),
    onSuccess: () => {
      toast.success("Session revoked");
      void client.invalidateQueries({ queryKey: ["platform"] });
    },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Could not revoke the session."),
  });

  if (me.isLoading) return null;
  if (!me.data?.platform_admin) return <Navigate to="/dashboard" replace />;

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Super admin"
        title="Platform control"
        description="Every organization, user, session and event across this deployment. Only platform administrators can see or change this area."
        actions={<Badge className="border-amber-500/25 bg-amber-500/10 text-amber-700"><Crown className="mr-1 h-3 w-3" /> {me.data.user.email}</Badge>}
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <StatCard label="Organizations" value={overview.data?.organizations ?? "-"} hint="Workspaces on this deployment" icon={<Building2 className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Users" value={overview.data?.users ?? "-"} hint={`${overview.data?.active_users ?? 0} active, ${overview.data?.platform_admins ?? 0} platform admins`} icon={<Users className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Active sessions" value={overview.data?.active_sessions ?? "-"} hint="Signed in right now" icon={<Monitor className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Active assets" value={overview.data?.assets ?? "-"} hint="Registered and testable" icon={<ShieldAlert className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Running scans" value={overview.data?.running_scans ?? "-"} hint={`${overview.data?.scans ?? 0} total assessments`} tone={overview.data?.running_scans ? "warn" : "default"} icon={<Radar className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Open findings" value={overview.data?.findings ?? "-"} hint={`${overview.data?.high_risk_findings ?? 0} critical or high`} tone={overview.data?.high_risk_findings ? "danger" : "default"} icon={<ShieldAlert className="h-4 w-4" />} loading={overview.isLoading} />
      </div>

      <div className="mt-6">
        <Tabs<Tab>
          value={tab}
          onChange={setTab}
          tabs={[
            { label: "Organizations", value: "organizations", count: organizations.data?.items.length },
            { label: "Users", value: "users", count: users.data?.items.length },
            { label: "Sessions", value: "sessions", count: sessions.data?.items.length },
            { label: "Activity", value: "activity", count: activity.data?.total },
          ]}
        />
      </div>

      {tab === "organizations" ? (
        <div className="mt-4">
          <QueryState
            loading={organizations.isLoading}
            error={organizations.error}
            onRetry={() => void organizations.refetch()}
            skeleton={<div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-850"><SkeletonTable rows={5} columns={7} /></div>}
          >
            <TableShell>
              {(organizations.data?.items.length ?? 0) === 0 ? (
                <EmptyState icon={<Building2 className="h-4 w-4" />} title="No organizations" description="Organizations appear when the first workspace is created." />
              ) : (
                <table className="table-base">
                  <thead>
                    <tr><th>Organization</th><th>Owner</th><th>Members</th><th>Assets</th><th>Assessments</th><th>Open findings</th><th /></tr>
                  </thead>
                  <tbody>
                    {organizations.data?.items.map((org) => (
                      <OrganizationRow key={org.id} org={org} defaultOpen={org.id === openOrgId} onEdit={() => setEditingOrg(org)} />
                    ))}
                  </tbody>
                </table>
              )}
            </TableShell>
          </QueryState>
        </div>
      ) : null}

      {tab === "users" ? (
        <div className="mt-4">
          <QueryState
            loading={users.isLoading}
            error={users.error}
            onRetry={() => void users.refetch()}
            skeleton={<div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-850"><SkeletonTable rows={6} columns={6} /></div>}
          >
            <TableShell>
              {(users.data?.items.length ?? 0) === 0 ? (
                <EmptyState icon={<Users className="h-4 w-4" />} title="No users" description="Users appear when accounts are created or invited." />
              ) : (
                <table className="table-base">
                  <thead>
                    <tr><th>User</th><th>Organizations</th><th>Status</th><th>Access</th><th>Last sign in</th><th /></tr>
                  </thead>
                  <tbody>
                    {users.data?.items.map((user) => (
                      <UserRow key={user.id} user={user} isSelf={user.id === me.data?.user.id} onManage={() => setManageUserId(user.id)} />
                    ))}
                  </tbody>
                </table>
              )}
            </TableShell>
          </QueryState>
        </div>
      ) : null}

      {tab === "sessions" ? (
        <div className="mt-4">
          <QueryState
            loading={sessions.isLoading}
            error={sessions.error}
            onRetry={() => void sessions.refetch()}
            skeleton={<div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-850"><SkeletonTable rows={6} columns={7} /></div>}
          >
            <TableShell>
              {(sessions.data?.items.length ?? 0) === 0 ? (
                <EmptyState icon={<Monitor className="h-4 w-4" />} title="No active sessions" description="Active browser sessions appear here as users sign in." />
              ) : (
                <table className="table-base">
                  <thead>
                    <tr><th>User</th><th>Organization</th><th>IP address</th><th>Started</th><th>Last seen</th><th>Expires</th><th /></tr>
                  </thead>
                  <tbody>
                    {sessions.data?.items.map((session) => (
                      <tr key={session.id}>
                        <td>
                          <div className="text-[12px] font-medium text-ink-100">{session.user_name}</div>
                          <div className="mt-0.5 text-[9.5px] text-ink-400">{session.user_email}</div>
                        </td>
                        <td className="text-[11.5px] text-ink-200">{session.org_name}</td>
                        <td>
                          <div className="font-mono text-[10.5px] text-ink-300">{session.ip || "-"}</div>
                          <div className="mt-0.5 max-w-[220px] truncate text-[9px] text-ink-400" title={session.user_agent}>{session.user_agent || ""}</div>
                        </td>
                        <td className="whitespace-nowrap text-[10.5px] text-ink-400">{formatDateTime(session.created_at)}</td>
                        <td className="whitespace-nowrap text-[10.5px] text-ink-400">{relativeTime(session.last_seen_at)}</td>
                        <td className="whitespace-nowrap text-[10.5px] text-ink-400">{relativeTime(session.expires_at)}</td>
                        <td className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-ink-400 hover:text-red-700"
                            loading={revokeSession.isPending && revokeSession.variables === session.id}
                            onClick={() => { if (window.confirm(`Revoke the session for ${session.user_email}?`)) revokeSession.mutate(session.id); }}
                          >
                            Revoke
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </TableShell>
          </QueryState>
        </div>
      ) : null}

      {tab === "activity" ? (
        <div className="mt-4 space-y-3">
          <div className="flex flex-col gap-2 rounded-xl border border-ink-650 bg-ink-850 p-3 sm:flex-row sm:items-center">
            <div className="relative min-w-0 flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
              <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search action, actor, email, organization or resource" className="border-ink-700 bg-ink-900 pl-9" />
            </div>
            <Select value={orgFilter} onChange={(event) => { setOrgFilter(event.target.value); setPage(1); }} className="w-auto border-ink-700 bg-ink-900">
              <option value="">All organizations</option>
              {organizations.data?.items.map((org) => <option key={org.id} value={org.id}>{org.name}</option>)}
            </Select>
          </div>
          <QueryState
            loading={activity.isLoading}
            error={activity.error}
            onRetry={() => void activity.refetch()}
            skeleton={<div className="space-y-2">{Array.from({ length: 6 }).map((_, index) => <Skeleton key={index} className="h-14 w-full rounded-xl" />)}</div>}
          >
            <TableShell footer={<Pagination page={activity.data?.page ?? 1} perPage={activity.data?.per_page ?? 30} total={activity.data?.total ?? 0} onPage={setPage} />}>
              {(activity.data?.items.length ?? 0) === 0 ? (
                <EmptyState icon={<Radar className="h-4 w-4" />} title="No activity" description="Platform events appear as users sign in and change the deployment." />
              ) : (
                <div className="divide-y divide-ink-700/60">
                  {activity.data?.items.map((event) => (
                    <div key={event.id} className="flex flex-col gap-1.5 px-5 py-3.5 sm:flex-row sm:items-start sm:justify-between">
                      <div className="min-w-0">
                        <p className="break-words font-mono text-[11px] text-amber-700">{event.action}</p>
                        <p className="mt-0.5 text-[10.5px] text-ink-400">
                          {event.actor || "System"}{event.actor_email ? ` - ${event.actor_email}` : ""}{event.org_name ? ` - ${event.org_name}` : " - Platform"}{event.ip ? ` - ${event.ip}` : ""}
                        </p>
                        {event.resource_id ? <p className="mt-0.5 max-w-[420px] truncate font-mono text-[9px] text-ink-400">{event.resource_type}: {event.resource_id}</p> : null}
                        {event.metadata && Object.keys(event.metadata).length ? (
                          <details className="mt-1">
                            <summary className="cursor-pointer text-[9.5px] text-ink-400 hover:text-ink-300">View details</summary>
                            <pre className="mt-1 max-h-40 max-w-lg overflow-auto rounded border border-ink-700 bg-ink-950 p-2 font-mono text-[9px] leading-relaxed text-ink-400">{JSON.stringify(event.metadata, null, 2)}</pre>
                          </details>
                        ) : null}
                      </div>
                      <div className="shrink-0 text-[10px] text-ink-400" title={formatDateTime(event.created_at)}>{relativeTime(event.created_at)}</div>
                    </div>
                  ))}
                </div>
              )}
            </TableShell>
          </QueryState>
        </div>
      ) : null}

      <UserManageModal
        userId={manageUserId}
        open={Boolean(manageUserId)}
        isSelf={manageUserId === me.data?.user.id}
        onClose={() => setManageUserId("")}
      />
      {editingOrg ? <OrgEditModal org={editingOrg} onClose={() => setEditingOrg(null)} /> : null}
    </PageTransition>
  );
}

function OrganizationRow({ org, defaultOpen = false, onEdit }: { org: PlatformOrganization; defaultOpen?: boolean; onEdit: () => void }) {
  const [open, setOpen] = useState(defaultOpen);
  const detail = usePlatformOrganization(open ? org.id : "");
  const client = useQueryClient();
  const invalidate = () => void client.invalidateQueries({ queryKey: ["platform"] });

  useEffect(() => {
    if (defaultOpen) setOpen(true);
  }, [defaultOpen]);

  const updateMember = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: string }) =>
      api.patch(`/platform/organizations/${org.id}/members/${userId}`, { role_id: role }),
    onSuccess: () => { toast.success("Member role updated"); invalidate(); },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Could not update the member."),
  });

  const removeMember = useMutation({
    mutationFn: (userId: string) => api.delete(`/platform/organizations/${org.id}/members/${userId}`),
    onSuccess: () => { toast.success("Member removed"); invalidate(); },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Could not remove the member."),
  });

  return (
    <>
      <tr>
        <td>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[12px] font-medium text-ink-100">{org.name}</span>
            {org.emergency_stop ? <Badge className="border-red-500/25 bg-red-500/10 text-red-700">emergency stop</Badge> : null}
          </div>
          <div className="mt-0.5 font-mono text-[9.5px] text-ink-400">{org.slug}</div>
        </td>
        <td>
          <div className="text-[11.5px] text-ink-200">{org.owner_name || "-"}</div>
          <div className="mt-0.5 text-[9.5px] text-ink-400">{org.owner_email || ""}</div>
        </td>
        <td className="text-[11.5px] text-ink-200">{org.member_count}</td>
        <td className="text-[11.5px] text-ink-200">{org.asset_count}</td>
        <td className="text-[11.5px] text-ink-200">{org.scan_count}</td>
        <td className="text-[11.5px] text-ink-200">{org.open_findings}</td>
        <td>
          <div className="flex justify-end gap-1">
            <Button variant="ghost" size="sm" onClick={() => setOpen((value) => !value)}>{open ? "Hide" : "Inspect"}</Button>
            <Button variant="ghost" size="icon" className="h-8 w-8" onClick={onEdit} aria-label={`Edit ${org.name}`}><Pencil className="h-3.5 w-3.5" /></Button>
          </div>
        </td>
      </tr>
      {open ? (
        <tr>
          <td colSpan={7} className="bg-ink-900/40">
            <QueryState loading={detail.isLoading} error={detail.error} skeleton={<div className="space-y-2 p-3"><Skeleton className="h-12 w-full" /><Skeleton className="h-12 w-full" /></div>}>
              <div className="grid gap-4 p-3 lg:grid-cols-2">
                <div>
                  <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-400">Members</p>
                  <div className="space-y-1.5">
                    {detail.data?.members.map((member) => (
                      <div key={member.user_id} className="flex flex-col gap-2 rounded-lg border border-ink-700 bg-ink-850 px-3 py-2 sm:flex-row sm:items-center sm:justify-between">
                        <div className="min-w-0">
                          <p className="truncate text-[11.5px] text-ink-100">{member.name}{member.is_active ? "" : " (suspended)"}</p>
                          <p className="truncate text-[9.5px] text-ink-400">{member.email}</p>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          <Select
                            value={member.role}
                            onChange={(event) => {
                              const role = event.target.value;
                              if (window.confirm(`Change ${member.name} to ${role}?`)) updateMember.mutate({ userId: member.user_id, role });
                            }}
                            className="h-7 w-auto border-ink-700 bg-ink-900 text-[10px]"
                          >
                            {["owner", "admin", "analyst", "viewer"].map((role) => <option key={role} value={role}>{role}</option>)}
                          </Select>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 text-ink-400 hover:text-red-700"
                            loading={removeMember.isPending && removeMember.variables === member.user_id}
                            onClick={() => { if (window.confirm(`Remove ${member.name} from ${org.name}?`)) removeMember.mutate(member.user_id); }}
                            aria-label={`Remove ${member.name}`}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-400">Recent assessments</p>
                  <div className="space-y-1.5">
                    {(detail.data?.recent_scans.length ?? 0) === 0 ? <p className="text-[11px] text-ink-400">No assessments yet.</p> : null}
                    {detail.data?.recent_scans.map((scan) => (
                      <div key={scan.id} className="flex items-center justify-between gap-3 rounded-lg border border-ink-700 bg-ink-850 px-3 py-2">
                        <div className="min-w-0">
                          <p className="truncate text-[11.5px] text-ink-100">{scan.scanner}</p>
                          <p className="text-[9.5px] text-ink-400">{scan.category} - {relativeTime(scan.created_at)}</p>
                        </div>
                        <Badge>{scan.status}</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </QueryState>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function UserRow({ user, isSelf, onManage }: { user: PlatformUser; isSelf: boolean; onManage: () => void }) {
  return (
    <tr>
      <td>
        <div className="text-[12px] font-medium text-ink-100">{user.name}{isSelf ? " (you)" : ""}</div>
        <div className="mt-0.5 text-[9.5px] text-ink-400">{user.email}</div>
      </td>
      <td>
        <div className="flex flex-wrap gap-1">
          {user.memberships.length === 0 ? <span className="text-[10px] text-ink-400">No organization</span> : null}
          {user.memberships.map((membership) => (
            <Badge key={membership.org_id}>{membership.org_name} - {membership.role_name}</Badge>
          ))}
        </div>
      </td>
      <td>{user.is_active ? <Badge className="border-lime-500/25 bg-lime-500/10 text-lime-700">active</Badge> : <Badge className="border-red-500/25 bg-red-500/10 text-red-700">suspended</Badge>}</td>
      <td>{user.is_platform_admin ? <Badge className="border-amber-500/25 bg-amber-500/10 text-amber-700"><Crown className="mr-1 h-3 w-3" /> platform admin</Badge> : <span className="text-[10px] text-ink-400">member</span>}</td>
      <td className="whitespace-nowrap text-[10.5px] text-ink-400">{user.last_login_at ? relativeTime(user.last_login_at) : "Never"}</td>
      <td className="text-right"><Button variant="secondary" size="sm" onClick={onManage}>Manage</Button></td>
    </tr>
  );
}

function UserManageModal({ userId, open, isSelf, onClose }: { userId: string; open: boolean; isSelf: boolean; onClose: () => void }) {
  const detail = usePlatformUser(open ? userId : "");
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [tempPassword, setTempPassword] = useState("");
  const invalidate = () => void client.invalidateQueries({ queryKey: ["platform"] });

  useEffect(() => {
    if (detail.data) {
      setName(detail.data.user.name);
      setEmail(detail.data.user.email);
    }
  }, [detail.data]);

  useEffect(() => {
    setTempPassword("");
  }, [userId, open]);

  const update = useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.patch(`/platform/users/${userId}`, payload),
    onSuccess: () => { toast.success("User updated"); invalidate(); },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Could not update the user."),
  });

  const resetPassword = useMutation({
    mutationFn: () => api.post<{ temporary_password: string; sessions_revoked: number }>(`/platform/users/${userId}/reset-password`, {}),
    onSuccess: (data) => {
      setTempPassword(data.temporary_password);
      toast.success(`Password reset. ${data.sessions_revoked} sessions signed out.`);
      invalidate();
    },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Could not reset the password."),
  });

  const signOut = useMutation({
    mutationFn: () => api.post<{ revoked: number }>(`/platform/users/${userId}/sign-out`),
    onSuccess: (data) => { toast.success(`${data.revoked} sessions signed out`); invalidate(); },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Could not sign out the user."),
  });

  const revokeSession = useMutation({
    mutationFn: (id: string) => api.delete(`/platform/sessions/${id}`),
    onSuccess: () => { toast.success("Session revoked"); invalidate(); },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Could not revoke the session."),
  });

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success("Copied to clipboard");
    } catch {
      toast.error("Could not copy. Select the password manually.");
    }
  };

  const user = detail.data?.user;
  const active = Boolean(user?.is_active);
  const platformAdmin = Boolean(user?.is_platform_admin);

  return (
    <Modal open={open} onClose={onClose} title="Manage user" description={user?.email} width="max-w-3xl">
      <QueryState loading={detail.isLoading} error={detail.error} skeleton={<div className="space-y-3"><Skeleton className="h-16 w-full" /><Skeleton className="h-24 w-full" /><Skeleton className="h-24 w-full" /></div>}>
        {detail.data && user ? (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex h-10 w-10 items-center justify-center rounded-full text-[12px] font-bold text-ink-50" style={{ backgroundColor: user.avatar_color }}>{user.name.slice(0, 2).toUpperCase()}</div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-[14px] font-semibold text-ink-50">{user.name}</p>
                <p className="truncate text-[11px] text-ink-400">Joined {formatDateTime(user.created_at)}{user.last_login_at ? `, last seen ${relativeTime(user.last_login_at)}` : ""}</p>
              </div>
              {active ? <Badge className="border-lime-500/25 bg-lime-500/10 text-lime-700">active</Badge> : <Badge className="border-red-500/25 bg-red-500/10 text-red-700">suspended</Badge>}
              {platformAdmin ? <Badge className="border-amber-500/25 bg-amber-500/10 text-amber-700"><Crown className="mr-1 h-3 w-3" /> platform admin</Badge> : null}
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Name"><Input value={name} onChange={(event) => setName(event.target.value)} /></Field>
              <Field label="Email address"><Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></Field>
            </div>

            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={() => update.mutate({ name: name.trim(), email: email.trim() })} loading={update.isPending} disabled={!name.trim() || !email.trim()}><Save className="h-3.5 w-3.5" /> Save profile</Button>
              <Button variant={active ? "danger" : "secondary"} size="sm" disabled={isSelf && active} onClick={() => { if (window.confirm(`${active ? "Suspend" : "Activate"} ${user.email}?`)) update.mutate({ is_active: !active }); }}><Ban className="h-3.5 w-3.5" /> {active ? "Suspend account" : "Activate account"}</Button>
              <Button variant="secondary" size="sm" onClick={() => { if (window.confirm(`Reset the password for ${user.email}? All their sessions will be signed out.`)) resetPassword.mutate(); }} loading={resetPassword.isPending}><KeyRound className="h-3.5 w-3.5" /> Reset password</Button>
              <Button variant="secondary" size="sm" onClick={() => { if (window.confirm(`Sign ${user.email} out of every session?`)) signOut.mutate(); }} loading={signOut.isPending}><LogOut className="h-3.5 w-3.5" /> Force sign out</Button>
              <Button variant="secondary" size="sm" disabled={isSelf && platformAdmin} onClick={() => { if (window.confirm(`${platformAdmin ? "Revoke platform admin from" : "Make"} ${user.email} ${platformAdmin ? "" : "a platform admin"}?`)) update.mutate({ is_platform_admin: !platformAdmin }); }}><Crown className="h-3.5 w-3.5" /> {platformAdmin ? "Revoke platform admin" : "Make platform admin"}</Button>
            </div>

            {tempPassword ? (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/[0.06] p-3">
                <p className="text-[11px] font-medium text-amber-800">Temporary password, shown once</p>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <code className="rounded border border-ink-600 bg-ink-900 px-2 py-1 font-mono text-[12px] text-ink-100">{tempPassword}</code>
                  <Button variant="secondary" size="sm" onClick={() => void copy(tempPassword)}><Copy className="h-3.5 w-3.5" /> Copy</Button>
                </div>
                <p className="mt-2 text-[10px] text-ink-400">Send this to the user through a secure channel. It will not be shown again.</p>
              </div>
            ) : null}

            <div className="grid gap-2 sm:grid-cols-4">
              <MiniStat label="Assets owned" value={detail.data.counts.assets_owned} />
              <MiniStat label="Findings assigned" value={detail.data.counts.findings_assigned} />
              <MiniStat label="Scans started" value={detail.data.counts.scans_started} />
              <MiniStat label="Reports created" value={detail.data.counts.reports_created} />
            </div>

            <div>
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-400">Organizations and roles</p>
              <div className="space-y-1.5">
                {detail.data.memberships.length === 0 ? <p className="text-[11px] text-ink-400">This user does not belong to any organization.</p> : null}
                {detail.data.memberships.map((membership) => (
                  <div key={membership.org_id} className="flex items-center justify-between gap-3 rounded-lg border border-ink-700 bg-ink-850 px-3 py-2">
                    <div className="min-w-0">
                      <p className="truncate text-[11.5px] text-ink-100">{membership.org_name}</p>
                      <p className="text-[9.5px] text-ink-400">Joined {formatDateTime(membership.joined_at)}</p>
                    </div>
                    <Badge>{membership.role_name}</Badge>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-400">Active sessions</p>
              <div className="space-y-1.5">
                {detail.data.sessions.length === 0 ? <p className="text-[11px] text-ink-400">No active sessions.</p> : null}
                {detail.data.sessions.map((session) => (
                  <div key={session.id} className="flex flex-col gap-2 rounded-lg border border-ink-700 bg-ink-850 px-3 py-2 sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0">
                      <p className="truncate text-[11px] text-ink-200">{session.ip || "Unknown IP"} - {session.org_name}</p>
                      <p className="truncate text-[9px] text-ink-400" title={session.user_agent}>{session.user_agent || "Unknown device"} - last seen {relativeTime(session.last_seen_at)}</p>
                    </div>
                    <Button variant="ghost" size="sm" className="text-ink-400 hover:text-red-700" loading={revokeSession.isPending && revokeSession.variables === session.id} onClick={() => { if (window.confirm("Revoke this session?")) revokeSession.mutate(session.id); }}>Revoke</Button>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-400">Recent activity</p>
              <div className="max-h-56 space-y-1.5 overflow-y-auto pr-1">
                {detail.data.activity.length === 0 ? <p className="text-[11px] text-ink-400">No activity recorded.</p> : null}
                {detail.data.activity.map((event) => (
                  <div key={event.id} className="rounded-lg border border-ink-700 bg-ink-850 px-3 py-2">
                    <div className="flex items-start justify-between gap-2">
                      <p className="break-words font-mono text-[10px] text-amber-700">{event.action}</p>
                      <span className="shrink-0 text-[9px] text-ink-400">{relativeTime(event.created_at)}</span>
                    </div>
                    <p className="mt-0.5 text-[9.5px] text-ink-400">{event.org_name || "Platform"}{event.ip ? ` - ${event.ip}` : ""}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </QueryState>
    </Modal>
  );
}

function OrgEditModal({ org, onClose }: { org: PlatformOrganization; onClose: () => void }) {
  const client = useQueryClient();
  const [name, setName] = useState(org.name);
  const [slug, setSlug] = useState(org.slug);
  const [retention, setRetention] = useState(org.retention_days);
  const [emergencyStop, setEmergencyStop] = useState(org.emergency_stop);

  const update = useMutation({
    mutationFn: () => api.patch(`/platform/organizations/${org.id}`, {
      name: name.trim(), slug: slug.trim(), retention_days: retention, emergency_stop: emergencyStop,
    }),
    onSuccess: () => {
      toast.success("Organization updated");
      void client.invalidateQueries({ queryKey: ["platform"] });
      onClose();
    },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Could not update the organization."),
  });

  return (
    <Modal open onClose={onClose} title="Edit organization" description={org.name} width="max-w-lg">
      <div className="space-y-4">
        <Field label="Organization name"><Input value={name} onChange={(event) => setName(event.target.value)} /></Field>
        <Field label="Slug" hint="Lowercase letters, numbers and hyphens"><Input value={slug} onChange={(event) => setSlug(event.target.value)} className="font-mono" /></Field>
        <Field label="Data retention" hint="Days"><Input type="number" min={30} max={3650} value={retention} onChange={(event) => setRetention(Number(event.target.value))} /></Field>
        <Toggle checked={emergencyStop} onChange={setEmergencyStop} label="Emergency stop" description="Blocks every new assessment in this organization." />
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={() => update.mutate()} loading={update.isPending} disabled={!name.trim() || !slug.trim()}><Save className="h-3.5 w-3.5" /> Save changes</Button>
        </div>
      </div>
    </Modal>
  );
}

function MiniStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900 px-3 py-2">
      <p className="text-[9.5px] text-ink-400">{label}</p>
      <p className="mt-1 text-[16px] font-semibold text-ink-50">{value}</p>
    </div>
  );
}

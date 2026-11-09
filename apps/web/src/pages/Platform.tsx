import { useEffect, useState } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Building2, Crown, Radar, ShieldAlert, Users } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import {
  useMe,
  usePlatformActivity,
  usePlatformOrganization,
  usePlatformOrganizations,
  usePlatformOverview,
  usePlatformUsers,
} from "@/hooks/queries";
import { formatDateTime, relativeTime } from "@/lib/utils";
import type { PlatformOrganization, PlatformUser } from "@/types";
import {
  Badge,
  Button,
  EmptyState,
  PageHeader,
  PageTransition,
  QueryState,
  Skeleton,
  SkeletonTable,
  StatCard,
  TableShell,
  Tabs,
} from "@/components/ui";

type Tab = "organizations" | "users" | "activity";

export function PlatformPage() {
  const [params] = useSearchParams();
  const requestedTab = params.get("tab");
  const [tab, setTab] = useState<Tab>(requestedTab === "users" || requestedTab === "activity" ? requestedTab : "organizations");
  const openOrgId = params.get("org") ?? "";
  const me = useMe();

  useEffect(() => {
    if (requestedTab === "users" || requestedTab === "activity" || requestedTab === "organizations") setTab(requestedTab);
  }, [requestedTab]);
  const overview = usePlatformOverview();
  const organizations = usePlatformOrganizations();
  const users = usePlatformUsers();
  const activity = usePlatformActivity();
  const client = useQueryClient();

  const updateUser = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      api.patch(`/platform/users/${id}`, payload),
    onSuccess: () => {
      toast.success("User updated");
      void client.invalidateQueries({ queryKey: ["platform"] });
    },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Could not update the user."),
  });

  if (me.isLoading) return null;
  if (!me.data?.platform_admin) return <Navigate to="/dashboard" replace />;

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Super admin"
        title="Platform control"
        description="Every organization, member and recent event across this deployment. This area is only visible to platform administrators."
        actions={<Badge className="border-amber-500/25 bg-amber-500/10 text-amber-700"><Crown className="mr-1 h-3 w-3" /> {me.data?.user.email ?? ""}</Badge>}
      />

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <StatCard label="Organizations" value={overview.data?.organizations ?? "-"} hint="Workspaces on this deployment" icon={<Building2 className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Users" value={overview.data?.users ?? "-"} hint={`${overview.data?.active_users ?? 0} active`} icon={<Users className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Active assets" value={overview.data?.assets ?? "-"} hint="Registered and testable" icon={<ShieldAlert className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Running scans" value={overview.data?.running_scans ?? "-"} hint={`${overview.data?.scans ?? 0} total assessments`} tone={overview.data?.running_scans ? "warn" : "default"} icon={<Radar className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Open findings" value={overview.data?.findings ?? "-"} hint={`${overview.data?.high_risk_findings ?? 0} critical or high`} tone={overview.data?.high_risk_findings ? "danger" : "default"} icon={<ShieldAlert className="h-4 w-4" />} loading={overview.isLoading} />
        <StatCard label="Platform admins" value={overview.data?.platform_admins ?? "-"} hint="Accounts with cross-organization access" tone="good" icon={<Crown className="h-4 w-4" />} loading={overview.isLoading} />
      </div>

      <div className="mt-6">
        <Tabs<Tab>
          value={tab}
          onChange={setTab}
          tabs={[
            { label: "Organizations", value: "organizations", count: organizations.data?.items.length },
            { label: "Users", value: "users", count: users.data?.items.length },
            { label: "Activity", value: "activity" },
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
                    {organizations.data?.items.map((org) => <OrganizationRow key={org.id} org={org} defaultOpen={org.id === openOrgId} />)}
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
                      <UserRow
                        key={user.id}
                        user={user}
                        isSelf={user.id === me.data?.user.id}
                        pending={updateUser.isPending}
                        onUpdate={(payload) => updateUser.mutate({ id: user.id, payload })}
                      />
                    ))}
                  </tbody>
                </table>
              )}
            </TableShell>
          </QueryState>
        </div>
      ) : null}

      {tab === "activity" ? (
        <div className="mt-4">
          <QueryState
            loading={activity.isLoading}
            error={activity.error}
            onRetry={() => void activity.refetch()}
            skeleton={<div className="space-y-2">{Array.from({ length: 6 }).map((_, index) => <Skeleton key={index} className="h-14 w-full rounded-xl" />)}</div>}
          >
            <TableShell>
              {(activity.data?.items.length ?? 0) === 0 ? (
                <EmptyState icon={<Radar className="h-4 w-4" />} title="No activity" description="Platform events appear as users sign in and change the deployment." />
              ) : (
                <div className="divide-y divide-ink-700/60">
                  {activity.data?.items.map((event) => (
                    <div key={event.id} className="flex flex-col gap-1.5 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
                      <div className="min-w-0">
                        <p className="break-words font-mono text-[11px] text-amber-700">{event.action}</p>
                        <p className="mt-0.5 text-[10.5px] text-ink-400">
                          {event.actor || "System"}{event.actor_email ? ` · ${event.actor_email}` : ""}{event.org_name ? ` · ${event.org_name}` : " · Platform"}
                        </p>
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
    </PageTransition>
  );
}

function OrganizationRow({ org, defaultOpen = false }: { org: PlatformOrganization; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const detail = usePlatformOrganization(open ? org.id : "");
  useEffect(() => {
    if (defaultOpen) setOpen(true);
  }, [defaultOpen]);
  return (
    <>
      <tr>
        <td>
          <div className="text-[12px] font-medium text-ink-100">{org.name}</div>
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
        <td className="text-right"><Button variant="ghost" size="sm" onClick={() => setOpen((value) => !value)}>{open ? "Hide" : "Inspect"}</Button></td>
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
                      <div key={member.user_id} className="flex items-center justify-between gap-3 rounded-lg border border-ink-700 bg-ink-850 px-3 py-2">
                        <div className="min-w-0">
                          <p className="truncate text-[11.5px] text-ink-100">{member.name}</p>
                          <p className="truncate text-[9.5px] text-ink-400">{member.email}</p>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          <Badge>{member.role_name}</Badge>
                          {member.is_active ? null : <Badge className="border-red-500/25 bg-red-500/10 text-red-700">disabled</Badge>}
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
                          <p className="text-[9.5px] text-ink-400">{scan.category} · {relativeTime(scan.created_at)}</p>
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

function UserRow({
  user,
  isSelf,
  pending,
  onUpdate,
}: {
  user: PlatformUser;
  isSelf: boolean;
  pending: boolean;
  onUpdate: (payload: Record<string, unknown>) => void;
}) {
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
            <Badge key={membership.org_id}>{membership.org_name} · {membership.role_name}</Badge>
          ))}
        </div>
      </td>
      <td>{user.is_active ? <Badge className="border-lime-500/25 bg-lime-500/10 text-lime-700">active</Badge> : <Badge className="border-red-500/25 bg-red-500/10 text-red-700">disabled</Badge>}</td>
      <td>{user.is_platform_admin ? <Badge className="border-amber-500/25 bg-amber-500/10 text-amber-700"><Crown className="mr-1 h-3 w-3" /> platform admin</Badge> : <span className="text-[10px] text-ink-400">member</span>}</td>
      <td className="whitespace-nowrap text-[10.5px] text-ink-400">{user.last_login_at ? relativeTime(user.last_login_at) : "Never"}</td>
      <td>
        <div className="flex flex-wrap justify-end gap-1">
          <Button
            variant="ghost"
            size="sm"
            disabled={pending || (isSelf && user.is_active)}
            onClick={() => {
              const next = !user.is_active;
              if (window.confirm(`${next ? "Enable" : "Disable"} ${user.email}?`)) onUpdate({ is_active: next });
            }}
          >
            {user.is_active ? "Disable" : "Enable"}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={pending || (isSelf && user.is_platform_admin)}
            onClick={() => {
              const next = !user.is_platform_admin;
              if (window.confirm(`${next ? "Grant" : "Revoke"} platform admin access for ${user.email}?`)) onUpdate({ is_platform_admin: next });
            }}
          >
            {user.is_platform_admin ? "Revoke admin" : "Make admin"}
          </Button>
        </div>
      </td>
    </tr>
  );
}

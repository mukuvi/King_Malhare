import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Bell, CheckCheck, FileText, Radio, ShieldAlert, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { useNotifications } from "@/hooks/queries";
import { formatDateTime, relativeTime } from "@/lib/utils";
import type { Notification } from "@/types";
import { Badge, Button, EmptyState, PageHeader, PageTransition, Pagination, QueryState, Skeleton, TableShell, Tabs } from "@/components/ui";

const icons = {
  scan: Radio,
  finding: ShieldAlert,
  report: FileText,
  system: ShieldCheck,
  authorization: ShieldCheck,
};

export function NotificationsPage() {
  const [tab, setTab] = useState<"all" | "unread">("all");
  const [page, setPage] = useState(1);
  const notifications = useNotifications(tab === "unread", page);
  const client = useQueryClient();
  const navigate = useNavigate();

  const mark = useMutation({
    mutationFn: (payload: { ids?: string[]; all?: boolean }) => api.post("/notifications/read", payload),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["notifications"] });
      toast.success("Notifications updated");
    },
  });

  const openNotification = (notification: Notification) => {
    if (!notification.read) mark.mutate({ ids: [notification.id] });
    if (notification.link) navigate(notification.link);
  };

  return (
    <PageTransition>
      <PageHeader
        eyebrow="Inbox"
        title="Notifications"
        description="Scan outcomes, report readiness, authorization records and system events for this organization."
        actions={notifications.data?.unread ? <Button variant="secondary" size="sm" onClick={() => mark.mutate({ all: true })} loading={mark.isPending}><CheckCheck className="h-3.5 w-3.5" /> Mark all read</Button> : null}
      />

      <div className="mt-6">
        <Tabs<"all" | "unread">
          value={tab}
          onChange={(value) => { setTab(value); setPage(1); }}
          tabs={[
            { label: "All", value: "all", count: notifications.data?.total },
            { label: "Unread", value: "unread", count: notifications.data?.unread },
          ]}
        />
      </div>

      <div className="mt-4">
        <QueryState loading={notifications.isLoading} error={notifications.error} onRetry={() => void notifications.refetch()} skeleton={<div className="space-y-2">{Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-20 w-full rounded-xl" />)}</div>}>
          <TableShell footer={<Pagination page={notifications.data?.page ?? 1} perPage={notifications.data?.per_page ?? 25} total={notifications.data?.total ?? 0} onPage={setPage} />}>
            {(notifications.data?.items.length ?? 0) === 0 ? (
              <EmptyState icon={<Bell className="h-4 w-4" />} title={tab === "unread" ? "No unread notifications" : "No notifications"} description="Notifications are created when an assessment finishes, a report is ready or an authorization is recorded." />
            ) : (
              <div className="divide-y divide-ink-700/60">
                {notifications.data?.items.map((notification) => {
                  const Icon = icons[notification.type] ?? Bell;
                  return (
                    <button key={notification.id} onClick={() => openNotification(notification)} className={`flex w-full items-start gap-3 px-5 py-4 text-left transition-colors hover:bg-ink-800/60 ${notification.read ? "" : "bg-amber-500/[0.025]"}`}>
                      <span className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${notification.read ? "border-ink-600 bg-ink-800 text-ink-400" : "border-amber-500/25 bg-amber-500/10 text-amber-700"}`}>
                        <Icon className="h-3.5 w-3.5" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <p className="text-[12.5px] font-medium text-ink-100">{notification.title}</p>
                          {!notification.read ? <span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> : null}
                        </div>
                        <p className="mt-1 text-[11.5px] leading-relaxed text-ink-400">{notification.body}</p>
                        <p className="mt-1.5 text-[9.5px] text-ink-400">{formatDateTime(notification.created_at)} · {relativeTime(notification.created_at)}</p>
                      </div>
                      <Badge className="mt-0.5 hidden sm:inline-flex">{notification.type}</Badge>
                    </button>
                  );
                })}
              </div>
            )}
          </TableShell>
        </QueryState>
      </div>
      <p className="mt-4 text-[10.5px] text-ink-400">Notification delivery is in-app only. Email and webhook delivery are not configured in this deployment.</p>
    </PageTransition>
  );
}

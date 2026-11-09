import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { api, queryString } from "@/lib/api";
import type {
  ApiKey,
  Asset,
  Authorization,
  CVE,
  CWE,
  CloudConnection,
  Finding,
  FindingDetail,
  IntegrationStatus,
  Me,
  Member,
  Notification,
  Organization,
  Overview,
  Paginated,
  PlatformActivity,
  PlatformOrganization,
  PlatformOverview,
  PlatformSession,
  PlatformUser,
  PlatformUserDetail,
  Report,
  Scan,
  ScanDetail,
  ScanProfile,
  ScannerInfo,
  Schedule,
  TrendPoint,
} from "@/types";
import { useAuthStore } from "@/stores/ui";

export const queryKeys = {
  me: ["me"] as const,
  overview: ["overview"] as const,
  trends: (days: number) => ["trends", days] as const,
  assets: (params: string) => ["assets", params] as const,
  asset: (id: string) => ["asset", id] as const,
  authorizations: (assetId: string) => ["authorizations", assetId] as const,
  scans: (params: string) => ["scans", params] as const,
  scan: (id: string) => ["scan", id] as const,
  findings: (params: string) => ["findings", params] as const,
  finding: (id: string) => ["finding", id] as const,
  reports: (params: string) => ["reports", params] as const,
  report: (id: string) => ["report", id] as const,
  notifications: (params: string) => ["notifications", params] as const,
  integrations: ["integrations"] as const,
  scanners: ["scanners"] as const,
  profiles: ["profiles"] as const,
  members: ["members"] as const,
  audit: (params: string) => ["audit", params] as const,
  intelRecent: ["intel", "recent"] as const,
  cwes: ["intel", "cwes"] as const,
  apiKeys: ["api-keys"] as const,
  schedules: ["schedules"] as const,
  cloud: ["cloud-connections"] as const,
  platformOverview: ["platform", "overview"] as const,
  platformOrganizations: ["platform", "organizations"] as const,
  platformOrganization: (id: string) => ["platform", "organization", id] as const,
  platformUsers: ["platform", "users"] as const,
  platformUser: (id: string) => ["platform", "user", id] as const,
  platformSessions: ["platform", "sessions"] as const,
  platformActivity: (params: string) => ["platform", "activity", params] as const,
};

export function useMe() {
  const setAuth = useAuthStore((state) => state.setAuth);
  const query = useQuery({
    queryKey: queryKeys.me,
    queryFn: () => api.get<Me>("/auth/me"),
    retry: false,
    staleTime: 60_000,
  });
  useEffect(() => {
    if (query.data) {
      setAuth(query.data.permissions, query.data.role, query.data.org.name);
    }
  }, [query.data, setAuth]);
  return query;
}

export function useOverview() {
  return useQuery({ queryKey: queryKeys.overview, queryFn: () => api.get<Overview>("/stats/overview") });
}

export function useTrends(days = 30) {
  return useQuery({
    queryKey: queryKeys.trends(days),
    queryFn: () => api.get<{ days: number; items: TrendPoint[] }>(`/stats/trends${queryString({ days })}`),
  });
}

export function useAssets(params: Record<string, string | number | undefined> = {}) {
  const qs = queryString(params);
  return useQuery({ queryKey: queryKeys.assets(qs), queryFn: () => api.get<Paginated<Asset>>(`/assets${qs}`) });
}

export function useAsset(id?: string) {
  return useQuery({
    queryKey: queryKeys.asset(id ?? ""),
    queryFn: () => api.get<Asset>(`/assets/${id}`),
    enabled: Boolean(id),
  });
}

export function useAuthorizations(assetId?: string) {
  return useQuery({
    queryKey: queryKeys.authorizations(assetId ?? ""),
    queryFn: () => api.get<Authorization[]>(`/assets/${assetId}/authorizations`),
    enabled: Boolean(assetId),
  });
}

export function useScans(params: Record<string, string | number | undefined> = {}) {
  const qs = queryString(params);
  return useQuery({
    queryKey: queryKeys.scans(qs),
    queryFn: () => api.get<Paginated<Scan>>(`/scans${qs}`),
    refetchInterval: (query) =>
      query.state.data?.items.some((scan) => ["queued", "initializing", "running", "pending"].includes(scan.status)) ? 10_000 : false,
  });
}

export function useScan(id?: string, live = false) {
  return useQuery({
    queryKey: queryKeys.scan(id ?? ""),
    queryFn: () => api.get<ScanDetail>(`/scans/${id}`),
    enabled: Boolean(id),
    refetchInterval: live ? 5_000 : false,
  });
}

export function useFindings(params: Record<string, string | number | undefined> = {}) {
  const qs = queryString(params);
  return useQuery({ queryKey: queryKeys.findings(qs), queryFn: () => api.get<Paginated<Finding>>(`/findings${qs}`) });
}

export function useFinding(id?: string) {
  return useQuery({
    queryKey: queryKeys.finding(id ?? ""),
    queryFn: () => api.get<FindingDetail>(`/findings/${id}`),
    enabled: Boolean(id),
  });
}

export function useReports(params: Record<string, string | number | undefined> = {}) {
  const qs = queryString(params);
  return useQuery({ queryKey: queryKeys.reports(qs), queryFn: () => api.get<Paginated<Report>>(`/reports${qs}`) });
}

export function useReport(id?: string) {
  return useQuery({
    queryKey: queryKeys.report(id ?? ""),
    queryFn: () => api.get<Report>(`/reports/${id}`),
    enabled: Boolean(id),
  });
}

export function useNotifications(unreadOnly = false, page = 1) {
  const qs = queryString({ unread: unreadOnly, page, per_page: 25 });
  return useQuery({
    queryKey: queryKeys.notifications(qs),
    queryFn: () => api.get<{ items: Notification[]; total: number; unread: number; page: number; per_page: number }>(`/notifications${qs}`),
    refetchInterval: 60_000,
  });
}

export function useIntegrations() {
  return useQuery({ queryKey: queryKeys.integrations, queryFn: () => api.get<IntegrationStatus>("/integrations"), refetchInterval: 30_000 });
}

export function useScanners() {
  return useQuery({
    queryKey: queryKeys.scanners,
    queryFn: () => api.get<{ items: ScannerInfo[]; worker_online: boolean; queue_depth: number; emergency_stop: boolean }>("/scanners"),
    refetchInterval: 30_000,
  });
}

export function useProfiles() {
  return useQuery({ queryKey: queryKeys.profiles, queryFn: () => api.get<{ items: ScanProfile[] }>("/scan-profiles") });
}

export function useMembers() {
  return useQuery({ queryKey: queryKeys.members, queryFn: () => api.get<Member[]>("/org/members") });
}

export function useOrganization() {
  return useQuery({ queryKey: ["org"], queryFn: () => api.get<Organization>("/org") });
}

export function useAuditEvents(params: Record<string, string | number | undefined>) {
  const qs = queryString(params);
  return useQuery({
    queryKey: queryKeys.audit(qs),
    queryFn: () => api.get<Paginated<{ id: string; action: string; resource_type: string; resource_id?: string; metadata: Record<string, unknown>; ip?: string; actor?: string; actor_email?: string; created_at: string }>>(`/audit-events${qs}`),
  });
}

export function useRecentIntel() {
  return useQuery({ queryKey: queryKeys.intelRecent, queryFn: () => api.get<{ items: CVE[] }>("/intel/recent") });
}

export function useCWEs() {
  return useQuery({ queryKey: queryKeys.cwes, queryFn: () => api.get<{ items: CWE[] }>("/intel/cwes") });
}

export function useApiKeys() {
  return useQuery({ queryKey: queryKeys.apiKeys, queryFn: () => api.get<{ items: ApiKey[] }>("/api-keys") });
}

export function useSchedules() {
  return useQuery({ queryKey: queryKeys.schedules, queryFn: () => api.get<{ items: Schedule[] }>("/schedules") });
}

export function useCloudConnections() {
  return useQuery({ queryKey: queryKeys.cloud, queryFn: () => api.get<{ items: CloudConnection[] }>("/cloud-connections") });
}

export function useCVELookup() {
  return useMutation({ mutationFn: (cve: string) => api.get<CVE>(`/intel/cve/${encodeURIComponent(cve)}`) });
}

export function useUpdateFinding(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.patch(`/findings/${id}`, payload),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["finding", id] });
      void client.invalidateQueries({ queryKey: ["findings"] });
      void client.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}

export function useCreateScan() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.post<{ id: string; status: string }>("/scans", payload),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["scans"] });
      void client.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}

export function useCreateReport() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.post<{ id: string; status: string }>("/reports", payload),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["reports"] });
    },
  });
}

export function usePlatformOverview() {
  return useQuery({
    queryKey: queryKeys.platformOverview,
    queryFn: () => api.get<PlatformOverview>("/platform/overview"),
    retry: false,
  });
}

export function usePlatformOrganizations() {
  return useQuery({
    queryKey: queryKeys.platformOrganizations,
    queryFn: () => api.get<{ items: PlatformOrganization[] }>("/platform/organizations"),
    retry: false,
  });
}

export function usePlatformOrganization(id: string) {
  return useQuery({
    queryKey: queryKeys.platformOrganization(id),
    queryFn: () => api.get<{ organization: PlatformOrganization; members: Member[]; recent_scans: Array<{ id: string; scanner: string; category: string; status: string; progress: number; created_at: string }> }>(`/platform/organizations/${id}`),
    enabled: Boolean(id),
    retry: false,
  });
}

export function usePlatformUsers() {
  return useQuery({
    queryKey: queryKeys.platformUsers,
    queryFn: () => api.get<{ items: PlatformUser[] }>("/platform/users"),
    retry: false,
  });
}

export function usePlatformUser(id: string) {
  return useQuery({
    queryKey: queryKeys.platformUser(id),
    queryFn: () => api.get<PlatformUserDetail>(`/platform/users/${id}`),
    enabled: Boolean(id),
    retry: false,
  });
}

export function usePlatformSessions() {
  return useQuery({
    queryKey: queryKeys.platformSessions,
    queryFn: () => api.get<{ items: PlatformSession[] }>("/platform/sessions"),
    retry: false,
  });
}

export function usePlatformActivity(params: Record<string, string | number | undefined> = {}) {
  const qs = queryString(params);
  return useQuery({
    queryKey: queryKeys.platformActivity(qs),
    queryFn: () => api.get<{ items: PlatformActivity[]; total: number; page: number; per_page: number }>(`/platform/activity${qs}`),
    retry: false,
  });
}

export function useLogout() {
  const client = useQueryClient();
  const clear = useAuthStore((state) => state.clear);
  return useMutation({
    mutationFn: () => api.post("/auth/logout"),
    onSuccess: () => {
      clear();
      client.clear();
      window.location.href = "/";
    },
  });
}

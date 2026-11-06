import { useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import { RequireAuth } from "@/components/layout/AppShell";
import { LandingPage } from "@/pages/Landing";
import { LoginPage, RegisterPage } from "@/pages/Auth";
import { DashboardPage } from "@/pages/Dashboard";
import { AssetsPage } from "@/pages/Assets";
import { AssetDetailPage } from "@/pages/AssetDetail";
import { ScanCenterPage } from "@/pages/ScanCenter";
import { ScanNewPage } from "@/pages/ScanNew";
import { ScanDetailPage } from "@/pages/ScanDetail";
import { WebSecurityPage, NetworkSecurityPage, AuthenticationPage, CloudSecurityPage } from "@/pages/Categories";
import { FindingsPage } from "@/pages/Findings";
import { FindingDetailPage } from "@/pages/FindingDetail";
import { ReportsPage, ReportDetailPage } from "@/pages/Reports";
import { IntelPage } from "@/pages/Intel";
import { NotificationsPage } from "@/pages/Notifications";
import { AuditPage } from "@/pages/Audit";
import { IntegrationsPage } from "@/pages/Integrations";
import { SettingsPage } from "@/pages/Settings";
import { OrganizationPage } from "@/pages/Organization";
import { ApiDocsPage } from "@/pages/ApiDocs";
import { NotFoundPage } from "@/pages/NotFound";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 20_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        if (error instanceof Error && "status" in error) {
          const status = (error as { status?: number }).status;
          if (status && status >= 400 && status < 500) return false;
        }
        return failureCount < 2;
      },
    },
  },
});

function ScrollToTop() {
  const location = useLocation();
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" as ScrollBehavior });
  }, [location.pathname]);
  return null;
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ScrollToTop />
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route element={<RequireAuth />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/assets/:id" element={<AssetDetailPage />} />
            <Route path="/scans" element={<ScanCenterPage />} />
            <Route path="/scans/new" element={<ScanNewPage />} />
            <Route path="/scans/:id" element={<ScanDetailPage />} />
            <Route path="/web-security" element={<WebSecurityPage />} />
            <Route path="/network-security" element={<NetworkSecurityPage />} />
            <Route path="/cloud-security" element={<CloudSecurityPage />} />
            <Route path="/auth-testing" element={<AuthenticationPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/findings/:id" element={<FindingDetailPage />} />
            <Route path="/intel" element={<IntelPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/reports/:id" element={<ReportDetailPage />} />
            <Route path="/notifications" element={<NotificationsPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/integrations" element={<IntegrationsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/organization" element={<OrganizationPage />} />
            <Route path="/api-docs" element={<ApiDocsPage />} />
            <Route path="/dashboard/*" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
        <Toaster
          theme="dark"
          position="bottom-right"
          closeButton
          toastOptions={{
            style: {
              background: "#18181c",
              border: "1px solid #2a2a31",
              color: "#e9e4d8",
              fontSize: "12.5px",
            },
          }}
        />
      </BrowserRouter>
    </QueryClientProvider>
  );
}

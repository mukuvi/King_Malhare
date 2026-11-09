import { useEffect } from "react";
import { Link, Navigate, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useMe, useOrganization } from "@/hooks/queries";
import { useAuthStore, useUIStore } from "@/stores/ui";
import { setReadOnlyView } from "@/lib/api";
import { Logo } from "./Logo";
import { Sidebar, SidebarEmergencyBanner } from "./Sidebar";
import { Topbar } from "./Topbar";

export function BootScreen() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-ink-950">
      <div className="flex flex-col items-center gap-4">
        <div className="animate-pulseSoft">
          <Logo />
        </div>
        <div className="h-1 w-32 overflow-hidden rounded-full bg-ink-700">
          <div className="h-full w-1/2 animate-shimmer rounded-full bg-amber-400" />
        </div>
        <p className="text-[11px] tracking-wide text-ink-400">Verifying session</p>
      </div>
    </div>
  );
}

export function RequireAuth() {
  const me = useMe();
  const clear = useAuthStore((state) => state.clear);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const handler = () => {
      clear();
      navigate("/login", { replace: true });
    };
    window.addEventListener("km:unauthorized", handler);
    return () => window.removeEventListener("km:unauthorized", handler);
  }, [clear, navigate]);

  if (me.isLoading) return <BootScreen />;
  if (me.isError || !me.data) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }
  return <AppShell />;
}

function AppShell() {
  const org = useOrganization();
  const me = useMe();
  const viewMode = useUIStore((state) => state.viewMode);
  const setViewMode = useUIStore((state) => state.setViewMode);
  const navigate = useNavigate();
  const location = useLocation();
  const readOnly = Boolean(me.data?.platform_admin && viewMode === "user");
  const adminMode = Boolean(me.data?.platform_admin && viewMode === "admin");

  useEffect(() => {
    setReadOnlyView(readOnly);
  }, [readOnly]);

  useEffect(() => {
    if (!adminMode) return;
    const allowed = location.pathname === "/platform" || location.pathname.startsWith("/platform/") || location.pathname === "/settings";
    if (!allowed) navigate("/platform", { replace: true });
  }, [adminMode, location.pathname, navigate]);

  return (
    <div className="min-h-screen overflow-x-hidden">
      <Sidebar />
      <div className="lg:pl-[248px]">
        <Topbar />
        <SidebarEmergencyBanner active={Boolean(org.data?.emergency_stop)} />
        {readOnly ? (
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-amber-500/25 bg-amber-500/10 px-4 py-2 text-[11.5px] text-amber-800 sm:px-6">
            <span>Read-only user view. You can see the workspace, but changes are blocked.</span>
            <button
              onClick={() => { setViewMode("admin"); navigate("/platform"); }}
              className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-[10.5px] font-medium text-amber-800 hover:bg-amber-500/15"
            >
              Switch to Admin view
            </button>
          </div>
        ) : null}
        <main className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>
        <footer className="mx-auto flex w-full max-w-[1400px] flex-col gap-2 px-4 pb-8 pt-4 text-[10.5px] text-ink-400 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
          <span>King Malhare · Authorized security testing only</span>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <Link to="/privacy" className="hover:text-ink-100">Privacy Policy</Link>
            <Link to="/terms" className="hover:text-ink-100">Terms of Service</Link>
            <Link to="/api-docs" className="hover:text-ink-100">API</Link>
            <span className="font-mono text-[10px]">v1.0.0</span>
          </div>
        </footer>
      </div>
    </div>
  );
}

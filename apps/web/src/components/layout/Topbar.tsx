import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Bell, ChevronDown, Crown, Eye, LogOut, Menu, Plus, Settings } from "lucide-react";
import { useMe, useLogout, useNotifications } from "@/hooks/queries";
import { useUIStore } from "@/stores/ui";
import { initials } from "@/lib/utils";
import { buttonStyles } from "@/components/ui";
import { GlobalSearch } from "./GlobalSearch";
import { Logo } from "./Logo";

export function Topbar() {
  const { toggleSidebar } = useUIStore();
  const viewMode = useUIStore((state) => state.viewMode);
  const setViewMode = useUIStore((state) => state.setViewMode);
  const navigate = useNavigate();
  const { data: me } = useMe();
  const readOnly = Boolean(me?.platform_admin && viewMode === "user");
  const canScan = Boolean(me?.permissions.includes("scans:write")) && !readOnly;
  const { data: notifications } = useNotifications();
  const logout = useLogout();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onClick = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) setMenuOpen(false);
    };
    window.addEventListener("mousedown", onClick);
    return () => window.removeEventListener("mousedown", onClick);
  }, []);

  return (
    <header className="surface-blur sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-ink-700/80 px-4 sm:px-6">
      <button className="-ml-1 rounded-lg p-1.5 text-ink-300 hover:bg-ink-800 hover:text-ink-100 lg:hidden" onClick={toggleSidebar} aria-label="Open menu">
        <Menu className="h-5 w-5" />
      </button>
      <Link to="/dashboard" className="lg:hidden" aria-label="King Malhare dashboard">
        <Logo compact />
      </Link>

      <GlobalSearch />

      {me?.platform_admin ? (
        <div className="hidden items-center rounded-lg border border-ink-700 bg-ink-850 p-0.5 sm:flex">
          <button
            onClick={() => { setViewMode("admin"); navigate("/platform"); }}
            className={viewMode === "admin" ? "rounded-md bg-amber-400 px-2.5 py-1 text-[10.5px] font-semibold text-ink-50" : "rounded-md px-2.5 py-1 text-[10.5px] text-ink-300 hover:text-ink-100"}
          >
            Admin
          </button>
          <button
            onClick={() => { setViewMode("user"); navigate("/dashboard"); }}
            className={viewMode === "user" ? "rounded-md bg-ink-700 px-2.5 py-1 text-[10.5px] font-semibold text-ink-50" : "rounded-md px-2.5 py-1 text-[10.5px] text-ink-300 hover:text-ink-100"}
          >
            User
          </button>
        </div>
      ) : null}

      <div className="ml-auto flex items-center gap-2">
        {canScan ? (
          <Link to="/scans/new" className={buttonStyles("primary", "sm", "hidden sm:inline-flex")}>
            <Plus className="h-3.5 w-3.5" />
            New assessment
          </Link>
        ) : null}
        <Link to="/notifications" className="relative rounded-md p-2 text-ink-300 transition-colors hover:bg-ink-800 hover:text-ink-100" aria-label="Notifications">
          <Bell className="h-[18px] w-[18px]" strokeWidth={1.8} />
          {notifications?.unread ? (
            <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-amber-400 px-1 text-[8.5px] font-bold text-ink-50">
              {notifications.unread > 9 ? "9+" : notifications.unread}
            </span>
          ) : null}
        </Link>

        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setMenuOpen((open) => !open)}
            className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-850/60 py-1 pl-1 pr-2 text-left transition-colors hover:border-ink-500 hover:bg-ink-800"
            aria-haspopup="menu"
            aria-expanded={menuOpen}
          >
            <div className="flex h-7 w-7 items-center justify-center rounded-full text-[10px] font-bold text-ink-50" style={{ backgroundColor: me?.user.avatar_color ?? "#D98B8B" }}>
              {initials(me?.user.name)}
            </div>
            <ChevronDown className="h-3.5 w-3.5 text-ink-400" />
          </button>
          {menuOpen ? (
            <div className="absolute right-0 top-11 w-60 overflow-hidden rounded-xl border border-ink-600 bg-ink-850 shadow-lift" role="menu">
              <div className="border-b border-ink-700 px-4 py-3">
                <p className="truncate text-[12.5px] font-medium text-ink-50">{me?.user.name}</p>
                <p className="truncate text-[11px] text-ink-400">{me?.user.email}</p>
                <div className="mt-2 flex items-center gap-2">
                  <span className="rounded border border-ink-600 px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-ink-300">{me?.role}</span>
                  <span className="truncate text-[10px] text-ink-400">{me?.org.name}</span>
                </div>
              </div>
              <div className="p-1.5">
                {me?.platform_admin ? (
                  <button
                    onClick={() => {
                      const next = viewMode === "admin" ? "user" : "admin";
                      setViewMode(next);
                      navigate(next === "admin" ? "/platform" : "/dashboard");
                      setMenuOpen(false);
                    }}
                    className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-[12.5px] text-ink-200 hover:bg-ink-800"
                    role="menuitem"
                  >
                    {viewMode === "admin" ? <Eye className="h-3.5 w-3.5" /> : <Crown className="h-3.5 w-3.5" />}
                    {viewMode === "admin" ? "View as user (read-only)" : "Switch to Admin view"}
                  </button>
                ) : null}
                <Link to="/settings" className="flex items-center gap-2 rounded-md px-2.5 py-2 text-[12.5px] text-ink-200 hover:bg-ink-800" onClick={() => setMenuOpen(false)} role="menuitem">
                  <Settings className="h-3.5 w-3.5" /> Account settings
                </Link>
                <button
                  className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-[12.5px] text-red-700 hover:bg-red-500/10"
                  onClick={() => logout.mutate()}
                  role="menuitem"
                  disabled={logout.isPending}
                >
                  <LogOut className="h-3.5 w-3.5" /> {logout.isPending ? "Signing out…" : "Sign out"}
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
}

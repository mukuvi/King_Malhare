import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Bell, ChevronDown, LogOut, Menu, Plus, Search, Settings } from "lucide-react";
import { useMe, useLogout, useNotifications } from "@/hooks/queries";
import { useUIStore } from "@/stores/ui";
import { initials } from "@/lib/utils";
import { buttonStyles } from "@/components/ui";
import { Logo } from "./Logo";

export function Topbar() {
  const { toggleSidebar } = useUIStore();
  const { data: me } = useMe();
  const canScan = Boolean(me?.permissions.includes("scans:write"));
  const { data: notifications } = useNotifications();
  const logout = useLogout();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "/" && document.activeElement?.tagName !== "INPUT" && document.activeElement?.tagName !== "TEXTAREA") {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    const onClick = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) setMenuOpen(false);
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("mousedown", onClick);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousedown", onClick);
    };
  }, []);

  return (
    <header className="surface-blur sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-ink-700/80 px-4 sm:px-6">
      <button className="-ml-1 rounded-lg p-1.5 text-ink-300 hover:bg-ink-800 hover:text-ink-100 lg:hidden" onClick={toggleSidebar} aria-label="Open menu">
        <Menu className="h-5 w-5" />
      </button>
      <Link to="/dashboard" className="lg:hidden" aria-label="King Malhare dashboard">
        <Logo compact />
      </Link>

      <form
        className="relative hidden max-w-md flex-1 md:block"
        onSubmit={(event) => {
          event.preventDefault();
          if (query.trim()) navigate(`/findings?search=${encodeURIComponent(query.trim())}`);
        }}
      >
        <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
        <input
          ref={searchRef}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search findings, assets, CVEs"
          className="h-9 w-full rounded-xl border border-ink-700 bg-ink-850/90 pl-9 pr-12 text-[12.5px] text-ink-100 placeholder:text-ink-400 transition-all hover:border-ink-500 focus:border-amber-500/60 focus:outline-none focus:ring-2 focus:ring-amber-500/15"
          aria-label="Search findings, assets and CVEs"
        />
        <span className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-ink-600 bg-ink-800 px-1.5 py-0.5 font-mono text-[9px] text-ink-400">/</span>
      </form>

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

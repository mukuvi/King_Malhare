import { NavLink, useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  Bell,
  BookOpenCheck,
  Boxes,
  Cloud,
  Code2,
  FileText,
  Globe2,
  KeyRound,
  LayoutDashboard,
  Network,
  Plug,
  Radar,
  ScrollText,
  Settings,
  ShieldAlert,
  Users,
  X,
} from "lucide-react";
import { useEffect } from "react";
import { cn, initials } from "@/lib/utils";
import { useUIStore } from "@/stores/ui";
import { useMe, useNotifications, useOrganization } from "@/hooks/queries";
import { Logo } from "./Logo";

const groups = [
  {
    label: "Workspace",
    items: [
      { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
      { to: "/assets", label: "Assets", icon: Boxes },
      { to: "/scans", label: "Scan center", icon: Radar },
    ],
  },
  {
    label: "Assessments",
    items: [
      { to: "/web-security", label: "Web security", icon: Globe2 },
      { to: "/network-security", label: "Network security", icon: Network },
      { to: "/cloud-security", label: "Cloud security", icon: Cloud },
      { to: "/auth-testing", label: "Authentication", icon: KeyRound },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { to: "/findings", label: "Findings", icon: ShieldAlert },
      { to: "/intel", label: "Vulnerability intel", icon: BookOpenCheck },
    ],
  },
  {
    label: "Outputs",
    items: [
      { to: "/reports", label: "Reports", icon: FileText },
      { to: "/notifications", label: "Notifications", icon: Bell },
    ],
  },
  {
    label: "Operations",
    items: [
      { to: "/integrations", label: "Integrations", icon: Plug },
      { to: "/audit", label: "Audit log", icon: ScrollText },
      { to: "/api-docs", label: "API", icon: Code2 },
      { to: "/organization", label: "Organization", icon: Users },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export function Sidebar() {
  const { sidebarOpen, setSidebarOpen } = useUIStore();
  const { data: me } = useMe();
  const { data: org } = useOrganization();
  const { data: notifications } = useNotifications();
  const location = useLocation();

  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname, setSidebarOpen]);

  const content = (
    <div className="flex h-full flex-col">
      <div className="flex h-16 shrink-0 items-center justify-between border-b border-ink-700/80 px-4">
        <NavLink to="/dashboard" aria-label="King Malhare dashboard">
          <Logo />
        </NavLink>
        <button className="rounded-lg p-1.5 text-ink-400 hover:bg-ink-800 hover:text-ink-100 lg:hidden" onClick={() => setSidebarOpen(false)} aria-label="Close menu">
          <X className="h-4 w-4" />
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto px-2.5 py-4">
        {groups.map((group) => (
          <div key={group.label} className="mb-5">
            <div className="px-2.5 pb-1.5 text-[9.5px] font-semibold uppercase tracking-[0.17em] text-ink-400">{group.label}</div>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      cn(
                        "group relative flex items-center gap-2.5 rounded-xl px-2.5 py-[7px] text-[12.5px] transition-colors",
                        isActive ? "font-medium text-ink-50" : "text-ink-300 hover:bg-ink-800/70 hover:text-ink-100",
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive ? (
                          <motion.span
                            layoutId="sidebar-active"
                            className="absolute inset-0 rounded-xl bg-ink-750 shadow-[0_1px_0_rgba(255,255,255,0.7)_inset]"
                            transition={{ type: "spring", stiffness: 380, damping: 32 }}
                          />
                        ) : null}
                        <Icon className={cn("relative z-10 h-[15px] w-[15px] shrink-0", isActive ? "text-amber-700" : "text-ink-400 group-hover:text-teal-700")} strokeWidth={1.8} />
                        <span className="relative z-10 flex-1">{item.label}</span>
                        {item.to === "/notifications" && notifications?.unread ? (
                          <span className="relative z-10 rounded-full bg-amber-400 px-1.5 py-0.5 text-[9px] font-bold leading-none text-ink-50">{notifications.unread}</span>
                        ) : null}
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="shrink-0 border-t border-ink-700/80 p-3">
        <NavLink to="/settings" className="flex items-center gap-2.5 rounded-xl border border-ink-700 bg-ink-850/70 p-2.5 transition-all hover:border-ink-500 hover:bg-ink-800">
          <div className="flex h-7 w-7 items-center justify-center rounded-full text-[10px] font-semibold text-ink-50" style={{ backgroundColor: me?.user.avatar_color ?? "#D98B8B" }}>
            {initials(me?.user.name)}
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate text-[11.5px] font-medium text-ink-100">{me?.user.name ?? "Loading"}</div>
            <div className="truncate text-[10px] text-ink-400">{org?.name ?? ""}</div>
          </div>
          <span className="rounded-md border border-ink-600 bg-ink-900/60 px-1.5 py-0.5 text-[8px] uppercase tracking-wider text-ink-400">{me?.role}</span>
        </NavLink>
      </div>
    </div>
  );

  return (
    <>
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[248px] border-r border-ink-700/80 bg-ink-900/80 backdrop-blur-xl lg:block">{content}</aside>
      <AnimatePresence>
        {sidebarOpen ? (
          <div className="fixed inset-0 z-50 lg:hidden">
            <motion.div className="absolute inset-0 bg-ink-50/35 backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSidebarOpen(false)} />
            <motion.aside
              className="relative h-full w-[280px] border-r border-ink-700 bg-ink-900 shadow-lift"
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: "spring", stiffness: 340, damping: 34 }}
            >
              {content}
            </motion.aside>
          </div>
        ) : null}
      </AnimatePresence>
    </>
  );
}

export function SidebarEmergencyBanner({ active }: { active: boolean }) {
  if (!active) return null;
  return (
    <div className="flex items-center gap-2 border-b border-red-500/25 bg-red-500/10 px-4 py-2 text-[11.5px] text-red-700">
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-red-500" />
      Emergency stop is active. New assessments are blocked.
    </div>
  );
}

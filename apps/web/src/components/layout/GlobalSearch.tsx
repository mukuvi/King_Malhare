import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Bell,
  BookOpenCheck,
  Boxes,
  Building2,
  Cloud,
  Code2,
  Crown,
  FileText,
  Globe2,
  KeyRound,
  LayoutDashboard,
  Loader2,
  Network,
  Plus,
  Plug,
  Radar,
  ScrollText,
  Search,
  Settings,
  ShieldAlert,
  Users,
  type LucideIcon,
} from "lucide-react";
import { api, queryString } from "@/lib/api";
import { useMe } from "@/hooks/queries";
import { useUIStore } from "@/stores/ui";
import { cn } from "@/lib/utils";
import type { Asset, Finding, PlatformOrganization, PlatformUser, Report } from "@/types";

type PageEntry = {
  label: string;
  to: string;
  keywords: string;
  icon: LucideIcon;
  platformOnly?: boolean;
};

const pages: PageEntry[] = [
  { label: "Overview", to: "/dashboard", keywords: "dashboard home overview posture statistics", icon: LayoutDashboard },
  { label: "Assets", to: "/assets", keywords: "assets inventory targets websites servers ip network", icon: Boxes },
  { label: "Scan center", to: "/scans", keywords: "scans assessments queue history running", icon: Radar },
  { label: "New assessment", to: "/scans/new", keywords: "scan new start assessment run", icon: Plus },
  { label: "Web security", to: "/web-security", keywords: "web security http owasp web app", icon: Globe2 },
  { label: "Network security", to: "/network-security", keywords: "network nmap ports services", icon: Network },
  { label: "Cloud security", to: "/cloud-security", keywords: "cloud aws azure gcp contabo posture", icon: Cloud },
  { label: "Authentication", to: "/auth-testing", keywords: "authentication auth login testing password", icon: KeyRound },
  { label: "Findings", to: "/findings", keywords: "findings vulnerabilities issues triage", icon: ShieldAlert },
  { label: "Vulnerability intel", to: "/intel", keywords: "cve cwe intelligence vulnerability lookup", icon: BookOpenCheck },
  { label: "Reports", to: "/reports", keywords: "reports pdf html export download", icon: FileText },
  { label: "Notifications", to: "/notifications", keywords: "notifications inbox alerts events", icon: Bell },
  { label: "Integrations", to: "/integrations", keywords: "integrations cloud connections api keys schedules scanners", icon: Plug },
  { label: "Audit log", to: "/audit", keywords: "audit log events activity history", icon: ScrollText },
  { label: "API reference", to: "/api-docs", keywords: "api docs openapi reference endpoints developers", icon: Code2 },
  { label: "Organization", to: "/organization", keywords: "organization members team invites roles workspace", icon: Users },
  { label: "Settings", to: "/settings", keywords: "settings account profile password name", icon: Settings },
  { label: "Platform control", to: "/platform", keywords: "platform super admin deployment", icon: Crown, platformOnly: true },
  { label: "Platform organizations", to: "/platform?tab=organizations", keywords: "platform organizations workspaces tenants super admin", icon: Building2, platformOnly: true },
  { label: "Platform users", to: "/platform?tab=users", keywords: "platform users accounts people super admin", icon: Users, platformOnly: true },
];

type Result = {
  id: string;
  group: string;
  label: string;
  sublabel?: string;
  to: string;
  icon: LucideIcon;
};

const CVE_PATTERN = /^CVE-\d{4}-\d{4,7}$/i;

function matches(haystack: string, term: string) {
  const hay = haystack.toLowerCase();
  return term
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((part) => {
      if (hay.includes(part)) return true;
      if (part.length > 3 && part.endsWith("s") && hay.includes(part.slice(0, -1))) return true;
      if (part.length > 3 && hay.includes(`${part}s`)) return true;
      return false;
    });
}

function useDebounced(value: string, delay: number) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

export function GlobalSearch() {
  const navigate = useNavigate();
  const { data: me } = useMe();
  const platformAdmin = Boolean(me?.platform_admin);
  const viewMode = useUIStore((state) => state.viewMode);
  const adminMode = Boolean(platformAdmin && viewMode === "admin");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const term = useDebounced(query.trim(), 180);
  const enabled = open && term.length >= 2;

  const assets = useQuery({
    queryKey: ["global-search", "assets", term],
    queryFn: () => api.get<{ items: Asset[] }>(`/assets${queryString({ search: term, per_page: 4 })}`),
    enabled: enabled && !adminMode,
    staleTime: 15_000,
  });
  const findings = useQuery({
    queryKey: ["global-search", "findings", term],
    queryFn: () => api.get<{ items: Finding[] }>(`/findings${queryString({ search: term, per_page: 4 })}`),
    enabled: enabled && !adminMode,
    staleTime: 15_000,
  });
  const reports = useQuery({
    queryKey: ["global-search", "reports", term],
    queryFn: () => api.get<{ items: Report[] }>(`/reports${queryString({ search: term, per_page: 3 })}`),
    enabled: enabled && !adminMode,
    staleTime: 15_000,
  });
  const platformOrganizations = useQuery({
    queryKey: ["global-search", "platform-organizations"],
    queryFn: () => api.get<{ items: PlatformOrganization[] }>("/platform/organizations"),
    enabled: enabled && adminMode,
    staleTime: 60_000,
  });
  const platformUsers = useQuery({
    queryKey: ["global-search", "platform-users"],
    queryFn: () => api.get<{ items: PlatformUser[] }>("/platform/users"),
    enabled: enabled && adminMode,
    staleTime: 60_000,
  });

  const results = useMemo<Result[]>(() => {
    const out: Result[] = [];
    const trimmed = term.trim();
    const pageMatches = pages
      .filter((page) => adminMode ? page.platformOnly : !page.platformOnly)
      .filter((page) => !trimmed || matches(`${page.label} ${page.keywords}`, trimmed))
      .sort((a, b) => {
        if (!trimmed) return 0;
        const aStarts = a.label.toLowerCase().startsWith(trimmed.toLowerCase()) ? 0 : 1;
        const bStarts = b.label.toLowerCase().startsWith(trimmed.toLowerCase()) ? 0 : 1;
        return aStarts - bStarts;
      })
      .slice(0, trimmed ? 6 : 7);
    for (const page of pageMatches) {
      out.push({ id: `page-${page.to}`, group: "Go to", label: page.label, to: page.to, icon: page.icon });
    }
    if (!trimmed) return out;

    if (!adminMode && CVE_PATTERN.test(trimmed)) {
      out.push({
        id: "cve-lookup",
        group: "Intelligence",
        label: `Look up ${trimmed.toUpperCase()}`,
        sublabel: "Open the CVE record",
        to: `/intel?cve=${encodeURIComponent(trimmed.toUpperCase())}`,
        icon: BookOpenCheck,
      });
    }
    if (!adminMode) {
      for (const asset of assets.data?.items ?? []) {
        out.push({
          id: `asset-${asset.id}`,
          group: "Assets",
          label: asset.name,
          sublabel: `${asset.type.replace(/_/g, " ")} - ${asset.target}`,
          to: `/assets/${asset.id}`,
          icon: Boxes,
        });
      }
      for (const finding of findings.data?.items ?? []) {
        out.push({
          id: `finding-${finding.id}`,
          group: "Findings",
          label: finding.title,
          sublabel: `${finding.severity} - ${finding.asset_name}`,
          to: `/findings/${finding.id}`,
          icon: ShieldAlert,
        });
      }
      for (const report of reports.data?.items ?? []) {
        out.push({
          id: `report-${report.id}`,
          group: "Reports",
          label: report.title,
          sublabel: `${report.status}${report.client_name ? ` - ${report.client_name}` : ""}`,
          to: `/reports/${report.id}`,
          icon: FileText,
        });
      }
    }
    if (adminMode) {
      for (const org of (platformOrganizations.data?.items ?? []).filter((item) => matches(`${item.name} ${item.slug} ${item.owner_name} ${item.owner_email}`, trimmed)).slice(0, 3)) {
        out.push({
          id: `platform-org-${org.id}`,
          group: "Organizations",
          label: org.name,
          sublabel: `${org.member_count} members - ${org.owner_email || "no owner"}`,
          to: `/platform?org=${org.id}`,
          icon: Building2,
        });
      }
      for (const user of (platformUsers.data?.items ?? []).filter((item) => matches(`${item.name} ${item.email} ${item.memberships.map((m) => m.org_name).join(" ")}`, trimmed)).slice(0, 3)) {
        out.push({
          id: `platform-user-${user.id}`,
          group: "Users",
          label: user.name,
          sublabel: `${user.email}${user.is_platform_admin ? " - platform admin" : ""}`,
          to: `/platform?tab=users`,
          icon: Users,
        });
      }
    }
    return out;
  }, [term, adminMode, assets.data, findings.data, reports.data, platformOrganizations.data, platformUsers.data]);

  useEffect(() => {
    setActive(0);
  }, [term, open]);

  useEffect(() => {
    const onPointerDown = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing = target?.tagName === "INPUT" || target?.tagName === "TEXTAREA" || target?.isContentEditable;
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen(true);
        inputRef.current?.focus();
        return;
      }
      if (event.key === "/" && !typing) {
        event.preventDefault();
        setOpen(true);
        inputRef.current?.focus();
      }
    };
    window.addEventListener("mousedown", onPointerDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onPointerDown);
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  const select = (result?: Result) => {
    if (result) {
      navigate(result.to);
    } else if (query.trim()) {
      navigate(`/findings?search=${encodeURIComponent(query.trim())}`);
    } else {
      return;
    }
    setOpen(false);
    setQuery("");
    inputRef.current?.blur();
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setOpen(true);
      setActive((value) => Math.min(value + 1, Math.max(results.length - 1, 0)));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((value) => Math.max(value - 1, 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      select(results[active]);
    } else if (event.key === "Escape") {
      setOpen(false);
      inputRef.current?.blur();
    }
  };

  const loading = enabled && (assets.isFetching || findings.isFetching || reports.isFetching);
  let lastGroup = "";

  return (
    <div ref={containerRef} className="relative hidden max-w-md flex-1 md:block">
      <form onSubmit={(event) => { event.preventDefault(); select(results[active]); }}>
        <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
        <input
          ref={inputRef}
          value={query}
          onChange={(event) => { setQuery(event.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onKeyDown={onKeyDown}
          placeholder={adminMode ? "Search platform organizations and users" : "Search anything: assets, findings, pages, APIs"}
          className="h-9 w-full rounded-xl border border-ink-700 bg-ink-850/90 pl-9 pr-16 text-[12.5px] text-ink-100 placeholder:text-ink-400 transition-all hover:border-ink-500 focus:border-amber-500/60 focus:outline-none focus:ring-2 focus:ring-amber-500/15"
          role="combobox"
          aria-expanded={open}
          aria-controls="global-search-results"
          aria-autocomplete="list"
          aria-label="Search pages, assets, findings, reports and users"
        />
        <span className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-ink-600 bg-ink-800 px-1.5 py-0.5 font-mono text-[9px] text-ink-400">Ctrl K</span>
      </form>

      {open ? (
        <div id="global-search-results" role="listbox" className="absolute left-0 right-0 top-11 z-50 max-h-[70vh] overflow-y-auto rounded-xl border border-ink-600 bg-ink-850 shadow-lift">
          <div className="flex items-center justify-between border-b border-ink-700 px-3 py-2 text-[9.5px] uppercase tracking-[0.12em] text-ink-400">
            <span>{query.trim() ? "Results" : "Quick links"}</span>
            {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <span>Enter to open</span>}
          </div>
          {results.length === 0 ? (
            <div className="px-4 py-6 text-center">
              <p className="text-[12px] text-ink-200">No matches for "{query.trim()}"</p>
              <p className="mt-1 text-[10.5px] text-ink-400">Try an asset name, finding title, report, CVE or page name.</p>
            </div>
          ) : (
            <div className="py-1">
              {results.map((result, index) => {
                const Icon = result.icon;
                const showGroup = result.group !== lastGroup;
                lastGroup = result.group;
                return (
                  <div key={result.id}>
                    {showGroup ? <div className="px-3 pb-1 pt-2 text-[9px] font-semibold uppercase tracking-[0.14em] text-ink-400">{result.group}</div> : null}
                    <button
                      type="button"
                      role="option"
                      aria-selected={index === active}
                      onMouseEnter={() => setActive(index)}
                      onClick={() => select(result)}
                      className={cn(
                        "flex w-full items-center gap-2.5 px-3 py-2 text-left transition-colors",
                        index === active ? "bg-ink-800" : "hover:bg-ink-800/60",
                      )}
                    >
                      <span className={cn("flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border", index === active ? "border-amber-500/30 bg-amber-500/10 text-amber-700" : "border-ink-700 bg-ink-900 text-ink-400")}>
                        <Icon className="h-3.5 w-3.5" />
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[12px] font-medium text-ink-100">{result.label}</span>
                        {result.sublabel ? <span className="mt-0.5 block truncate text-[10px] text-ink-400">{result.sublabel}</span> : null}
                      </span>
                      {index === active ? <ArrowUpRight className="h-3.5 w-3.5 shrink-0 text-ink-400" /> : null}
                    </button>
                  </div>
                );
              })}
            </div>
          )}
          <div className="border-t border-ink-700 px-3 py-2 text-[9.5px] text-ink-400">
            Arrow keys to move, Enter to open, Esc to close
          </div>
        </div>
      ) : null}
    </div>
  );
}

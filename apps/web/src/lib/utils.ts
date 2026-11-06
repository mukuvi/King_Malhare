import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { FindingStatus, ScanStatus, Severity } from "@/types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(value?: string, options?: Intl.DateTimeFormatOptions): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    ...options,
  }).format(date);
}

export function formatDateTime(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(date);
}

export function relativeTime(value?: string): string {
  if (!value) return "—";
  const date = new Date(value).getTime();
  if (Number.isNaN(date)) return "—";
  const diff = date - Date.now();
  const abs = Math.abs(diff);
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["year", 365 * 24 * 3600 * 1000],
    ["month", 30 * 24 * 3600 * 1000],
    ["week", 7 * 24 * 3600 * 1000],
    ["day", 24 * 3600 * 1000],
    ["hour", 3600 * 1000],
    ["minute", 60 * 1000],
    ["second", 1000],
  ];
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  for (const [unit, ms] of units) {
    if (abs >= ms || unit === "second") {
      return formatter.format(Math.round(diff / ms), unit);
    }
  }
  return "—";
}

export function initials(name?: string): string {
  if (!name) return "KM";
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}

export const severityLabel: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const severityStyles: Record<Severity, string> = {
  critical: "border-red-500/30 bg-red-500/10 text-red-300",
  high: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  medium: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  low: "border-lime-500/25 bg-lime-500/10 text-lime-300",
  info: "border-sky-500/25 bg-sky-500/10 text-sky-300",
};

export const severityHex: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f5b025",
  low: "#84cc16",
  info: "#64748b",
};

export const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function statusLabel(status: FindingStatus): string {
  const labels: Record<FindingStatus, string> = {
    open: "Open",
    confirmed: "Confirmed",
    in_progress: "In progress",
    fixed: "Fixed",
    retest_required: "Retest required",
    accepted_risk: "Accepted risk",
    false_positive: "False positive",
  };
  return labels[status];
}

export const scanStatusLabel: Record<ScanStatus, string> = {
  pending: "Pending",
  queued: "Queued",
  initializing: "Initializing",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function categoryLabel(category: string): string {
  const labels: Record<string, string> = {
    web: "Web application",
    network: "Network",
    cloud: "Cloud",
    authentication: "Authentication",
    infrastructure: "Infrastructure",
  };
  return labels[category] ?? category;
}

export function scannerLabel(name?: string): string {
  const labels: Record<string, string> = {
    "http-baseline": "HTTP baseline",
    nmap: "Nmap",
    nuclei: "Nuclei",
    zap: "OWASP ZAP",
    nikto: "Nikto",
    gobuster: "Gobuster",
    testssl: "testssl.sh",
    sqlmap: "SQLMap",
    trivy: "Trivy",
    prowler: "Prowler",
    scoutsuite: "ScoutSuite",
    checkov: "Checkov",
    "aws-posture": "AWS posture",
    "auth-baseline": "Auth baseline",
  };
  return name ? labels[name] ?? name : "—";
}

export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function formatPercent(value: number): string {
  return `${Math.round(value)}%`;
}

export function truncate(value: string, length: number): string {
  if (value.length <= length) return value;
  return `${value.slice(0, length).trimEnd()}…`;
}

export function riskTone(score: number): string {
  if (score >= 80) return "text-lime-300";
  if (score >= 60) return "text-amber-300";
  if (score >= 40) return "text-orange-300";
  return "text-red-300";
}

export function postureScoreLabel(score: number): string {
  if (score >= 80) return "Strong";
  if (score >= 60) return "Moderate";
  if (score >= 40) return "Elevated";
  return "Critical";
}

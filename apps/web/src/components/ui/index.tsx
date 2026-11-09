import {
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
  useEffect,
} from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, ChevronLeft, ChevronRight, Loader2, X } from "lucide-react";
import { cn, scanStatusLabel, severityLabel, severityStyles, statusLabel } from "@/lib/utils";
import type { FindingStatus, ScanStatus, Severity } from "@/types";
import { Link } from "react-router-dom";

/* -------------------------------------------------------------------------- */
/* Buttons                                                                    */
/* -------------------------------------------------------------------------- */

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "outline";
type ButtonSize = "sm" | "md" | "lg" | "icon";

export function buttonStyles(variant: ButtonVariant = "primary", size: ButtonSize = "md", className?: string) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-xl font-medium transition-all duration-150 disabled:pointer-events-none disabled:opacity-45 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/50 focus-visible:ring-offset-2 focus-visible:ring-offset-ink-950";
  const variants: Record<ButtonVariant, string> = {
    primary: "bg-amber-300 text-ink-50 shadow-soft hover:bg-amber-200 active:bg-amber-400",
    secondary: "border border-ink-600 bg-ink-850 text-ink-100 hover:border-ink-500 hover:bg-ink-800",
    ghost: "text-ink-300 hover:bg-ink-800 hover:text-ink-50",
    danger: "border border-red-500/25 bg-red-500/10 text-red-700 hover:bg-red-500/15",
    outline: "border border-amber-500/50 text-amber-700 hover:bg-amber-500/10",
  };
  const sizes: Record<ButtonSize, string> = {
    sm: "h-8 px-2.5 text-[12px]",
    md: "h-9 px-3.5 text-[13px]",
    lg: "h-11 px-5 text-[14px]",
    icon: "h-9 w-9",
  };
  return cn(base, variants[variant], sizes[size], className);
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

export function Button({ variant = "primary", size = "md", loading, className, children, disabled, ...props }: ButtonProps) {
  return (
    <button className={buttonStyles(variant, size, className)} disabled={disabled || loading} {...props}>
      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
      {children}
    </button>
  );
}

/* -------------------------------------------------------------------------- */
/* Panels and typography                                                      */
/* -------------------------------------------------------------------------- */

export function Card({ className, children, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("panel", className)} {...props}>
      {children}
    </div>
  );
}

export function CardHeader({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("flex items-start justify-between gap-4 border-b border-ink-700/70 px-5 py-4", className)}>{children}</div>;
}

export function CardTitle({ children, subtitle }: { children: ReactNode; subtitle?: string }) {
  return (
    <div>
      <h3 className="text-[13.5px] font-semibold tracking-[-0.01em] text-ink-50">{children}</h3>
      {subtitle ? <p className="mt-0.5 text-[12px] text-ink-300">{subtitle}</p> : null}
    </div>
  );
}

export function CardContent({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("px-5 py-4", className)}>{children}</div>;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  className,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between", className)}>
      <div className="min-w-0">
        {eyebrow ? <div className="eyebrow mb-2">{eyebrow}</div> : null}
        <h1 className="text-[26px] font-semibold leading-tight tracking-[-0.03em] text-ink-50 sm:text-[30px]">{title}</h1>
        {description ? <p className="mt-2 max-w-2xl text-[13.5px] text-ink-300">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Badges                                                                     */
/* -------------------------------------------------------------------------- */

export function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-800 px-2 py-0.5 text-[10.5px] font-medium tracking-wide text-ink-200", className)}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em]", severityStyles[severity], className)}>
      {severityLabel[severity]}
    </span>
  );
}

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const tone: Record<ScanStatus, string> = {
    pending: "border-ink-500 bg-ink-800 text-ink-300",
    queued: "border-sky-500/25 bg-sky-500/10 text-sky-700",
    initializing: "border-sky-500/25 bg-sky-500/10 text-sky-700",
    running: "border-amber-500/30 bg-amber-500/10 text-amber-700",
    completed: "border-lime-600/25 bg-lime-500/10 text-lime-700",
    failed: "border-red-500/30 bg-red-500/10 text-red-700",
    cancelled: "border-ink-500 bg-ink-800 text-ink-300",
  };
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em]", tone[status])}>
      <span className={cn("h-1.5 w-1.5 rounded-full", status === "running" && "animate-pulse bg-amber-500", status === "queued" && "bg-sky-500", status === "completed" && "bg-lime-500", status === "failed" && "bg-red-500", status === "cancelled" && "bg-ink-400", status === "initializing" && "bg-sky-500")} />
      {scanStatusLabel[status]}
    </span>
  );
}

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  const tone: Record<FindingStatus, string> = {
    open: "border-red-500/25 bg-red-500/10 text-red-700",
    confirmed: "border-orange-500/25 bg-orange-500/10 text-orange-700",
    in_progress: "border-amber-500/25 bg-amber-500/10 text-amber-700",
    fixed: "border-lime-600/25 bg-lime-500/10 text-lime-700",
    retest_required: "border-sky-500/25 bg-sky-500/10 text-sky-700",
    accepted_risk: "border-ink-500 bg-ink-800 text-ink-300",
    false_positive: "border-ink-500 bg-ink-800 text-ink-300",
  };
  return <span className={cn("inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium", tone[status])}>{statusLabel(status)}</span>;
}

/* -------------------------------------------------------------------------- */
/* Forms                                                                      */
/* -------------------------------------------------------------------------- */

export function Label({ children, htmlFor, hint }: { children: ReactNode; htmlFor?: string; hint?: string }) {
  return (
    <label htmlFor={htmlFor} className="mb-1.5 flex items-baseline justify-between gap-3">
      <span className="text-[12px] font-medium text-ink-200">{children}</span>
      {hint ? <span className="text-[11px] text-ink-400">{hint}</span> : null}
    </label>
  );
}

export function Field({ label, hint, error, children, htmlFor }: { label: string; hint?: string; error?: string; children: ReactNode; htmlFor?: string }) {
  return (
    <div>
      <Label htmlFor={htmlFor} hint={hint}>{label}</Label>
      {children}
      {error ? <p className="mt-1.5 text-[11.5px] text-red-700">{error}</p> : null}
    </div>
  );
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn("input-base", className)} {...props} />;
}

export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn("input-base h-auto min-h-[92px] resize-y py-2.5 leading-relaxed", className)} {...props} />;
}

export function Select({ className, children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn("input-base appearance-none bg-[length:14px] bg-[right_10px_center] bg-no-repeat pr-8", className)} style={{ backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%238C8477' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E\")" }} {...props}>
      {children}
    </select>
  );
}

/* -------------------------------------------------------------------------- */
/* Overlays                                                                   */
/* -------------------------------------------------------------------------- */

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  width = "max-w-xl",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previous;
    };
  }, [open, onClose]);

  return createPortal(
    <AnimatePresence>
      {open ? (
        <div className="fixed inset-0 z-[70] flex items-end justify-center p-0 sm:items-center sm:p-6">
          <motion.div className="absolute inset-0 bg-ink-50/35 backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label={title}
            className={cn("relative z-10 flex max-h-[92vh] w-full flex-col overflow-hidden rounded-t-2xl border border-ink-600 bg-ink-850 shadow-lift sm:rounded-xl", width)}
            initial={{ opacity: 0, y: 24, scale: 0.985 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.99 }}
            transition={{ type: "spring", stiffness: 360, damping: 32 }}
          >
            <div className="flex items-start justify-between gap-4 border-b border-ink-700 px-5 py-4">
              <div>
                <h2 className="text-[15px] font-semibold text-ink-50">{title}</h2>
                {description ? <p className="mt-1 text-[12.5px] text-ink-300">{description}</p> : null}
              </div>
              <button onClick={onClose} className="rounded-md p-1.5 text-ink-400 transition-colors hover:bg-ink-800 hover:text-ink-100" aria-label="Close dialog">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
            {footer ? <div className="flex items-center justify-end gap-2 border-t border-ink-700 bg-ink-900/50 px-5 py-3.5">{footer}</div> : null}
          </motion.div>
        </div>
      ) : null}
    </AnimatePresence>,
    document.body,
  );
}

export function Drawer({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  width = "max-w-2xl",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previous;
    };
  }, [open, onClose]);

  return createPortal(
    <AnimatePresence>
      {open ? (
        <div className="fixed inset-0 z-[70] flex justify-end">
          <motion.div className="absolute inset-0 bg-ink-50/30 backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
          <motion.aside
            role="dialog"
            aria-modal="true"
            aria-label={title}
            className={cn("relative z-10 flex h-full w-full flex-col border-l border-ink-600 bg-ink-850 shadow-lift", width)}
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", stiffness: 320, damping: 34 }}
          >
            <div className="flex items-start justify-between gap-4 border-b border-ink-700 px-5 py-4">
              <div>
                <h2 className="text-[15px] font-semibold text-ink-50">{title}</h2>
                {description ? <p className="mt-1 text-[12.5px] text-ink-300">{description}</p> : null}
              </div>
              <button onClick={onClose} className="rounded-md p-1.5 text-ink-400 transition-colors hover:bg-ink-800 hover:text-ink-100" aria-label="Close panel">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
            {footer ? <div className="flex items-center justify-end gap-2 border-t border-ink-700 bg-ink-900/50 px-5 py-3.5">{footer}</div> : null}
          </motion.aside>
        </div>
      ) : null}
    </AnimatePresence>,
    document.body,
  );
}

/* -------------------------------------------------------------------------- */
/* Feedback                                                                   */
/* -------------------------------------------------------------------------- */

export function StatCard({
  label,
  value,
  hint,
  icon,
  tone = "default",
  to,
  loading,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  icon?: ReactNode;
  tone?: "default" | "warn" | "danger" | "good";
  to?: string;
  loading?: boolean;
}) {
  const tones = {
    default: "text-ink-50",
    warn: "text-amber-700",
    danger: "text-red-700",
    good: "text-lime-700",
  };
  const body = (
    <div className={cn("panel panel-hover flex h-full flex-col justify-between gap-4 p-4 sm:p-5", to && "cursor-pointer")}>
      <div className="flex items-start justify-between gap-3">
        <span className="text-[11.5px] font-medium text-ink-300">{label}</span>
        {icon ? <span className="text-ink-400">{icon}</span> : null}
      </div>
      {loading ? (
        <Skeleton className="h-8 w-16" />
      ) : (
        <div>
          <div className={cn("text-[27px] font-semibold leading-none tracking-[-0.04em]", tones[tone])}>{value}</div>
          {hint ? <div className="mt-2 text-[10.5px] leading-snug text-ink-400">{hint}</div> : null}
        </div>
      )}
    </div>
  );
  return to ? <Link to={to}>{body}</Link> : body;
}

export function Toggle({ checked, onChange, label, description }: { checked: boolean; onChange: (value: boolean) => void; label: string; description?: string }) {
  return (
    <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-ink-600 bg-ink-900/50 p-3 transition-colors hover:border-ink-500 hover:bg-ink-850">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`mt-0.5 h-4 w-7 shrink-0 rounded-full border transition-colors ${checked ? "border-amber-500 bg-amber-300" : "border-ink-500 bg-ink-700"}`}
      >
        <span className={`block h-3 w-3 rounded-full bg-ink-850 shadow-sm transition-transform ${checked ? "translate-x-3.5" : "translate-x-0.5"}`} />
      </button>
      <span>
        <span className="block text-[12px] font-medium text-ink-100">{label}</span>
        {description ? <span className="mt-0.5 block text-[11px] leading-relaxed text-ink-400">{description}</span> : null}
      </span>
    </label>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("skeleton", className)} />;
}

export function SkeletonTable({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className="divide-y divide-ink-700/70">
      {Array.from({ length: rows }).map((_, row) => (
        <div key={row} className="flex items-center gap-4 px-4 py-3.5">
          {Array.from({ length: columns }).map((_, column) => (
            <Skeleton key={column} className={cn("h-3.5", column === 0 ? "w-1/3" : "flex-1")} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-16 text-center", className)}>
      <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-2xl border border-ink-600 bg-ink-800 text-teal-700">{icon}</div>
      <h3 className="text-[14px] font-semibold text-ink-50">{title}</h3>
      <p className="mt-1.5 max-w-sm text-[12.5px] leading-relaxed text-ink-300">{description}</p>
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}

export function QueryState({
  loading,
  error,
  onRetry,
  children,
  skeleton,
}: {
  loading: boolean;
  error: unknown;
  onRetry?: () => void;
  children: ReactNode;
  skeleton?: ReactNode;
}) {
  if (loading) return <>{skeleton ?? <SkeletonTable />}</>;
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
        <AlertTriangle className="mb-3 h-5 w-5 text-red-600" />
        <p className="text-[13px] font-medium text-ink-100">Could not load this data</p>
        <p className="mt-1 max-w-md text-[12px] text-ink-400">{error instanceof Error ? error.message : "An unexpected error occurred."}</p>
        {onRetry ? (
          <Button variant="secondary" size="sm" className="mt-4" onClick={onRetry}>
            Try again
          </Button>
        ) : null}
      </div>
    );
  }
  return <>{children}</>;
}

export function Progress({ value, className, tone = "amber" }: { value: number; className?: string; tone?: "amber" | "lime" | "red" | "sky" }) {
  const colors = { amber: "bg-amber-400", lime: "bg-lime-500", red: "bg-red-500", sky: "bg-sky-500" };
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-ink-700", className)}>
      <div className={cn("h-full rounded-full transition-[width] duration-500", colors[tone])} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Tabs and pagination                                                        */
/* -------------------------------------------------------------------------- */

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: Array<{ label: string; value: T; count?: number }>; value: T; onChange: (value: T) => void }) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-ink-700 no-scrollbar">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          onClick={() => onChange(tab.value)}
          className={cn(
            "relative whitespace-nowrap px-3 py-2.5 text-[12.5px] font-medium transition-colors",
            value === tab.value ? "text-ink-50" : "text-ink-400 hover:text-ink-200",
          )}
        >
          {tab.label}
          {typeof tab.count === "number" ? <span className="ml-1.5 rounded-md bg-ink-700 px-1.5 py-0.5 text-[10px] text-ink-300">{tab.count}</span> : null}
          {value === tab.value ? <motion.div layoutId="tab-underline" className="absolute inset-x-1 -bottom-px h-0.5 rounded-full bg-amber-500" /> : null}
        </button>
      ))}
    </div>
  );
}

export function Pagination({ page, perPage, total, onPage }: { page: number; perPage: number; total: number; onPage: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / perPage));
  if (total === 0) return null;
  const start = (page - 1) * perPage + 1;
  const end = Math.min(page * perPage, total);
  return (
    <div className="flex flex-col items-center justify-between gap-3 border-t border-ink-700 px-4 py-3 sm:flex-row">
      <p className="text-[11.5px] text-ink-400">
        Showing <span className="text-ink-200">{start}-{end}</span> of <span className="text-ink-200">{total}</span>
      </p>
      <div className="flex items-center gap-1.5">
        <Button variant="secondary" size="icon" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <span className="px-2 text-[11.5px] text-ink-300">
          {page} / {pages}
        </span>
        <Button variant="secondary" size="icon" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

export function TableShell({ children, footer }: { children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-850 shadow-card">
      <div className="overflow-x-auto">{children}</div>
      {footer}
    </div>
  );
}

export function PageTransition({ children }: { children: ReactNode }) {
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}>
      {children}
    </motion.div>
  );
}

import { cn } from "@/lib/utils";

export function Logo({ compact = false, className }: { compact?: boolean; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <div className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-[7px] border border-amber-500/40 bg-ink-950">
        <span className="font-mono text-[15px] font-bold text-amber-400">K</span>
        <span className="absolute -right-1 -top-1 h-1.5 w-1.5 rounded-full bg-ember-400" />
      </div>
      {!compact ? (
        <div className="leading-none">
          <div className="text-[13.5px] font-semibold tracking-[-0.01em] text-ink-50">King Malhare</div>
          <div className="mt-1 text-[8px] font-semibold uppercase tracking-[0.2em] text-ink-400">Offensive security</div>
        </div>
      ) : null}
    </div>
  );
}

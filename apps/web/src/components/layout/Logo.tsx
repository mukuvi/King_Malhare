import { cn } from "@/lib/utils";

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 48 48"
      role="img"
      aria-label="King Malhare"
      className={cn("h-8 w-8 shrink-0", className)}
    >
      <rect x="1.5" y="1.5" width="45" height="45" rx="14" fill="#FFFDF9" stroke="#1F1B16" strokeWidth="1.6" />
      <path
        d="M17.4 22.5C12.8 13.6 13.9 6.2 18.3 6.2c3.5 0 4.1 7.1 2.6 16.3"
        fill="#F3C0B8"
        stroke="#1F1B16"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M30.6 22.5c4.6-8.9 3.5-16.3-.9-16.3-3.5 0-4.1 7.1-2.6 16.3"
        fill="#F3C0B8"
        stroke="#1F1B16"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M24 14.8c6.7 0 10.8 4.8 10.8 11.6 0 7.4-4.7 12.5-10.8 12.5S13.2 33.8 13.2 26.4c0-6.8 4.1-11.6 10.8-11.6Z"
        fill="#FFFDF9"
        stroke="#1F1B16"
        strokeWidth="1.6"
      />
      <path
        d="M17.1 14.9 19.2 9.8l2.8 2.9L24 8.6l2 4.1 2.8-2.9 2.1 5.1Z"
        fill="#F9D878"
        stroke="#1F1B16"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
      <circle cx="20.4" cy="27" r="1.25" fill="#1F1B16" />
      <circle cx="27.6" cy="27" r="1.25" fill="#1F1B16" />
      <path d="M24 30.2 22.7 31.8h2.6Z" fill="#BF7370" stroke="#1F1B16" strokeWidth="0.8" strokeLinejoin="round" />
      <path d="M21.2 32.8c1.7 1.1 3.9 1.1 5.6 0" fill="none" stroke="#1F1B16" strokeWidth="1.1" strokeLinecap="round" />
      <circle cx="15.8" cy="30.4" r="1.9" fill="#9DDCBF" opacity="0.85" />
      <circle cx="32.2" cy="30.4" r="1.9" fill="#9DDCBF" opacity="0.85" />
    </svg>
  );
}

export function Logo({ compact = false, className }: { compact?: boolean; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <LogoMark />
      {!compact ? (
        <div className="leading-none">
          <div className="flex items-baseline gap-1 text-[14px] font-semibold tracking-[-0.02em] text-ink-50">
            King Malhare
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
          </div>
          <div className="mt-1 text-[8px] font-semibold uppercase tracking-[0.2em] text-teal-700">
            Offensive security
          </div>
        </div>
      ) : null}
    </div>
  );
}

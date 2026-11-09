import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid, Bar, BarChart, Legend } from "recharts";
import { severityHex, severityLabel, severityOrder } from "@/lib/utils";
import { Skeleton } from "@/components/ui";

export function PostureGauge({ score, size = 148 }: { score: number; size?: number }) {
  const radius = (size - 14) / 2;
  const circumference = Math.PI * radius;
  const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
  const color = score >= 80 ? "#4FAF85" : score >= 60 ? "#E3A92F" : score >= 40 ? "#E38456" : "#D96B6B";
  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size / 2 + 20 }}>
      <svg width={size} height={size / 2 + 14} viewBox={`0 0 ${size} ${size / 2 + 14}`} className="overflow-visible">
        <path
          d={`M 7 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 7} ${size / 2}`}
          fill="none"
          stroke="#EDE5D7"
          strokeWidth="9"
          strokeLinecap="round"
        />
        <path
          d={`M 7 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 7} ${size / 2}`}
          fill="none"
          stroke={color}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 700ms ease" }}
        />
      </svg>
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 text-center">
        <div className="text-[30px] font-semibold leading-none tracking-[-0.04em]" style={{ color }}>{score}</div>
        <div className="mt-1 text-[9px] uppercase tracking-[0.16em] text-ink-400">Posture</div>
      </div>
    </div>
  );
}

export function SeverityDonut({
  counts,
  total,
  loading,
}: {
  counts: Record<string, number>;
  total: number;
  loading?: boolean;
}) {
  if (loading) return <Skeleton className="mx-auto h-[190px] w-[190px] rounded-full" />;
  const data = severityOrder
    .map((severity) => ({ name: severityLabel[severity], key: severity, value: counts[severity] ?? 0 }))
    .filter((entry) => entry.value > 0);
  if (!data.length) {
    return (
      <div className="flex h-[190px] flex-col items-center justify-center gap-3">
        <div className="h-[130px] w-[130px] rounded-full border-[10px] border-ink-700" />
        <p className="text-[11px] text-ink-400">No open findings</p>
      </div>
    );
  }
  return (
    <div className="relative h-[190px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={58} outerRadius={82} paddingAngle={2} stroke="none">
            {data.map((entry) => (
              <Cell key={entry.key} fill={severityHex[entry.key as keyof typeof severityHex]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: "#FFFDF9", border: "1px solid #E7DED0", borderRadius: 10, fontSize: 12, boxShadow: "0 18px 40px -30px rgba(31,27,22,0.35)" }}
            itemStyle={{ color: "#2E2923" }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[24px] font-semibold leading-none text-ink-50">{total}</span>
        <span className="mt-1 text-[9px] uppercase tracking-[0.15em] text-ink-400">Open</span>
      </div>
    </div>
  );
}

export function TrendChart({ data, loading }: { data: Array<Record<string, string | number>>; loading?: boolean }) {
  if (loading) return <Skeleton className="h-[250px] w-full" />;
  if (!data.length) return <div className="flex h-[250px] items-center justify-center text-[12px] text-ink-400">No trend data yet</div>;
  return (
    <div className="h-[250px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} barCategoryGap="22%" margin={{ top: 8, right: 8, left: -22, bottom: 0 }}>
          <CartesianGrid strokeDasharray="2 4" vertical={false} stroke="#EDE5D7" />
          <XAxis
            dataKey="label"
            tick={{ fill: "#8C8477", fontSize: 10 }}
            tickLine={false}
            axisLine={{ stroke: "#E7DED0" }}
            interval="preserveStartEnd"
            minTickGap={30}
          />
          <YAxis tick={{ fill: "#8C8477", fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip
            cursor={{ fill: "rgba(232,168,162,0.12)" }}
            contentStyle={{ background: "#FFFDF9", border: "1px solid #E7DED0", borderRadius: 10, fontSize: 12, boxShadow: "0 18px 40px -30px rgba(31,27,22,0.35)" }}
            labelStyle={{ color: "#4C463D" }}
          />
          <Legend wrapperStyle={{ fontSize: 10, color: "#8C8477", paddingTop: 8 }} />
          {(["critical", "high", "medium", "low"] as const).map((severity) => (
            <Bar key={severity} dataKey={severity} stackId="findings" fill={severityHex[severity]} radius={severity === "low" ? [2, 2, 0, 0] : undefined} maxBarSize={18} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ScannerBars({ data }: { data: Array<{ label: string; value: number }> }) {
  if (!data.length) return <p className="py-8 text-center text-[12px] text-ink-400">No scan activity in this period.</p>;
  return (
    <div className="space-y-3">
      {data.map((item) => (
        <div key={item.label}>
          <div className="mb-1 flex items-center justify-between text-[11.5px]">
            <span className="text-ink-300">{item.label}</span>
            <span className="font-mono text-ink-200">{item.value}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-ink-700">
            <div className="h-full rounded-full bg-amber-400/80" style={{ width: `${Math.min(100, item.value * 12)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

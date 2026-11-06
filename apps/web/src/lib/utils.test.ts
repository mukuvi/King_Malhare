import { describe, expect, it } from "vitest";
import { formatBytes, formatPercent, postureScoreLabel, severityStyles, truncate } from "@/lib/utils";

describe("utility formatting", () => {
  it("formats byte sizes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });

  it("formats percentages safely", () => {
    expect(formatPercent(99.6)).toBe("100%");
    expect(formatPercent(0)).toBe("0%");
  });

  it("truncates without cutting too aggressively", () => {
    expect(truncate("hello world", 5)).toBe("hello…");
    expect(truncate("short", 20)).toBe("short");
  });

  it("maps every severity to a class", () => {
    for (const severity of ["critical", "high", "medium", "low", "info"] as const) {
      expect(severityStyles[severity]).toContain("border");
    }
  });

  it("labels posture bands", () => {
    expect(postureScoreLabel(90)).toBe("Strong");
    expect(postureScoreLabel(65)).toBe("Moderate");
    expect(postureScoreLabel(30)).toBe("Critical");
  });
});

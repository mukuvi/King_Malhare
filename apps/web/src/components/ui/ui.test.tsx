import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Button, EmptyState, FindingStatusBadge, ScanStatusBadge, SeverityBadge } from "@/components/ui";
import { ShieldAlert } from "lucide-react";

describe("design system primitives", () => {
  it("renders a busy button and disables interaction", () => {
    render(<Button loading>Saving</Button>);
    const button = screen.getByRole("button", { name: /saving/i });
    expect(button).toBeDisabled();
    expect(button.querySelector("svg")).toBeInTheDocument();
  });

  it("renders every severity with the correct label", () => {
    render(
      <div>
        <SeverityBadge severity="critical" />
        <SeverityBadge severity="high" />
        <SeverityBadge severity="medium" />
        <SeverityBadge severity="low" />
        <SeverityBadge severity="info" />
      </div>,
    );
    for (const label of ["Critical", "High", "Medium", "Low", "Info"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it("renders scan and finding states", () => {
    render(
      <div>
        <ScanStatusBadge status="running" />
        <FindingStatusBadge status="accepted_risk" />
      </div>,
    );
    expect(screen.getByText("Running")).toBeInTheDocument();
    expect(screen.getByText("Accepted risk")).toBeInTheDocument();
  });

  it("renders an actionable empty state", () => {
    render(
      <EmptyState
        icon={<ShieldAlert data-testid="empty-icon" />}
        title="No findings"
        description="Run an assessment."
        action={<Button>New scan</Button>}
      />,
    );
    expect(screen.getByText("No findings")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New scan" })).toBeInTheDocument();
    expect(screen.getByTestId("empty-icon")).toBeInTheDocument();
  });
});

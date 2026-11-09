import { Link } from "react-router-dom";
import { ArrowLeft, Radar } from "lucide-react";
import { Button, EmptyState } from "@/components/ui";

export function NotFoundPage() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <div className="w-full max-w-md rounded-xl border border-ink-650 bg-ink-850">
        <EmptyState
          icon={<Radar className="h-4 w-4" />}
          title="404 - route not found"
          description="This page does not exist in the King Malhare console. Check the address or return to the overview."
          action={<Link to="/dashboard"><Button><ArrowLeft className="h-3.5 w-3.5" /> Back to overview</Button></Link>}
        />
      </div>
    </div>
  );
}

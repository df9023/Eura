import { Badge } from "@/components/ui/badge";
import type { Verdict } from "@/types";
import { ShieldCheck, ShieldX } from "lucide-react";

interface VerdictBadgeProps {
  verdict: Verdict;
}

export function VerdictBadge({ verdict }: VerdictBadgeProps) {
  const allowed = verdict === "SHIP_ALLOWED";

  return (
    <Badge
      variant={allowed ? "success" : "destructive"}
      className="gap-1.5 px-4 py-2 text-base"
    >
      {allowed ? <ShieldCheck className="h-5 w-5" /> : <ShieldX className="h-5 w-5" />}
      {allowed ? "SHIP ALLOWED" : "SHIP BLOCKED"}
    </Badge>
  );
}

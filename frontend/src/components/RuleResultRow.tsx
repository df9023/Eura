import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import type { RuleResult } from "@/types";
import { ChevronDown, ChevronRight, CheckCircle2, XCircle, HelpCircle, MinusCircle } from "lucide-react";

interface RuleResultRowProps {
  rule: RuleResult;
}

const statusConfig = {
  PASS: { icon: CheckCircle2, color: "text-[var(--color-success)]", badge: "success" as const },
  FAIL: { icon: XCircle, color: "text-[var(--color-destructive)]", badge: "destructive" as const },
  UNKNOWN: { icon: HelpCircle, color: "text-[var(--color-warning)]", badge: "warning" as const },
  NOT_APPLICABLE: { icon: MinusCircle, color: "text-[var(--color-muted-foreground)]", badge: "muted" as const },
};

const severityBadge = {
  CRITICAL: "destructive" as const,
  HIGH: "destructive" as const,
  MEDIUM: "warning" as const,
  LOW: "outline" as const,
  INFO: "muted" as const,
};

export function RuleResultRow({ rule }: RuleResultRowProps) {
  const [open, setOpen] = useState(false);
  const cfg = statusConfig[rule.status];
  const Icon = cfg.icon;

  return (
    <div className="border-b last:border-b-0">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-[var(--color-muted)] transition-colors"
        aria-expanded={open}
      >
        {open ? <ChevronDown className="h-4 w-4 shrink-0" /> : <ChevronRight className="h-4 w-4 shrink-0" />}
        <Icon className={`h-5 w-5 shrink-0 ${cfg.color}`} aria-label={rule.status} />
        <span className="font-mono text-sm text-[var(--color-muted-foreground)] w-32 shrink-0">{rule.rule_id}</span>
        <span className="flex-1 text-sm font-medium truncate">{rule.title}</span>
        <Badge variant={severityBadge[rule.severity.overall]}>{rule.severity.overall}</Badge>
      </button>

      {open && rule.evidence.length > 0 && (
        <div className="bg-[var(--color-muted)] px-12 py-3 text-sm">
          <p className="font-semibold mb-1">Evidence</p>
          <ul className="list-disc list-inside space-y-0.5 text-[var(--color-muted-foreground)]">
            {rule.evidence.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

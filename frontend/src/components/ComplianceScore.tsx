import { cn } from "@/lib/utils";

interface ComplianceScoreProps {
  score: number;
  label?: string;
  size?: "sm" | "lg";
}

export function ComplianceScore({ score, label = "CRA Score", size = "lg" }: ComplianceScoreProps) {
  const radius = size === "lg" ? 54 : 36;
  const stroke = size === "lg" ? 8 : 6;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const dim = (radius + stroke) * 2;

  const color =
    score >= 80 ? "var(--color-success)" : score >= 50 ? "var(--color-warning)" : "var(--color-destructive)";

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={dim} height={dim} className="-rotate-90" aria-label={`${label}: ${score}%`} role="img">
        <circle
          cx={radius + stroke}
          cy={radius + stroke}
          r={radius}
          fill="none"
          stroke="var(--color-border)"
          strokeWidth={stroke}
        />
        <circle
          cx={radius + stroke}
          cy={radius + stroke}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
        <text
          x={radius + stroke}
          y={radius + stroke}
          textAnchor="middle"
          dominantBaseline="central"
          className={cn("fill-[var(--color-foreground)] font-bold rotate-90", size === "lg" ? "text-2xl" : "text-base")}
          style={{ fontSize: size === "lg" ? 28 : 18 }}
        >
          {score}
        </text>
      </svg>
      <span className="text-sm text-[var(--color-muted-foreground)]">{label}</span>
    </div>
  );
}

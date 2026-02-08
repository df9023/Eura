import { useState, useMemo } from "react";
import { useRules } from "@/hooks/useRules";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { RuleCategory, Severity } from "@/types";
import { Loader2, Search, BookOpen } from "lucide-react";

const CATEGORIES: RuleCategory[] = ["BASE", "SEC", "VULN", "DOC", "LIFE"];

const severityBadge: Record<Severity, "destructive" | "warning" | "outline" | "muted"> = {
  CRITICAL: "destructive",
  HIGH: "destructive",
  MEDIUM: "warning",
  LOW: "outline",
  INFO: "muted",
};

const categoryColors: Record<string, string> = {
  BASE: "bg-blue-100 text-blue-800",
  SEC: "bg-red-100 text-red-800",
  VULN: "bg-orange-100 text-orange-800",
  DOC: "bg-green-100 text-green-800",
  LIFE: "bg-purple-100 text-purple-800",
};

export function RuleExplorer() {
  const { data, isLoading, isError } = useRules();
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState<RuleCategory | "ALL">("ALL");

  const filtered = useMemo(() => {
    if (!data) return [];
    return data.rules.filter((r) => {
      if (category !== "ALL" && !r.id.includes(`CRA-${category}`)) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          r.id.toLowerCase().includes(q) ||
          r.title.toLowerCase().includes(q) ||
          r.description_short.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [data, search, category]);

  if (isLoading) {
    return (
      <div className="flex justify-center pt-20">
        <Loader2 className="h-8 w-8 animate-spin text-[var(--color-primary)]" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex justify-center pt-20 text-[var(--color-destructive)]">
        Failed to load rules. Is the API running?
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <BookOpen className="h-6 w-6 text-[var(--color-primary)]" />
        <h1 className="text-2xl font-bold">Rule Explorer</h1>
        <Badge variant="outline" className="ml-2">{data?.total ?? 0} rules</Badge>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--color-muted-foreground)]" />
          <Input
            placeholder="Search rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            aria-label="Search rules"
          />
        </div>
        <div className="flex gap-1">
          <Button
            variant={category === "ALL" ? "default" : "outline"}
            size="sm"
            onClick={() => setCategory("ALL")}
          >
            All
          </Button>
          {CATEGORIES.map((c) => (
            <Button
              key={c}
              variant={category === c ? "default" : "outline"}
              size="sm"
              onClick={() => setCategory(c)}
            >
              {c}
            </Button>
          ))}
        </div>
      </div>

      {/* Rule cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map((rule) => {
          const cat = rule.id.split("-")[1] ?? "BASE";
          return (
            <Card key={rule.id}>
              <CardHeader className="pb-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm text-[var(--color-muted-foreground)]">{rule.id}</span>
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded ${categoryColors[cat] ?? ""}`}>
                    {cat}
                  </span>
                  <Badge variant={severityBadge[rule.severity.overall]} className="ml-auto">
                    {rule.severity.overall}
                  </Badge>
                </div>
                <CardTitle className="text-base mt-1">{rule.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <CardDescription>{rule.description_short}</CardDescription>
                {rule.references && rule.references.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {rule.references.map((ref, i) => (
                      <a
                        key={i}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-[var(--color-primary)] underline"
                      >
                        {ref.label}
                      </a>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <p className="text-center text-[var(--color-muted-foreground)] py-10">No rules match your search.</p>
      )}
    </div>
  );
}

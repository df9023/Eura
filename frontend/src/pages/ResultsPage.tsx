import { useLocation, useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ComplianceScore } from "@/components/ComplianceScore";
import { VerdictBadge } from "@/components/VerdictBadge";
import { RuleResultRow } from "@/components/RuleResultRow";
import { ExportPanel } from "@/components/ExportPanel";
import type { ScanResponse, RuleResult } from "@/types";
import { ArrowLeft, Package, AlertTriangle } from "lucide-react";
import { useMemo, useState } from "react";

type StatusFilter = "ALL" | "FAIL" | "PASS" | "UNKNOWN";

export function ResultsPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const scanResponse = (location.state as { scanResponse?: ScanResponse } | null)?.scanResponse;
  const result = scanResponse?.result;

  const [statusFilter, setStatusFilter] = useState<StatusFilter>("ALL");

  const filteredRules: RuleResult[] = useMemo(() => {
    if (!result) return [];
    const rules = result.rule_results;
    if (statusFilter === "ALL") return rules;
    return rules.filter((r) => r.status === statusFilter);
  }, [result, statusFilter]);

  if (!result) {
    return (
      <div className="flex flex-col items-center gap-6 pt-20">
        <p className="text-lg text-[var(--color-muted-foreground)]">No scan results to display.</p>
        <Button variant="outline" onClick={() => navigate("/")}>
          <ArrowLeft className="mr-2 h-4 w-4" /> Back to Scan
        </Button>
      </div>
    );
  }

  const counts = {
    pass: result.rule_results.filter((r) => r.status === "PASS").length,
    fail: result.rule_results.filter((r) => r.status === "FAIL").length,
    unknown: result.rule_results.filter((r) => r.status === "UNKNOWN").length,
  };

  return (
    <div className="space-y-6">
      {/* Back + repo name */}
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" onClick={() => navigate("/")} aria-label="Back">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <h1 className="text-2xl font-bold">{result.repo}</h1>
      </div>

      {/* Top metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="flex flex-col items-center py-6">
          <ComplianceScore score={result.score} label="CRA Score" />
        </Card>

        <Card className="flex flex-col items-center justify-center py-6 gap-3">
          <VerdictBadge verdict={result.verdict} />
          <p className="text-sm text-[var(--color-muted-foreground)]">
            Scan ID: <span className="font-mono">{result.scan_id.slice(0, 8)}</span>
          </p>
        </Card>

        <Card className="py-6 px-6 flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <Package className="h-4 w-4" />
            <span className="text-sm font-medium">Dependencies</span>
            <Badge variant="outline" className="ml-auto">{result.dependency_count}</Badge>
          </div>
          {result.vulnerability_summary && (
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm font-medium">Vulnerabilities</span>
              <Badge variant={result.vulnerability_summary.total > 0 ? "destructive" : "success"} className="ml-auto">
                {result.vulnerability_summary.total}
              </Badge>
            </div>
          )}
          <div className="flex items-center gap-2 text-sm">
            <span className="text-[var(--color-success)] font-medium">{counts.pass} passed</span>
            <span className="text-[var(--color-muted-foreground)]">/</span>
            <span className="text-[var(--color-destructive)] font-medium">{counts.fail} failed</span>
            <span className="text-[var(--color-muted-foreground)]">/</span>
            <span className="text-[var(--color-warning)] font-medium">{counts.unknown} unknown</span>
          </div>
        </Card>

        <ExportPanel scanResult={result} />
      </div>

      {/* Rule results table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Rule Results ({result.rule_results.length})</CardTitle>
            <div className="flex gap-1">
              {(["ALL", "FAIL", "PASS", "UNKNOWN"] as StatusFilter[]).map((f) => (
                <Button
                  key={f}
                  variant={statusFilter === f ? "default" : "outline"}
                  size="sm"
                  onClick={() => setStatusFilter(f)}
                >
                  {f}
                </Button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {filteredRules.length === 0 ? (
            <p className="p-6 text-sm text-[var(--color-muted-foreground)]">No rules match the filter.</p>
          ) : (
            filteredRules.map((rule) => <RuleResultRow key={rule.rule_id} rule={rule} />)
          )}
        </CardContent>
      </Card>
    </div>
  );
}

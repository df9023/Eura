import { useMemo } from "react";
import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ComplianceScore } from "@/components/ComplianceScore";
import { VerdictBadge } from "@/components/VerdictBadge";
import { CategoryBreakdown } from "@/components/CategoryBreakdown";
import { SeverityChart } from "@/components/SeverityChart";
import { ExportPanel } from "@/components/ExportPanel";
import type { ScanResult, RuleResult } from "@/types";
import {
  Shield, ArrowRight, Package, AlertTriangle,
  CheckCircle2, XCircle, HelpCircle, FileText, TrendingUp,
} from "lucide-react";

/**
 * Dashboard page — shows scan overview, charts, and export actions.
 * Reads the latest scan result from localStorage (persisted after each scan).
 */
export function DashboardPage() {
  const stored = localStorage.getItem("eura_last_scan");
  const result: ScanResult | null = useMemo(() => {
    if (!stored) return null;
    try {
      return JSON.parse(stored) as ScanResult;
    } catch {
      return null;
    }
  }, [stored]);

  if (!result) {
    return (
      <div className="flex flex-col items-center gap-6 pt-16">
        <Shield className="h-16 w-16 text-[var(--color-muted-foreground)]" />
        <h1 className="text-2xl font-bold">Welcome to EURA</h1>
        <p className="text-[var(--color-muted-foreground)] max-w-md text-center">
          No scan results yet. Run your first scan to see the compliance dashboard with
          scores, charts, and exportable artifacts.
        </p>
        <Link to="/scan">
          <Button size="lg">
            Run a Scan <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </Link>
      </div>
    );
  }

  const counts = {
    pass: result.rule_results.filter((r) => r.status === "PASS").length,
    fail: result.rule_results.filter((r) => r.status === "FAIL").length,
    unknown: result.rule_results.filter((r) => r.status === "UNKNOWN").length,
    na: result.rule_results.filter((r) => r.status === "NOT_APPLICABLE").length,
    total: result.rule_results.length,
  };

  // Severity breakdown
  const severityCounts = useMemo(() => {
    const sc = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    result.rule_results
      .filter((r) => r.status === "FAIL")
      .forEach((r) => {
        const sev = r.severity.overall;
        if (sev in sc) sc[sev as keyof typeof sc]++;
      });
    return sc;
  }, [result]);

  // Category breakdown
  const categoryData = useMemo(() => {
    const cats: Record<string, { pass: number; fail: number; unknown: number }> = {};
    result.rule_results.forEach((r) => {
      const parts = r.rule_id.split("-");
      const cat = parts.length >= 2 ? parts[1] : "OTHER";
      if (!cats[cat]) cats[cat] = { pass: 0, fail: 0, unknown: 0 };
      if (r.status === "PASS") cats[cat].pass++;
      else if (r.status === "FAIL") cats[cat].fail++;
      else cats[cat].unknown++;
    });
    return Object.entries(cats).map(([name, d]) => ({
      name,
      pass: d.pass,
      fail: d.fail,
      unknown: d.unknown,
    }));
  }, [result]);

  // Top failing rules
  const topFailing: RuleResult[] = useMemo(() => {
    const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return [...result.rule_results]
      .filter((r) => r.status === "FAIL")
      .sort((a, b) => (severityOrder[a.severity.overall] ?? 5) - (severityOrder[b.severity.overall] ?? 5))
      .slice(0, 5);
  }, [result]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <TrendingUp className="h-6 w-6 text-[var(--color-primary)]" />
            Dashboard
          </h1>
          <p className="text-sm text-[var(--color-muted-foreground)] mt-1">
            Latest scan: <span className="font-mono">{result.repo}</span>
            {result.created_at && (
              <> &mdash; {new Date(result.created_at).toLocaleDateString()}</>
            )}
          </p>
        </div>
        <Link to="/scan">
          <Button variant="outline">New Scan</Button>
        </Link>
      </div>

      {/* Top metrics row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="flex flex-col items-center py-6">
          <ComplianceScore score={result.score} label="CRA Score" />
        </Card>

        <Card className="flex flex-col items-center justify-center py-6 gap-2">
          <VerdictBadge verdict={result.verdict} />
          <p className="text-xs text-[var(--color-muted-foreground)] mt-1 font-mono">
            {result.scan_id.slice(0, 8)}
          </p>
        </Card>

        <Card className="py-6 px-6 flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <Package className="h-4 w-4 text-[var(--color-primary)]" />
            <span className="text-sm font-medium">Dependencies</span>
            <Badge variant="outline" className="ml-auto">{result.dependency_count}</Badge>
          </div>
          {result.vulnerability_summary && (
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-[var(--color-warning)]" />
              <span className="text-sm font-medium">Vulnerabilities</span>
              <Badge
                variant={result.vulnerability_summary.total > 0 ? "destructive" : "success"}
                className="ml-auto"
              >
                {result.vulnerability_summary.total}
              </Badge>
            </div>
          )}
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-[var(--color-muted-foreground)]" />
            <span className="text-sm font-medium">Rules evaluated</span>
            <Badge variant="outline" className="ml-auto">{counts.total}</Badge>
          </div>
        </Card>

        <Card className="py-6 px-6 flex flex-col gap-2">
          <CardTitle className="text-sm">Rule Status</CardTitle>
          <div className="flex items-center gap-2 text-sm">
            <CheckCircle2 className="h-4 w-4 text-[var(--color-success)]" />
            <span>{counts.pass} passed</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <XCircle className="h-4 w-4 text-[var(--color-destructive)]" />
            <span>{counts.fail} failed</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <HelpCircle className="h-4 w-4 text-[var(--color-warning)]" />
            <span>{counts.unknown} unknown</span>
          </div>
        </Card>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Category Breakdown</CardTitle>
            <CardDescription>Pass / fail distribution across CRA rule categories</CardDescription>
          </CardHeader>
          <CardContent>
            <CategoryBreakdown data={categoryData} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Failure Severity</CardTitle>
            <CardDescription>Distribution of failing rules by severity</CardDescription>
          </CardHeader>
          <CardContent>
            <SeverityChart data={severityCounts} />
          </CardContent>
        </Card>
      </div>

      {/* Bottom row: Top failures + Exports */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Top failing rules */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top Failures</CardTitle>
            <CardDescription>Highest severity failures to address first</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {topFailing.length === 0 ? (
              <p className="text-sm text-[var(--color-success)] flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4" /> All rules passing!
              </p>
            ) : (
              topFailing.map((rule) => (
                <div key={rule.rule_id} className="flex items-center gap-3 py-1.5">
                  <XCircle className="h-4 w-4 text-[var(--color-destructive)] shrink-0" />
                  <span className="font-mono text-xs text-[var(--color-muted-foreground)] w-28 shrink-0">
                    {rule.rule_id}
                  </span>
                  <span className="text-sm flex-1 truncate">{rule.title}</span>
                  <Badge
                    variant={
                      rule.severity.overall === "CRITICAL" || rule.severity.overall === "HIGH"
                        ? "destructive"
                        : rule.severity.overall === "MEDIUM"
                          ? "warning"
                          : "outline"
                    }
                    className="text-xs"
                  >
                    {rule.severity.overall}
                  </Badge>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* Export panel */}
        <ExportPanel scanResult={result} />
      </div>
    </div>
  );
}

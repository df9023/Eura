/* ------------------------------------------------------------------ */
/*  TypeScript types mirroring backend Pydantic schemas               */
/* ------------------------------------------------------------------ */

export type Verdict = "SHIP_ALLOWED" | "SHIP_BLOCKED";
export type RuleStatus = "PASS" | "FAIL" | "UNKNOWN" | "NOT_APPLICABLE";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type RuleCategory = "BASE" | "SEC" | "VULN" | "DOC" | "LIFE";

export interface RuleResult {
  rule_id: string;
  title: string;
  status: RuleStatus;
  severity: {
    overall: Severity;
  };
  evidence: string[];
  category?: string;
}

export interface VulnerabilitySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanResult {
  scan_id: string;
  repo: string;
  verdict: Verdict;
  score: number;
  rule_results: RuleResult[];
  dependency_count: number;
  vulnerability_summary?: VulnerabilitySummary;
  created_at?: string;
}

export interface ScanRequest {
  repo: string;
  branch?: string;
}

export interface RuleDefinition {
  id: string;
  title: string;
  description_short: string;
  description_long: string;
  category: string;
  regulation: string;
  severity: {
    overall: Severity;
  };
  remediation_ids?: string[];
  references?: { url: string; label: string }[];
}

export interface RulesResponse {
  rules: RuleDefinition[];
  total: number;
}

export interface ScanResponse {
  scan_id: string;
  status: string;
  result?: ScanResult;
}

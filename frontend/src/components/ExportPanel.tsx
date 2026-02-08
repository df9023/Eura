import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { ScanResult } from "@/types";
import { api } from "@/lib/api";
import {
  Download,
  FileJson,
  Shield,
  AlertTriangle,
  Loader2,
  Check,
} from "lucide-react";

interface ExportPanelProps {
  scanResult: ScanResult;
}

type ExportFormat = "sarif" | "sbom-spdx" | "sbom-cyclonedx" | "vex" | "csaf";

interface ExportItem {
  id: ExportFormat;
  label: string;
  description: string;
  icon: typeof FileJson;
  tag: string;
}

const EXPORTS: ExportItem[] = [
  {
    id: "sarif",
    label: "SARIF Report",
    description: "Static analysis results (SARIF 2.1.0)",
    icon: FileJson,
    tag: "CRA",
  },
  {
    id: "sbom-spdx",
    label: "SBOM (SPDX)",
    description: "Software Bill of Materials — SPDX 2.3",
    icon: FileJson,
    tag: "CRA",
  },
  {
    id: "sbom-cyclonedx",
    label: "SBOM (CycloneDX)",
    description: "Software Bill of Materials — CycloneDX 1.5",
    icon: FileJson,
    tag: "CRA",
  },
  {
    id: "vex",
    label: "VEX Document",
    description: "Vulnerability Exploitability Exchange (OpenVEX)",
    icon: Shield,
    tag: "CRA",
  },
  {
    id: "csaf",
    label: "CSAF Advisory",
    description: "Common Security Advisory Framework 2.0",
    icon: AlertTriangle,
    tag: "CRA",
  },
];

function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function ExportPanel({ scanResult }: ExportPanelProps) {
  const [loading, setLoading] = useState<ExportFormat | null>(null);
  const [completed, setCompleted] = useState<Set<ExportFormat>>(new Set());

  const doExport = async (format: ExportFormat) => {
    setLoading(format);
    try {
      const repo = scanResult.repo;
      const scanId = scanResult.scan_id;
      const prefix = repo.replace("/", "_");

      if (format === "sarif") {
        const body = {
          rule_results: scanResult.rule_results.map((r) => ({
            rule_id: r.rule_id,
            status: r.status,
            reason: r.title,
            confidence: 0.8,
            evidence: {},
          })),
          repo_name: repo,
          scan_id: scanId,
        };
        const data = await api.post("/v1/exports/sarif", body);
        downloadJson(data, `${prefix}_sarif.json`);
      }

      if (format === "sbom-spdx" || format === "sbom-cyclonedx") {
        const sbomFormat = format === "sbom-spdx" ? "spdx" : "cyclonedx";
        const body = {
          dependencies: [], // Would need dependency data from scan
          format: sbomFormat,
          name: `EURA SBOM for ${repo}`,
          repo_name: repo,
        };
        const data = await api.post("/v1/sbom/generate", body);
        downloadJson(data, `${prefix}_sbom_${sbomFormat}.json`);
      }

      if (format === "vex") {
        const vulns = scanResult.vulnerability_summary
          ? Array.from({ length: scanResult.vulnerability_summary.total }, (_, i) => ({
            vuln_id: `VULN-${i + 1}`,
            affected_package: "unknown",
            severity: "MEDIUM",
          }))
          : [];
        const body = {
          vulnerabilities: vulns,
          repo_name: repo,
          scan_id: scanId,
        };
        const data = await api.post("/v1/exports/vex", body);
        downloadJson(data, `${prefix}_vex.json`);
      }

      if (format === "csaf") {
        const vulns = scanResult.vulnerability_summary
          ? Array.from({ length: scanResult.vulnerability_summary.total }, (_, i) => ({
            vuln_id: `VULN-${i + 1}`,
            affected_package: "unknown",
            severity: "MEDIUM",
          }))
          : [];
        const body = {
          vulnerabilities: vulns,
          repo_name: repo,
          scan_id: scanId,
        };
        const data = await api.post("/v1/exports/csaf", body);
        downloadJson(data, `${prefix}_csaf.json`);
      }

      setCompleted((prev) => new Set(prev).add(format));
    } catch (err) {
      console.error(`Export ${format} failed:`, err);
    } finally {
      setLoading(null);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Download className="h-4 w-4" /> Export Artifacts
        </CardTitle>
        <CardDescription>
          Download compliance artifacts for EU regulatory audits
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {EXPORTS.map((exp) => {
          const Icon = exp.icon;
          const isLoading = loading === exp.id;
          const isDone = completed.has(exp.id);

          return (
            <div
              key={exp.id}
              className="flex items-center gap-3 py-2 px-3 rounded-md hover:bg-[var(--color-muted)] transition-colors"
            >
              <Icon className="h-4 w-4 text-[var(--color-primary)] shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium">{exp.label}</p>
                <p className="text-xs text-[var(--color-muted-foreground)] truncate">
                  {exp.description}
                </p>
              </div>
              <Badge variant="outline" className="text-xs shrink-0">
                {exp.tag}
              </Badge>
              <Button
                size="sm"
                variant={isDone ? "success" : "outline"}
                onClick={() => doExport(exp.id)}
                disabled={isLoading}
                className="shrink-0"
              >
                {isLoading ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : isDone ? (
                  <Check className="h-3 w-3" />
                ) : (
                  <Download className="h-3 w-3" />
                )}
              </Button>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

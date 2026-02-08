import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useStartScan } from "@/hooks/useScans";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Loader2, ArrowRight, Github } from "lucide-react";

export function ScanPage() {
  const [repo, setRepo] = useState("");
  const navigate = useNavigate();
  const scan = useStartScan();

  const handleScan = () => {
    if (!repo.trim()) return;
    scan.mutate(
      { repo: repo.trim() },
      {
        onSuccess: (data) => {
          // Persist scan result for dashboard
          if (data.result) {
            localStorage.setItem("eura_last_scan", JSON.stringify(data.result));
          }
          navigate("/results", { state: { scanResponse: data } });
        },
      },
    );
  };

  return (
    <div className="flex flex-col items-center justify-center gap-12 pt-12">
      {/* Hero */}
      <div className="flex flex-col items-center gap-4 text-center max-w-2xl">
        <div className="flex items-center justify-center h-16 w-16 rounded-2xl bg-[var(--color-primary)] text-white">
          <Shield className="h-8 w-8" />
        </div>
        <h1 className="text-4xl font-bold tracking-tight">EURA Compliance Scanner</h1>
        <p className="text-lg text-[var(--color-muted-foreground)] max-w-lg">
          Evaluate any GitHub repository against the <strong>EU Cyber Resilience Act</strong> and{" "}
          <strong>EU AI Act</strong> in seconds.
        </p>
      </div>

      {/* Scan form */}
      <Card className="w-full max-w-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Github className="h-5 w-5" /> Scan a Repository
          </CardTitle>
          <CardDescription>Enter a GitHub owner/repo (e.g. facebook/react)</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleScan();
            }}
            className="flex gap-2"
          >
            <Input
              placeholder="owner/repo"
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              disabled={scan.isPending}
              aria-label="GitHub repository"
            />
            <Button type="submit" disabled={scan.isPending || !repo.trim()} size="lg">
              {scan.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Scanning...
                </>
              ) : (
                <>
                  Scan <ArrowRight className="ml-2 h-4 w-4" />
                </>
              )}
            </Button>
          </form>
          {scan.isError && (
            <p className="mt-3 text-sm text-[var(--color-destructive)]">
              {scan.error instanceof Error ? scan.error.message : "Scan failed"}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Feature cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 w-full max-w-3xl">
        {[
          { title: "35 CRA Rules", desc: "Covers BASE, SEC, VULN, DOC, LIFE categories" },
          { title: "Vulnerability Scan", desc: "OSV.dev integration for known CVEs" },
          { title: "Compliance Artifacts", desc: "SBOM, SARIF, badges, remediation guides" },
        ].map((f) => (
          <Card key={f.title} className="text-center">
            <CardHeader className="pb-2">
              <CardTitle className="text-base">{f.title}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-[var(--color-muted-foreground)]">{f.desc}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

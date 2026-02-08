"""API V1 request and response schemas for Section 3.5."""
from typing import List, Optional, Literal, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from uuid import UUID


# ============================================================================
# Scan Management Schemas
# ============================================================================

class ScanResponseV1(BaseModel):
    """Scan response model."""
    id: str
    project_id: Optional[str] = None
    repository_id: Optional[str] = None
    status: Literal["queued", "processing", "completed", "failed"]
    repo_name: str
    commit_hash: Optional[str] = None
    installation_id: Optional[int] = None
    total_files: Optional[int] = None
    analyzed_files: Optional[int] = None
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    verdict: Optional[Literal["SHIP_ALLOWED", "SHIP_BLOCKED"]] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class ScanListResponseV1(BaseModel):
    """List of scans response."""
    scans: List[ScanResponseV1]
    total: int


# ============================================================================
# Project Management Schemas
# ============================================================================

class ProjectCreateRequestV1(BaseModel):
    """Request to create a project."""
    name: str = Field(..., min_length=1, max_length=255)
    organization_id: Optional[str] = None


class ProjectUpdateRequestV1(BaseModel):
    """Request to update a project."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)


class ProjectResponseV1(BaseModel):
    """Project response model."""
    id: str
    organization_id: Optional[str] = None
    name: str
    created_at: datetime
    updated_at: datetime
    last_scan_at: Optional[datetime] = None
    last_scan_id: Optional[str] = None


class ProjectListResponseV1(BaseModel):
    """List of projects response."""
    projects: List[ProjectResponseV1]
    total: int


# ============================================================================
# Repository Management Schemas
# ============================================================================

class RepositoryCreateRequestV1(BaseModel):
    """Request to create a repository."""
    project_id: str
    provider: Literal["github", "gitlab", "bitbucket", "azure_devops"]
    owner: str = Field(..., min_length=1, max_length=255)
    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1)
    default_branch: Optional[str] = Field("main", max_length=255)


class RepositoryUpdateRequestV1(BaseModel):
    """Request to update a repository."""
    default_branch: Optional[str] = Field(None, max_length=255)


class RepositoryResponseV1(BaseModel):
    """Repository response model."""
    id: str
    project_id: str
    provider: str
    owner: str
    name: str
    url: str
    default_branch: str
    created_at: datetime
    updated_at: datetime


class RepositoryListResponseV1(BaseModel):
    """List of repositories response."""
    repositories: List[RepositoryResponseV1]
    total: int


# ============================================================================
# Rule Management Schemas
# ============================================================================

class RuleResponseV1(BaseModel):
    """Rule response model."""
    id: str
    rule_id: str
    version: str
    regulation: str
    title: str
    description_short: Optional[str] = None
    description_long: Optional[str] = None
    severity: Literal["critical", "high", "medium", "low"]
    is_blocking: bool
    rule_definition: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class RuleListResponseV1(BaseModel):
    """List of rules response."""
    rules: List[RuleResponseV1]
    total: int


# ============================================================================
# Compliance Report Schemas
# ============================================================================

class ComplianceReportResponseV1(BaseModel):
    """Compliance report response model."""
    id: str
    scan_id: str
    project_id: str
    regulation: str
    verdict: Literal["SHIP_ALLOWED", "SHIP_BLOCKED"]
    score: Optional[float] = None
    total_rules: Optional[int] = None
    passed: Optional[int] = None
    failed: Optional[int] = None
    unknown: Optional[int] = None
    not_applicable: Optional[int] = None
    evaluated_at: datetime
    created_at: datetime


class ComplianceReportListResponseV1(BaseModel):
    """List of compliance reports response."""
    reports: List[ComplianceReportResponseV1]
    total: int


class ReportGenerateRequestV1(BaseModel):
    """Request to generate a compliance report."""
    scan_id: str
    regulation: Optional[str] = None  # If None, generates for all regulations


# ============================================================================
# SBOM Schemas
# ============================================================================

class SbomDependencyItem(BaseModel):
    """Single dependency for SBOM generation (name, version, type, file_source)."""
    name: str = Field(..., min_length=1, description="Package name")
    version: str = Field(default="", description="Version or version specifier")
    type: str = Field(default="unknown", description="Ecosystem: python, node, poetry, etc.")
    file_source: str = Field(default="", description="Manifest file path (e.g. requirements.txt)")


class SbomGenerateRequestV1(BaseModel):
    """Request to generate SBOM from dependency list (no scan/DB required)."""
    dependencies: List[SbomDependencyItem] = Field(..., description="List of dependencies")
    format: Literal["spdx", "cyclonedx"] = Field(
        "spdx",
        description="Output format: SPDX 2.3 or CycloneDX 1.5"
    )
    name: Optional[str] = Field("EURA SBOM", description="Document name (SPDX)")
    repo_name: Optional[str] = Field(None, description="Repository identifier (e.g. owner/repo)")
    commit_sha: Optional[str] = Field(None, description="Commit hash")


# ============================================================================
# SARIF Export Schemas
# ============================================================================

class SarifRuleResultItem(BaseModel):
    """A single rule evaluation result for SARIF export."""
    rule_id: str = Field(..., description="Rule identifier (e.g. CRA-BASE-001)")
    status: Literal["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"] = Field(
        ..., description="Evaluation status"
    )
    reason: str = Field(default="", description="Human-readable explanation")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence score")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting evidence")


class SarifFindingItem(BaseModel):
    """A security finding for SARIF export (secret detection, code analysis)."""
    id: str = Field(default="", description="Finding identifier")
    title: str = Field(..., description="Finding title")
    severity: Literal["high", "medium", "low", "info"] = Field(
        default="medium", description="Severity level"
    )
    summary: str = Field(default="", description="Brief summary")
    details: str = Field(default="", description="Full details")
    category: str = Field(default="security", description="Category (secrets, auth, crypto, config)")
    evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Evidence entries with file, lines, snippet"
    )


class SarifVulnerabilityItem(BaseModel):
    """A single vulnerability for SARIF export."""
    vuln_id: str = Field(..., description="Vulnerability ID (e.g. GHSA-xxxx or CVE-xxxx)")
    summary: str = Field(default="", description="Vulnerability summary")
    severity: str = Field(default="UNKNOWN", description="Severity (CRITICAL, HIGH, MEDIUM, LOW)")
    affected_package: str = Field(default="", description="Affected package name")
    affected_version: str = Field(default="", description="Affected version")
    fixed_version: str = Field(default="", description="Version that fixes the vulnerability")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class SarifVulnerabilityReport(BaseModel):
    """Vulnerability report for SARIF export."""
    vulnerability_count: int = Field(default=0, description="Total vulnerabilities found")
    vulnerable_count: int = Field(default=0, description="Number of vulnerable packages")
    total_dependencies: int = Field(default=0, description="Total dependencies scanned")
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    vulnerabilities: List[SarifVulnerabilityItem] = Field(
        default_factory=list, description="List of vulnerabilities"
    )


class SarifExportRequestV1(BaseModel):
    """Request to generate a SARIF 2.1.0 report from scan data.

    Provide rule_results at minimum. Optionally include findings and
    vulnerability_report for a comprehensive SARIF document.
    """
    rule_results: List[SarifRuleResultItem] = Field(
        ..., description="Rule evaluation results from EURA scan"
    )
    findings: List[SarifFindingItem] = Field(
        default_factory=list, description="Security findings (optional)"
    )
    vulnerability_report: Optional[SarifVulnerabilityReport] = Field(
        None, description="OSV vulnerability report (optional)"
    )
    repo_name: Optional[str] = Field(None, description="Repository identifier (e.g. owner/repo)")
    commit_sha: Optional[str] = Field(None, description="Git commit hash")
    scan_id: Optional[str] = Field(None, description="EURA scan UUID")


# ============================================================================
# Remediation Template Schemas
# ============================================================================

class RemediationTemplateRequestV1(BaseModel):
    """Request to generate a remediation compliance document."""
    template_id: Literal[
        "security-md", "changelog-md", "support-md",
        "contributing-md", "security-config"
    ] = Field(..., description="Template identifier")
    project_name: str = Field(default="My Project", description="Project name for the template")
    contact_email: str = Field(default="security@example.com", description="Security/support contact email")
    # SECURITY.md specific
    pgp_key_url: Optional[str] = Field(None, description="URL to PGP public key (SECURITY.md)")
    response_hours: int = Field(default=48, ge=1, description="Hours to acknowledge report (SECURITY.md)")
    disclosure_days: int = Field(default=90, ge=1, description="Days before coordinated disclosure (SECURITY.md)")
    # CHANGELOG.md specific
    initial_version: str = Field(default="1.0.0", description="Initial version for CHANGELOG.md")
    # SUPPORT.md specific
    support_years: int = Field(default=5, ge=1, le=20, description="Years of committed support (SUPPORT.md)")


class RemediationTemplateResponseV1(BaseModel):
    """Response with generated remediation template."""
    template_id: str
    filename: str
    content: str
    addresses_rules: List[str]


class RemediationTemplateListItemV1(BaseModel):
    """Metadata for a single available template."""
    template_id: str
    filename: str
    addresses_rules: List[str]
    description: str


# ============================================================================
# VEX Export Schemas
# ============================================================================

class VexVulnerabilityItem(BaseModel):
    """A single vulnerability for VEX export."""
    vuln_id: str = Field(..., description="Vulnerability ID (e.g. CVE-2021-44228, GHSA-xxxx)")
    affected_package: str = Field(..., description="Affected package name")
    affected_version: str = Field(default="", description="Currently installed version")
    fixed_version: str = Field(default="", description="Version that fixes the vulnerability")
    severity: str = Field(default="UNKNOWN", description="Severity (CRITICAL, HIGH, MEDIUM, LOW)")
    summary: str = Field(default="", description="Vulnerability summary")
    ecosystem: str = Field(default="", description="Package ecosystem (pypi, npm, go, etc.)")
    vex_status: Optional[Literal[
        "not_affected", "affected", "fixed", "under_investigation"
    ]] = Field(None, description="Explicit VEX status override")
    justification: Optional[Literal[
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    ]] = Field(None, description="Justification for not_affected status")
    action_statement: str = Field(default="", description="Recommended action")
    impact_statement: str = Field(default="", description="Impact description")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class VexExportRequestV1(BaseModel):
    """Request to generate an OpenVEX document from vulnerability data.

    Provide a list of vulnerabilities.  Each vulnerability will become a
    VEX statement describing its exploitability status.
    """
    vulnerabilities: List[VexVulnerabilityItem] = Field(
        ..., description="Vulnerabilities to include in VEX document"
    )
    repo_name: Optional[str] = Field(None, description="Repository identifier (e.g. owner/repo)")
    commit_sha: Optional[str] = Field(None, description="Git commit hash")
    scan_id: Optional[str] = Field(None, description="EURA scan UUID")
    author: str = Field(
        default="EURA Compliance Scanner",
        description="VEX document author"
    )
    author_role: Literal["tool", "vendor", "discoverer"] = Field(
        default="tool", description="Author role"
    )


# ============================================================================
# CSAF Export Schemas
# ============================================================================

class CsafVulnerabilityItem(BaseModel):
    """A single vulnerability for CSAF export."""
    vuln_id: str = Field(..., description="Vulnerability ID (e.g. CVE-2021-44228, GHSA-xxxx)")
    affected_package: str = Field(..., description="Affected package name")
    affected_version: str = Field(default="", description="Currently installed version")
    fixed_version: str = Field(default="", description="Version that fixes the vulnerability")
    severity: str = Field(default="UNKNOWN", description="Severity (CRITICAL, HIGH, MEDIUM, LOW)")
    summary: str = Field(default="", description="Vulnerability summary")
    ecosystem: str = Field(default="", description="Package ecosystem (pypi, npm, go, etc.)")
    vex_status: Optional[str] = Field(None, description="Explicit VEX status override")
    action_statement: str = Field(default="", description="Recommended action")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class CsafExportRequestV1(BaseModel):
    """Request to generate a CSAF 2.0 advisory from vulnerability data.

    Provide a list of vulnerabilities.  Each becomes a CSAF vulnerability
    entry with product status, remediations, and severity scores.
    """
    vulnerabilities: List[CsafVulnerabilityItem] = Field(
        ..., description="Vulnerabilities to include in CSAF advisory"
    )
    repo_name: Optional[str] = Field(None, description="Repository identifier (e.g. owner/repo)")
    commit_sha: Optional[str] = Field(None, description="Git commit hash")
    scan_id: Optional[str] = Field(None, description="EURA scan UUID")
    title: Optional[str] = Field(None, description="Advisory title (auto-generated if omitted)")
    publisher_name: str = Field(
        default="EURA Compliance Scanner",
        description="Publisher name for the advisory"
    )
    category: Literal["csaf_vex", "csaf_security_advisory"] = Field(
        default="csaf_vex",
        description="CSAF document category"
    )


# ============================================================================
# Error Response Schema
# ============================================================================

class ErrorResponseV1(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None

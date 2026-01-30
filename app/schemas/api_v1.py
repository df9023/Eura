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
# Error Response Schema
# ============================================================================

class ErrorResponseV1(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None

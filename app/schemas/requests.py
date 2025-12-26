"""API request and response schemas."""
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field
from app.models.domain import Finding


class Dependency(BaseModel):
    """A dependency extracted from a manifest file."""
    name: str
    version: str
    type: str  # e.g., "python", "node", "poetry"
    file_source: str


class RuleResult(BaseModel):
    """Result of evaluating a single compliance rule."""
    rule_id: str
    status: Literal["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: Optional[str] = None
    evaluated_at: str


class ComplianceReport(BaseModel):
    """Compliance evaluation report for CRA rules."""
    rule_results: List[RuleResult]
    evaluated_at: str
    total_rules: int
    passed: int
    failed: int
    unknown: int
    not_applicable: int


class ScanRepoRequest(BaseModel):
    """Request schema for scanning a repository."""
    project_id: Optional[str] = Field(None, description="Optional UUID. If None, scan is not saved.")
    repo_name: str = Field(..., description="Format: owner/repo")
    installation_id: int
    max_files: Optional[int] = Field(None, description="Override MAX_FILES for this scan")


class ScanResponse(BaseModel):
    """Response schema for scan results."""
    success: bool
    repo_name: str
    total_files: int
    analyzed_files: int
    findings: List[Finding]
    commit_hash: Optional[str] = None
    dependencies: List[Dependency] = []
    compliance_report: Optional[ComplianceReport] = None


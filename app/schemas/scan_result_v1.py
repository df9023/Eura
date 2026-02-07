"""Phase 0: Single Source of Truth Contract - Scan Result V1 Models.

This module defines the verdict-first, deterministic response model that drives the UI.
All models use timezone-aware UTC datetimes and strict typing for deterministic behavior.
"""
import re
from datetime import datetime, timezone
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator


class RuleResultV1(BaseModel):
    """Result of evaluating a single compliance rule.
    
    Attributes:
        rule_id: Unique identifier for the rule (e.g., "CRA-BASE-001")
        title: Human-readable title of the rule
        description: Detailed description of what the rule checks
        status: Evaluation status (PASS, FAIL, or NOT_APPLICABLE)
        is_blocking: Whether this rule blocks shipping if it fails
        evidence: Dictionary containing evidence data (file paths, snippets, etc.)
    """
    rule_id: str = Field(..., description="Rule identifier, e.g., 'CRA-BASE-001'")
    title: str = Field(..., description="Human-readable rule title")
    description: str = Field(..., description="Detailed description of the rule")
    status: Literal["PASS", "FAIL", "NOT_APPLICABLE"] = Field(
        ..., 
        description="Evaluation status of the rule"
    )
    is_blocking: bool = Field(
        ..., 
        description="True if this rule blocks shipping when it fails"
    )
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Evidence data supporting the evaluation (file paths, snippets, etc.)"
    )


class EvidenceRefsV1(BaseModel):
    """References to stored evidence in the database.
    
    Attributes:
        scan_id: UUID of the scan record
        dependency_snapshot_id: UUID of the dependency snapshot (or scan_id if snapshot not available)
        compliance_report_id: UUID of the compliance report record
    """
    scan_id: str = Field(..., description="UUID of the scan record")
    dependency_snapshot_id: Optional[str] = Field(
        None,
        description="UUID of the dependency snapshot, or scan_id if snapshot not available"
    )
    compliance_report_id: Optional[str] = Field(
        None,
        description="UUID of the compliance report record"
    )


class AdvisoryFindingV1(BaseModel):
    """Advisory finding that does not block shipping but provides recommendations.
    
    Attributes:
        category: Category of the advisory (e.g., "security", "performance", "best_practice")
        message: Human-readable advisory message
        file_path: Optional file path where the advisory applies
        line_start: Optional starting line number
        line_end: Optional ending line number
        suggested_fix: Optional suggested remediation
    """
    category: str = Field(..., description="Category of the advisory finding")
    message: str = Field(..., description="Human-readable advisory message")
    file_path: Optional[str] = Field(None, description="File path where the advisory applies")
    line_start: Optional[int] = Field(None, ge=1, description="Starting line number (1-indexed)")
    line_end: Optional[int] = Field(None, ge=1, description="Ending line number (1-indexed)")
    suggested_fix: Optional[str] = Field(None, description="Suggested remediation for the advisory")


class ScanRunRequestV1(BaseModel):
    """V1 API request for running a scan.
    
    Attributes:
        repo_url: Repository URL or identifier (e.g., "owner/repo" or full GitHub URL)
        environment: Deployment environment (defaults to "dev")
        installation_id: Optional GitHub App installation ID (required for private repos)
        user_id: Optional user ID to associate scan with logged-in user
    """
    repo_url: str = Field(..., description="Repository URL or identifier (e.g., 'owner/repo')")
    environment: Literal["dev", "staging", "production", "eu-production"] = Field(
        default="dev",
        description="Deployment environment"
    )
    installation_id: Optional[int] = Field(
        None,
        description="GitHub App installation ID (required for private repos, optional for public)"
    )
    user_id: Optional[str] = Field(
        None,
        description="User ID to associate scan with logged-in user (for scan history)"
    )
    
    @field_validator('repo_url')
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        """
        Validate repository URL format.
        
        Allows standard "owner/repo" or full GitHub URLs.
        Regex checks for: (optional https://github.com/) + owner + / + repo
        
        Raises:
            ValueError: If repo_url format is invalid
        """
        # Allow standard "owner/repo" or full GitHub URLs
        # Regex checks for: (optional https://github.com/) + owner + / + repo
        pattern = r'^(https?://github\.com/)?[\w-]+/[\w.-]+/?$'
        if not re.match(pattern, v.strip()):
            raise ValueError(
                'Invalid repository URL format. Must be "owner/repo" or "https://github.com/owner/repo"'
            )
        return v


class ScanResultV1(BaseModel):
    """Phase 0: Single Source of Truth Contract - Verdict-first scan result.
    
    This model is deterministic and drives the UI. It provides a clear verdict
    (SHIP_ALLOWED or SHIP_BLOCKED) along with all rule evaluations and evidence references.
    
    Attributes:
        scan_id: UUID of the scan record
        project_id: UUID of the project (None for ephemeral scans)
        repo_url: Repository URL or identifier (e.g., "owner/repo")
        commit_sha: Git commit SHA that was evaluated
        environment: Deployment environment where this scan applies
        evaluated_at: UTC timestamp when the evaluation was performed
        verdict: Shipping verdict (SHIP_ALLOWED or SHIP_BLOCKED)
        blocking_rules: List of rule IDs that are blocking shipping
        rule_results: Complete list of all rule evaluation results
        evidence_refs: References to stored evidence in the database
        advisory_findings: Optional advisory findings (non-blocking recommendations)
    """
    scan_id: str = Field(..., description="UUID of the scan record")
    project_id: Optional[str] = Field(None, description="UUID of the project, None for ephemeral scans")
    repo_url: str = Field(..., description="Repository URL or identifier (e.g., 'owner/repo')")
    commit_sha: str = Field(..., description="Git commit SHA that was evaluated")
    environment: Literal["dev", "staging", "production", "eu-production"] = Field(
        ...,
        description="Deployment environment where this scan applies"
    )
    evaluated_at: datetime = Field(
        ...,
        description="UTC timestamp when the evaluation was performed (must be timezone-aware)"
    )
    verdict: Literal["SHIP_ALLOWED", "SHIP_BLOCKED"] = Field(
        ...,
        description="Shipping verdict based on rule evaluations"
    )
    blocking_rules: List[str] = Field(
        default_factory=list,
        description="List of rule IDs that are blocking shipping (empty if verdict is SHIP_ALLOWED)"
    )
    rule_results: List[RuleResultV1] = Field(
        default_factory=list,
        description="Complete list of all rule evaluation results"
    )
    evidence_refs: EvidenceRefsV1 = Field(
        ...,
        description="References to stored evidence in the database"
    )
    advisory_findings: List[AdvisoryFindingV1] = Field(
        default_factory=list,
        description="Optional advisory findings (non-blocking recommendations)"
    )
    
    @field_validator('evaluated_at')
    @classmethod
    def ensure_timezone_aware(cls, v: datetime) -> datetime:
        """Ensure evaluated_at is timezone-aware (UTC)."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=False,
    )

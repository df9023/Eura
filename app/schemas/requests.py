"""API request and response schemas."""
from typing import List, Optional
from pydantic import BaseModel, Field
from app.models.domain import Finding


class Dependency(BaseModel):
    """A dependency extracted from a manifest file."""
    name: str
    version: str
    type: str  # e.g., "python", "node", "poetry"
    file_source: str


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


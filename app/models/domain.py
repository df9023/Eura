"""Domain models for findings and evidence."""
from typing import List, Optional, Literal
from pydantic import BaseModel, Field

Severity = Literal["high", "medium", "low", "info"]


class Evidence(BaseModel):
    """Evidence for a security finding."""
    file: str
    lines: Optional[str] = None
    snippet: Optional[str] = None


class Finding(BaseModel):
    """A security finding from code analysis."""
    id: str
    title: str
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    details: str
    evidence: List[Evidence]
    recommendation: str
    category: Optional[str] = None  # ex: secrets, auth, crypto, config


"""Supabase database operations."""
import hashlib
from typing import List, Optional
from datetime import datetime
from fastapi import HTTPException
from app.core.config import supabase
from app.core.logger import logger
from app.models.domain import Finding, Evidence


def generate_fingerprint(project_id: str, vuln_category: str, title: str, evidence: List[Evidence]) -> str:
    """Generate SHA256 fingerprint for deduplication."""
    if not evidence:
        content = f"{project_id}:{vuln_category}:{title}:"
    else:
        ev0 = evidence[0]
        content = f"{project_id}:{vuln_category}:{title}:{ev0.file}:{ev0.lines or ''}"
    return hashlib.sha256(content.encode()).hexdigest()


def parse_line_number(lines_str: Optional[str]) -> Optional[int]:
    """Parse line number from '10-18' format, return first number."""
    if not lines_str:
        return None
    try:
        parts = lines_str.split("-")
        return int(parts[0].strip())
    except (ValueError, AttributeError):
        return None


def create_scan_record(project_id: str, repo_name: str, installation_id: int) -> str:
    """Create a scan record and return scan_id."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        result = supabase.table("scans").insert({
            "project_id": project_id,
            "status": "processing",
            "repo_name": repo_name,
            "installation_id": installation_id,
        }).execute()
        
        if not result.data or len(result.data) == 0:
            raise ValueError("Failed to create scan record")
        
        scan_id = result.data[0]["id"]
        logger.info("Created scan record: scan_id=%s, project_id=%s", scan_id, project_id)
        return scan_id
    except Exception as e:
        logger.error("Failed to create scan record: %s", e)
        raise


def update_scan_success(scan_id: str, duration_ms: int, total_files: int, analyzed_files: int):
    """Update scan record on success."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        supabase.table("scans").update({
            "status": "completed",
            "duration_ms": duration_ms,
            "total_files": total_files,
            "analyzed_files": analyzed_files,
            "error": None,
        }).eq("id", scan_id).execute()
        logger.info("Updated scan success: scan_id=%s, duration_ms=%d", scan_id, duration_ms)
    except Exception as e:
        logger.error("Failed to update scan success: %s", e)
        raise


def update_scan_failure(scan_id: str, duration_ms: int, error_msg: str):
    """Update scan record on failure."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        supabase.table("scans").update({
            "status": "failed",
            "duration_ms": duration_ms,
            "error": error_msg[:5000] if error_msg else None,  # Truncate if too long
        }).eq("id", scan_id).execute()
        logger.error("Updated scan failure: scan_id=%s, error=%s", scan_id, error_msg[:200])
    except Exception as e:
        logger.error("Failed to update scan failure: %s", e)
        # Don't raise - we're already in error handling


def update_project_last_scan(project_id: str):
    """Update project's last_scan_at timestamp."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        supabase.table("projects").update({
            "last_scan_at": datetime.utcnow().isoformat() + "Z",
        }).eq("id", project_id).execute()
        logger.info("Updated project last_scan_at: project_id=%s", project_id)
    except Exception as e:
        logger.warning("Failed to update project last_scan_at: %s", e)
        # Don't raise - this is not critical


def insert_findings(scan_id: str, project_id: str, findings: List[Finding]):
    """Insert findings with deduplication by fingerprint."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    if not findings:
        logger.info("No findings to insert")
        return
    
    # Deduplicate by fingerprint
    seen_fingerprints = set()
    unique_findings = []
    
    for finding in findings:
        vuln_category = finding.category or "other"
        evidence = finding.evidence or []
        ev0 = evidence[0] if evidence else Evidence(file="")
        
        fingerprint = generate_fingerprint(
            project_id=project_id,
            vuln_category=vuln_category,
            title=finding.title,
            evidence=evidence
        )
        
        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            unique_findings.append((finding, fingerprint, vuln_category, ev0))
    
    logger.info("Deduplicated findings: %d -> %d", len(findings), len(unique_findings))
    
    # Map severity to allowed values (info|low|medium|high|critical)
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    
    # Prepare insert data
    insert_data = []
    for finding, fingerprint, vuln_category, ev0 in unique_findings:
        # Map severity to allowed values, default to "info"
        mapped_severity = severity_map.get(finding.severity.lower(), "info")
        
        line_number = parse_line_number(ev0.lines if ev0 else None)
        
        # Prepare evidence_json
        evidence_json = []
        for ev in (finding.evidence or []):
            evidence_json.append({
                "file": ev.file,
                "lines": ev.lines,
                "snippet": ev.snippet,
            })
        
        insert_data.append({
            "scan_id": scan_id,
            "project_id": project_id,
            "severity": mapped_severity,
            "category": "security",  # Always "security"
            "vuln_category": vuln_category,
            "title": finding.title,
            "description": finding.summary,  # Old column
            "summary": finding.summary,
            "details": finding.details,
            "confidence": finding.confidence,
            "recommendation": finding.recommendation,
            "suggested_fix": finding.recommendation,  # Old column
            "evidence_json": evidence_json,
            "file_path": ev0.file if ev0 else None,
            "line_number": line_number,
            "code_snippet_before": ev0.snippet if ev0 else None,
            "fingerprint": fingerprint,
        })
    
    if not insert_data:
        logger.info("No findings to insert after deduplication")
        return
    
    # Batch insert
    try:
        # Insert in batches to avoid payload size issues
        batch_size = 100
        total_inserted = 0
        
        for i in range(0, len(insert_data), batch_size):
            batch = insert_data[i:i + batch_size]
            result = supabase.table("findings").insert(batch).execute()
            inserted_count = len(result.data) if result.data else 0
            total_inserted += inserted_count
            logger.info("Inserted batch: %d findings", inserted_count)
        
        logger.info("Inserted findings: total=%d", total_inserted)
    except Exception as e:
        logger.error("Failed to insert findings: %s", e)
        # Check if it's a duplicate constraint error
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            logger.warning("Duplicate findings detected (constraint violation), continuing")
        else:
            raise


"""Supabase database operations."""
import hashlib
from typing import List, Optional
from datetime import datetime
from fastapi import HTTPException
from app.core.config import supabase
from app.core.logger import logger
from app.models.domain import Finding, Evidence
from app.schemas.requests import Dependency, ComplianceReport, RuleResult


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


def create_scan_record(
    repo_name: str,
    installation_id: Optional[int] = None,
    commit_hash: Optional[str] = None,
    project_id: Optional[str] = None,
    user_id: Optional[str] = None
) -> str:
    """
    Create a scan record and return scan_id.
    
    Args:
        project_id: Optional project ID for persistence (legacy support)
        repo_name: Repository name in format "owner/repo" (required)
        installation_id: Optional GitHub App installation ID
        commit_hash: Optional Git commit SHA
        user_id: Optional user ID to associate scan with logged-in user
    
    Returns:
        scan_id: UUID of the created scan record
    
    Raises:
        HTTPException: If Supabase is not configured or record creation fails
        ValueError: If neither project_id nor user_id is provided, or repo_name is missing
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    if not repo_name:
        raise ValueError("repo_name is required")
    
    if not project_id and not user_id:
        raise ValueError("Either project_id or user_id must be provided")
    
    try:
        record_data = {
            "status": "processing",
            "repo_name": repo_name,
        }
        
        if project_id:
            record_data["project_id"] = project_id
        if user_id:
            record_data["user_id"] = user_id
        if installation_id is not None:
            record_data["installation_id"] = installation_id
        if commit_hash:
            record_data["commit_hash"] = commit_hash
        
        result = supabase.table("scans").insert(record_data).execute()
        
        if not result.data or len(result.data) == 0:
            raise ValueError("Failed to create scan record")
        
        scan_id = result.data[0]["id"]
        logger.info("Created scan record: scan_id=%s, project_id=%s, user_id=%s", scan_id, project_id, user_id)
        return scan_id
    except Exception as e:
        logger.error("Failed to create scan record: %s", e)
        raise


def update_scan_success(scan_id: str, duration_ms: int, total_files: int, analyzed_files: int, commit_hash: Optional[str] = None):
    """Update scan record on success."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        update_data = {
            "status": "completed",
            "duration_ms": duration_ms,
            "total_files": total_files,
            "analyzed_files": analyzed_files,
            "error": None,
        }
        if commit_hash:
            update_data["commit_hash"] = commit_hash
        
        supabase.table("scans").update(update_data).eq("id", scan_id).execute()
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


def bulk_insert_dependencies(scan_id: str, project_id: str, dependencies: List[Dependency]):
    """Insert dependencies into scan_dependencies table."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    if not dependencies:
        logger.info("No dependencies to insert")
        return
    
    try:
        # Transform Dependency objects to database format
        insert_data = []
        for dep in dependencies:
            insert_data.append({
                "scan_id": scan_id,
                "project_id": project_id,
                "name": dep.name,
                "version": dep.version,
                "type": dep.type,
                "file_source": dep.file_source,
            })
        
        # Bulk insert
        batch_size = 100
        total_inserted = 0
        
        for i in range(0, len(insert_data), batch_size):
            batch = insert_data[i:i + batch_size]
            result = supabase.table("scan_dependencies").insert(batch).execute()
            inserted_count = len(result.data) if result.data else 0
            total_inserted += inserted_count
            logger.info("Inserted dependency batch: %d dependencies", inserted_count)
        
        logger.info("Inserted dependencies: total=%d", total_inserted)
    except Exception as e:
        logger.error("Failed to insert dependencies: %s", e)
        # Check if it's a duplicate constraint error
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            logger.warning("Duplicate dependencies detected (constraint violation), continuing")
        else:
            # Don't raise - dependencies are important but not critical to scan success
            logger.warning("Continuing despite dependency insert failure")


def save_compliance_report(scan_id: str, project_id: str, compliance_report: ComplianceReport) -> Optional[str]:
    """
    Save compliance report to database.
    
    Args:
        scan_id: The scan ID this report belongs to
        project_id: The project ID
        compliance_report: The compliance report object
    
    Returns:
        The report_id if successful, None otherwise
    """
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    if not compliance_report:
        logger.warning("No compliance report to save")
        return None
    
    try:
        # Calculate score (percentage of passed rules, excluding NOT_APPLICABLE)
        total_evaluated = compliance_report.passed + compliance_report.failed + compliance_report.unknown
        if total_evaluated > 0:
            score = (compliance_report.passed / total_evaluated) * 100.0
        else:
            score = 0.0
        
        # Create summary string
        summary_parts = []
        if compliance_report.passed > 0:
            summary_parts.append(f"{compliance_report.passed} passed")
        if compliance_report.failed > 0:
            summary_parts.append(f"{compliance_report.failed} failed")
        if compliance_report.unknown > 0:
            summary_parts.append(f"{compliance_report.unknown} unknown")
        if compliance_report.not_applicable > 0:
            summary_parts.append(f"{compliance_report.not_applicable} not applicable")
        
        summary = ", ".join(summary_parts) if summary_parts else "No rules evaluated"
        
        # Insert compliance report
        report_data = {
            "scan_id": scan_id,
            "project_id": project_id,
            "score": round(score, 2),  # Store as decimal/float
            "summary": summary,
            "evaluated_at": compliance_report.evaluated_at,
            "total_rules": compliance_report.total_rules,
            "passed": compliance_report.passed,
            "failed": compliance_report.failed,
            "unknown": compliance_report.unknown,
            "not_applicable": compliance_report.not_applicable,
        }
        
        result = supabase.table("compliance_reports").insert(report_data).execute()
        
        if not result.data or len(result.data) == 0:
            raise ValueError("Failed to create compliance report record")
        
        report_id = result.data[0]["id"]
        logger.info("Created compliance report: report_id=%s, scan_id=%s, score=%.2f%%", 
                   report_id, scan_id, score)
        
        # Bulk insert rule results into compliance_details
        if compliance_report.rule_results:
            details_data = []
            for rule_result in compliance_report.rule_results:
                details_data.append({
                    "report_id": report_id,
                    "scan_id": scan_id,
                    "project_id": project_id,
                    "rule_id": rule_result.rule_id,
                    "status": rule_result.status,
                    "confidence": rule_result.confidence,
                    "reason": rule_result.reason,
                    "evaluated_at": rule_result.evaluated_at,
                })
            
            # Insert in batches
            batch_size = 100
            total_inserted = 0
            
            for i in range(0, len(details_data), batch_size):
                batch = details_data[i:i + batch_size]
                result = supabase.table("compliance_details").insert(batch).execute()
                inserted_count = len(result.data) if result.data else 0
                total_inserted += inserted_count
                logger.debug("Inserted compliance details batch: %d rules", inserted_count)
            
            logger.info("Inserted compliance details: total=%d rules", total_inserted)
        
        return report_id
        
    except Exception as e:
        logger.error("Failed to save compliance report: %s", e)
        # Check if it's a duplicate constraint error
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            logger.warning("Duplicate compliance report detected (constraint violation), continuing")
        else:
            # Don't raise - compliance report is important but not critical to scan success
            logger.warning("Continuing despite compliance report save failure")
        return None


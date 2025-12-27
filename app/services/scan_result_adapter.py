"""Adapter to convert internal scan/compliance output to ScanResultV1."""
from datetime import datetime, timezone
from typing import Optional, List
from app.core.logger import logger
from app.schemas.requests import ScanResponse, ComplianceReport, RuleResult
from app.schemas.scan_result_v1 import (
    ScanResultV1,
    RuleResultV1,
    EvidenceRefsV1,
    AdvisoryFindingV1
)
from app.services.compliance import load_rules_db


def convert_to_scan_result_v1(
    scan_response: ScanResponse,
    scan_id: Optional[str],
    compliance_report_id: Optional[str],
    repo_url: str,
    commit_sha: Optional[str],
    environment: str,
    project_id: Optional[str] = None
) -> ScanResultV1:
    """
    Convert internal ScanResponse and ComplianceReport to ScanResultV1.
    
    Args:
        scan_response: The scan response from execute_scan
        scan_id: UUID of the scan record (may be None for ephemeral scans)
        compliance_report_id: UUID of the compliance report (may be None)
        repo_url: Repository URL or identifier
        commit_sha: Git commit SHA (may be None)
        environment: Deployment environment
        project_id: Optional project ID
    
    Returns:
        ScanResultV1 object with verdict-first structure
    """
    # Generate scan_id if not provided (for ephemeral scans)
    if not scan_id:
        import uuid
        scan_id = str(uuid.uuid4())
        logger.debug("Generated ephemeral scan_id: %s", scan_id)
    
    # Use commit_sha or empty string
    commit_sha = commit_sha or ""
    
    # Get compliance report
    compliance_report = scan_response.compliance_report
    
    # Determine verdict: SHIP_BLOCKED if any rules failed, otherwise SHIP_ALLOWED
    # For Phase 0, we use simple logic: if any rule failed, block shipping
    verdict = "SHIP_ALLOWED"
    blocking_rules: List[str] = []
    
    if compliance_report:
        # Load rules DB to get rule metadata
        rules_db = load_rules_db()
        rules_by_id = {rule.get("rule_id"): rule for rule in rules_db.get("rules", [])}
        
        # Build rule_results and determine blocking rules
        rule_results_v1: List[RuleResultV1] = []
        
        for rule_result in compliance_report.rule_results:
            rule_id = rule_result.rule_id
            rule_metadata = rules_by_id.get(rule_id, {})
            
            # Determine if this rule is blocking
            # For Phase 0: a rule is blocking if it failed and has high/critical severity
            is_blocking = False
            if rule_result.status == "FAIL":
                severity = rule_metadata.get("severity", {})
                overall_severity = severity.get("overall", "medium")
                # Block if severity is high or critical
                if overall_severity in ["high", "critical"]:
                    is_blocking = True
                    blocking_rules.append(rule_id)
            
            # Get rule title and description from metadata
            title = rule_metadata.get("title", rule_id)
            description = rule_metadata.get("description_short", rule_metadata.get("description_long", ""))
            
            # Convert status (remove UNKNOWN, map to NOT_APPLICABLE if needed)
            status = rule_result.status
            if status == "UNKNOWN":
                # For Phase 0, treat UNKNOWN as NOT_APPLICABLE
                status = "NOT_APPLICABLE"
            
            # Build evidence dict
            evidence_dict = {
                "reason": rule_result.reason,
                "confidence": rule_result.confidence,
                "evaluated_at": rule_result.evaluated_at,
            }
            
            rule_results_v1.append(
                RuleResultV1(
                    rule_id=rule_id,
                    title=title,
                    description=description,
                    status=status,
                    is_blocking=is_blocking,
                    evidence=evidence_dict
                )
            )
        
        # Set verdict based on blocking rules
        if blocking_rules:
            verdict = "SHIP_BLOCKED"
    else:
        # No compliance report - default to SHIP_ALLOWED with empty rule_results
        rule_results_v1 = []
        logger.warning("No compliance report available, verdict set to SHIP_ALLOWED")
    
    # Build evidence refs
    evidence_refs = EvidenceRefsV1(
        scan_id=scan_id,
        dependency_snapshot_id=scan_id,  # Use scan_id if snapshot not available
        compliance_report_id=compliance_report_id
    )
    
    # Convert findings to advisory_findings (non-blocking recommendations)
    advisory_findings: List[AdvisoryFindingV1] = []
    for finding in scan_response.findings:
        # Only include non-critical findings as advisories
        if finding.severity in ["low", "info"]:
            # Extract file path and line numbers from evidence
            file_path = None
            line_start = None
            line_end = None
            
            if finding.evidence:
                ev0 = finding.evidence[0]
                file_path = ev0.file
                if ev0.lines:
                    # Parse line numbers from "10-18" format
                    try:
                        parts = ev0.lines.split("-")
                        line_start = int(parts[0].strip())
                        if len(parts) > 1:
                            line_end = int(parts[1].strip())
                        else:
                            line_end = line_start
                    except (ValueError, AttributeError):
                        pass
            
            advisory_findings.append(
                AdvisoryFindingV1(
                    category=finding.category or "other",
                    message=finding.summary,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    suggested_fix=finding.recommendation
                )
            )
    
    # Create ScanResultV1
    return ScanResultV1(
        scan_id=scan_id,
        project_id=project_id,
        repo_url=repo_url,
        commit_sha=commit_sha,
        environment=environment,
        evaluated_at=datetime.now(timezone.utc),
        verdict=verdict,
        blocking_rules=blocking_rules,
        rule_results=rule_results_v1,
        evidence_refs=evidence_refs,
        advisory_findings=advisory_findings
    )


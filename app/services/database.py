"""Database client for Supabase operations."""
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from fastapi import HTTPException
from app.core.config import supabase
from app.core.logger import logger


class DatabaseClient:
    """Client for interacting with Supabase database."""
    
    def __init__(self):
        """Initialize the database client."""
        if not supabase:
            raise ValueError("Supabase client not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.")
        self.client = supabase
    
    def create_scan(
        self, 
        repo_id: str, 
        repo_name: str,
        project_id: Optional[str] = None,
        commit_hash: Optional[str] = None,
        installation_id: Optional[int] = None
    ) -> str:
        """
        Create a new scan record.
        
        Args:
            repo_id: UUID of the repository to scan
            repo_name: Repository name (owner/repo format)
            project_id: Optional project ID (will be fetched from repo if not provided)
            commit_hash: Optional Git commit hash to scan
            installation_id: Optional GitHub installation ID
        
        Returns:
            scan_id: UUID of the created scan record
        
        Raises:
            HTTPException: If Supabase is not configured or creation fails
            ValueError: If repo_id is invalid or repository doesn't exist
        """
        try:
            # Verify repository exists and get project_id if not provided
            repo_result = self.client.table("repositories").select("id, project_id").eq("id", repo_id).execute()
            
            if not repo_result.data or len(repo_result.data) == 0:
                raise ValueError(f"Repository with id {repo_id} not found")
            
            repository = repo_result.data[0]
            if not project_id:
                project_id = repository.get("project_id")
            
            # Create scan record
            scan_data = {
                "repository_id": repo_id,
                "project_id": project_id,
                "repo_name": repo_name,
                "status": "queued",
                "commit_hash": commit_hash,
                "installation_id": installation_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            
            result = self.client.table("scans").insert(scan_data).execute()
            
            if not result.data or len(result.data) == 0:
                raise ValueError("Failed to create scan record")
            
            scan_id = result.data[0]["id"]
            logger.info("Created scan: scan_id=%s, repo_id=%s, repo_name=%s, commit_hash=%s", 
                       scan_id, repo_id, repo_name, commit_hash)
            
            return scan_id
            
        except ValueError as e:
            logger.error("Validation error creating scan: %s", e)
            raise
        except Exception as e:
            logger.error("Failed to create scan: %s", e)
            raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")
    
    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        total_files: Optional[int] = None,
        analyzed_files: Optional[int] = None,
        duration_ms: Optional[int] = None,
        error: Optional[str] = None,
        verdict: Optional[str] = None,
        raw_results: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Update scan status and metadata.
        
        Args:
            scan_id: UUID of the scan to update
            status: Status string ('queued', 'processing', 'completed', 'failed')
            total_files: Optional total files count
            analyzed_files: Optional analyzed files count
            duration_ms: Optional duration in milliseconds
            error: Optional error message
            verdict: Optional verdict ('SHIP_ALLOWED', 'SHIP_BLOCKED')
            raw_results: Optional raw results JSONB
        """
        try:
            update_data = {
                "status": status,
            }
            
            if total_files is not None:
                update_data["total_files"] = total_files
            if analyzed_files is not None:
                update_data["analyzed_files"] = analyzed_files
            if duration_ms is not None:
                update_data["duration_ms"] = duration_ms
            if error is not None:
                update_data["error"] = error
            if verdict is not None:
                if verdict not in ["SHIP_ALLOWED", "SHIP_BLOCKED"]:
                    raise ValueError(f"Invalid verdict: {verdict}")
                update_data["verdict"] = verdict
            if raw_results is not None:
                update_data["raw_results"] = raw_results
            
            if status == "completed" or status == "failed":
                update_data["completed_at"] = datetime.now(timezone.utc).isoformat()
            
            self.client.table("scans").update(update_data).eq("id", scan_id).execute()
            logger.info("Updated scan status: scan_id=%s, status=%s", scan_id, status)
            
        except Exception as e:
            logger.error("Failed to update scan status: %s", e)
            raise HTTPException(status_code=500, detail=f"Failed to update scan status: {str(e)}")
    
    def update_scan_verdict(
        self, 
        scan_id: str, 
        verdict: str, 
        results: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Update scan with verdict and results.
        
        Args:
            scan_id: UUID of the scan to update
            verdict: Verdict string (e.g., 'SHIP_ALLOWED', 'SHIP_BLOCKED')
            results: Optional dictionary containing scan results
        """
        if verdict not in ["SHIP_ALLOWED", "SHIP_BLOCKED"]:
            raise ValueError(f"Invalid verdict: {verdict}. Must be 'SHIP_ALLOWED' or 'SHIP_BLOCKED'")
        
        try:
            update_data = {
                "status": "completed",
                "verdict": verdict,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
            
            if results:
                if "raw_results" in results:
                    update_data["raw_results"] = results["raw_results"]
            
            self.client.table("scans").update(update_data).eq("id", scan_id).execute()
            logger.info("Updated scan verdict: scan_id=%s, verdict=%s", scan_id, verdict)
            
        except Exception as e:
            logger.error("Failed to update scan verdict: %s", e)
            raise HTTPException(status_code=500, detail=f"Failed to update scan verdict: {str(e)}")
    
    def save_rule_results(
        self,
        scan_id: str,
        rule_results: List[Dict[str, Any]]
    ) -> None:
        """
        Save rule evaluation results to rule_results table.
        
        Args:
            scan_id: UUID of the scan
            rule_results: List of rule result dictionaries with keys:
                - rule_id: str
                - status: str ('PASS', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE')
                - confidence: float (0.0-1.0)
                - reason: Optional[str]
                - evidence: Optional[Dict[str, Any]]
                - evaluated_at: str (ISO format)
        """
        if not rule_results:
            return
        
        try:
            records = []
            for result in rule_results:
                record = {
                    "scan_id": scan_id,
                    "rule_id": result.get("rule_id"),
                    "status": result.get("status"),
                    "confidence": result.get("confidence"),
                    "reason": result.get("reason"),
                    "evidence": result.get("evidence", {}),
                    "evaluated_at": result.get("evaluated_at", datetime.now(timezone.utc).isoformat()),
                }
                records.append(record)
            
            if records:
                self.client.table("rule_results").insert(records).execute()
                logger.info("Saved %d rule results for scan_id=%s", len(records), scan_id)
            
        except Exception as e:
            logger.error("Failed to save rule results: %s", e)
            raise HTTPException(status_code=500, detail=f"Failed to save rule results: {str(e)}")
    
    def save_compliance_report(
        self,
        scan_id: str,
        project_id: str,
        regulation: str,
        verdict: str,
        score: Optional[float] = None,
        total_rules: Optional[int] = None,
        passed: Optional[int] = None,
        failed: Optional[int] = None,
        unknown: Optional[int] = None,
        not_applicable: Optional[int] = None,
        evaluated_at: Optional[str] = None,
        rule_results: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """
        Save compliance report and related data.
        
        Args:
            scan_id: UUID of the scan
            project_id: UUID of the project
            regulation: Regulation name (e.g., 'CRA', 'AI_ACT', 'COMBINED')
            verdict: Verdict ('SHIP_ALLOWED', 'SHIP_BLOCKED')
            score: Optional compliance score (0-100)
            total_rules: Optional total rules count
            passed: Optional passed rules count
            failed: Optional failed rules count
            unknown: Optional unknown rules count
            not_applicable: Optional not applicable rules count
            evaluated_at: Optional ISO timestamp (defaults to now)
            rule_results: Optional list of rule results to save
        
        Returns:
            report_id: UUID of the created compliance report
        """
        try:
            if verdict not in ["SHIP_ALLOWED", "SHIP_BLOCKED"]:
                raise ValueError(f"Invalid verdict: {verdict}")
            
            evaluated_at_str = evaluated_at or datetime.now(timezone.utc).isoformat()
            
            # Create compliance report
            report_data = {
                "scan_id": scan_id,
                "project_id": project_id,
                "regulation": regulation,
                "verdict": verdict,
                "evaluated_at": evaluated_at_str,
            }
            
            if score is not None:
                report_data["score"] = score
            if total_rules is not None:
                report_data["total_rules"] = total_rules
            if passed is not None:
                report_data["passed"] = passed
            if failed is not None:
                report_data["failed"] = failed
            if unknown is not None:
                report_data["unknown"] = unknown
            if not_applicable is not None:
                report_data["not_applicable"] = not_applicable
            
            result = self.client.table("compliance_reports").insert(report_data).execute()
            
            if not result.data or len(result.data) == 0:
                raise ValueError("Failed to create compliance report")
            
            report_id = result.data[0]["id"]
            logger.info("Created compliance report: report_id=%s, scan_id=%s, regulation=%s, verdict=%s",
                       report_id, scan_id, regulation, verdict)
            
            # Save rule results if provided
            if rule_results:
                self.save_rule_results(scan_id, rule_results)
                
                # Also save compliance details (rule-level results linked to report)
                self.save_compliance_details(report_id, scan_id, rule_results, evaluated_at_str)
            
            return report_id
            
        except Exception as e:
            logger.error("Failed to save compliance report: %s", e)
            raise HTTPException(status_code=500, detail=f"Failed to save compliance report: {str(e)}")
    
    def save_compliance_details(
        self,
        report_id: str,
        scan_id: str,
        rule_results: List[Dict[str, Any]],
        evaluated_at: str
    ) -> None:
        """
        Save compliance details (rule-level results linked to report).
        
        Args:
            report_id: UUID of the compliance report
            scan_id: UUID of the scan
            rule_results: List of rule result dictionaries
            evaluated_at: ISO timestamp
        """
        if not rule_results:
            return
        
        try:
            records = []
            for result in rule_results:
                record = {
                    "report_id": report_id,
                    "scan_id": scan_id,
                    "rule_id": result.get("rule_id"),
                    "status": result.get("status"),
                    "confidence": result.get("confidence"),
                    "reason": result.get("reason"),
                    "evaluated_at": evaluated_at,
                }
                records.append(record)
            
            if records:
                self.client.table("compliance_details").insert(records).execute()
                logger.info("Saved %d compliance details for report_id=%s", len(records), report_id)
            
        except Exception as e:
            logger.error("Failed to save compliance details: %s", e)
            # Non-fatal - log but don't raise
    
    def save_ai_systems(
        self,
        scan_id: str,
        repository_id: str,
        ai_systems: List[Dict[str, Any]]
    ) -> None:
        """
        Save AI system classifications.
        
        Args:
            scan_id: UUID of the scan
            repository_id: UUID of the repository
            ai_systems: List of AI system dictionaries with keys:
                - name: Optional[str]
                - classification: str ('prohibited', 'high_risk', 'limited_risk', 'minimal_risk', 'unknown')
                - frameworks: Optional[List[str]]
                - use_case: Optional[str]
                - confidence: Optional[float] (0.0-1.0)
        """
        if not ai_systems:
            return
        
        try:
            records = []
            for ai_system in ai_systems:
                record = {
                    "scan_id": scan_id,
                    "repository_id": repository_id,
                    "name": ai_system.get("name"),
                    "classification": ai_system.get("classification"),
                    "frameworks": ai_system.get("frameworks", []),
                    "use_case": ai_system.get("use_case"),
                    "confidence": ai_system.get("confidence"),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                }
                records.append(record)
            
            if records:
                self.client.table("ai_systems").insert(records).execute()
                logger.info("Saved %d AI systems for scan_id=%s", len(records), scan_id)
            
        except Exception as e:
            logger.error("Failed to save AI systems: %s", e)
            # Non-fatal - log but don't raise
    
    def save_model_cards(
        self,
        ai_system_id: str,
        model_cards: List[Dict[str, Any]]
    ) -> None:
        """
        Save model card data.
        
        Args:
            ai_system_id: UUID of the AI system
            model_cards: List of model card dictionaries with keys:
                - file_path: Optional[str]
                - content: Optional[Dict[str, Any]]
                - validation_status: Optional[str] ('valid', 'invalid', 'incomplete', 'not_found')
                - validation_errors: Optional[List[str]]
        """
        if not model_cards:
            return
        
        try:
            records = []
            for card in model_cards:
                record = {
                    "ai_system_id": ai_system_id,
                    "file_path": card.get("file_path"),
                    "content": card.get("content", {}),
                    "validation_status": card.get("validation_status"),
                    "validation_errors": card.get("validation_errors", []),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                records.append(record)
            
            if records:
                self.client.table("model_cards").insert(records).execute()
                logger.info("Saved %d model cards for ai_system_id=%s", len(records), ai_system_id)
            
        except Exception as e:
            logger.error("Failed to save model cards: %s", e)
            # Non-fatal - log but don't raise
    
    # Query methods (Section 3.4.2 Repository Pattern)
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan by ID."""
        try:
            result = self.client.table("scans").select("*").eq("id", scan_id).execute()
            if result.data and len(result.data) > 0:
                return result.data[0]
            return None
        except Exception as e:
            logger.error("Failed to get scan: %s", e)
            return None
    
    def get_scans_by_project(self, project_id: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get scans for a project."""
        try:
            query = self.client.table("scans").select("*").eq("project_id", project_id).order("created_at", desc=True)
            if limit:
                query = query.limit(limit)
            result = query.execute()
            return result.data or []
        except Exception as e:
            logger.error("Failed to get scans by project: %s", e)
            return []
    
    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get rule by rule_id."""
        try:
            result = self.client.table("rules").select("*").eq("rule_id", rule_id).execute()
            if result.data and len(result.data) > 0:
                return result.data[0]
            return None
        except Exception as e:
            logger.error("Failed to get rule: %s", e)
            return None
    
    def get_rules_by_regulation(self, regulation: str) -> List[Dict[str, Any]]:
        """Get rules by regulation."""
        try:
            result = self.client.table("rules").select("*").eq("regulation", regulation).execute()
            return result.data or []
        except Exception as e:
            logger.error("Failed to get rules by regulation: %s", e)
            return []
    
    def get_all_rules(self) -> List[Dict[str, Any]]:
        """Get all rules."""
        try:
            result = self.client.table("rules").select("*").execute()
            return result.data or []
        except Exception as e:
            logger.error("Failed to get all rules: %s", e)
            return []
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get compliance report by ID."""
        try:
            result = self.client.table("compliance_reports").select("*").eq("id", report_id).execute()
            if result.data and len(result.data) > 0:
                return result.data[0]
            return None
        except Exception as e:
            logger.error("Failed to get report: %s", e)
            return None
    
    def get_reports_by_project(self, project_id: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get compliance reports for a project."""
        try:
            query = self.client.table("compliance_reports").select("*").eq("project_id", project_id).order("evaluated_at", desc=True)
            if limit:
                query = query.limit(limit)
            result = query.execute()
            return result.data or []
        except Exception as e:
            logger.error("Failed to get reports by project: %s", e)
            return []


# Singleton instance
_db_client: Optional[DatabaseClient] = None


def get_db_client() -> DatabaseClient:
    """
    Get or create the database client instance.
    
    Returns:
        DatabaseClient instance
    """
    global _db_client
    if _db_client is None:
        _db_client = DatabaseClient()
    return _db_client


# Backward compatibility wrapper functions for scan_executor.py

def create_scan_record(
    project_id: str,
    repo_name: str,
    installation_id: Optional[int] = None,
    commit_hash: Optional[str] = None,
    user_id: Optional[str] = None
) -> Optional[str]:
    """
    Create a scan record (backward compatibility wrapper).
    
    Note: This requires a repository to exist. For full functionality, use DatabaseClient directly.
    Returns None if Supabase is not configured.
    """
    if not supabase:
        return None
    
    try:
        # Try to find repository by repo_name (owner/repo format)
        # This is a simplified implementation - in production, you'd want to create/get repo first
        logger.warning("create_scan_record: Simplified implementation - requires repository to exist")
        return None
    except Exception as e:
        logger.error("Failed to create scan record: %s", e)
        return None


def update_scan_success(
    scan_id: str,
    duration_ms: int,
    verdict: str = "SHIP_ALLOWED",
    results: Optional[Dict[str, Any]] = None,
    total_files: Optional[int] = None,
    analyzed_files: Optional[int] = None,
    commit_hash: Optional[str] = None
) -> None:
    """Update scan as successful (backward compatibility wrapper)."""
    if not supabase:
        return
    
    try:
        db = get_db_client()
        db.update_scan_status(
            scan_id=scan_id,
            status="completed",
            total_files=total_files,
            analyzed_files=analyzed_files,
            duration_ms=duration_ms,
            verdict=verdict,
            raw_results=results
        )
    except Exception as e:
        logger.error("Failed to update scan success: %s", e)


def update_scan_failure(
    scan_id: str,
    duration_ms: int,
    error_message: str
) -> None:
    """Update scan as failed (backward compatibility wrapper)."""
    if not supabase:
        return
    
    try:
        db = get_db_client()
        db.update_scan_status(
            scan_id=scan_id,
            status="failed",
            duration_ms=duration_ms,
            error=error_message
        )
    except Exception as e:
        logger.error("Failed to update scan failure: %s", e)


def update_project_last_scan(project_id: str, scan_id: Optional[str] = None) -> None:
    """Update project's last scan (backward compatibility wrapper)."""
    if not supabase:
        return
    
    try:
        update_data = {}
        if scan_id:
            update_data["last_scan_id"] = scan_id
        update_data["last_scan_at"] = datetime.now(timezone.utc).isoformat()
        supabase.table("projects").update(update_data).eq("id", project_id).execute()
    except Exception as e:
        logger.error("Failed to update project last scan: %s", e)


def insert_findings(scan_id: str, project_id: str, findings: List[Dict[str, Any]]) -> None:
    """Insert findings (backward compatibility wrapper)."""
    if not supabase:
        return
    
    try:
        records = []
        for finding in findings:
            # Convert Finding model to database record format
            record = {
                "scan_id": scan_id,
                "project_id": project_id,
                "severity": finding.get("severity", "info"),
                "category": finding.get("category", "other"),
                "title": finding.get("title", ""),
                "summary": finding.get("summary", ""),
                "details": finding.get("details", ""),
                "file_path": finding.get("file_path"),
                "line_number": finding.get("line_number"),
                "code_snippet": finding.get("code_snippet"),
                "recommendation": finding.get("recommendation", ""),
                "confidence": finding.get("confidence", 0.0),
                "fingerprint": finding.get("fingerprint"),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            records.append(record)
        
        if records:
            supabase.table("findings").insert(records).execute()
            logger.info("Inserted %d findings for scan_id=%s", len(records), scan_id)
    except Exception as e:
        logger.error("Failed to insert findings: %s", e)


def bulk_insert_dependencies(scan_id: str, project_id: str, dependencies: List[Dict[str, Any]]) -> None:
    """Bulk insert dependencies (backward compatibility wrapper)."""
    if not supabase:
        return
    
    try:
        records = []
        for dep in dependencies:
            # Convert Dependency model to database record format
            record = {
                "scan_id": scan_id,
                "project_id": project_id,
                "name": dep.get("name", ""),
                "version": dep.get("version"),
                "type": dep.get("type", ""),
                "file_source": dep.get("file_source", ""),
                "license": dep.get("license"),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            records.append(record)
        
        if records:
            # FIX: Use scan_dependencies table instead of dependencies
            supabase.table("scan_dependencies").insert(records).execute()
            logger.info("Inserted %d dependencies for scan_id=%s", len(records), scan_id)
    except Exception as e:
        logger.error("Failed to insert dependencies: %s", e)


def save_compliance_report(
    scan_id: str,
    project_id: str,
    compliance_report: Any  # ComplianceReport model
) -> Optional[str]:
    """
    Save compliance report (backward compatibility wrapper).
    
    Args:
        scan_id: UUID of the scan
        project_id: UUID of the project
        compliance_report: ComplianceReport Pydantic model
    
    Returns:
        report_id: UUID of the created compliance report, or None if failed
    """
    if not supabase:
        return None
    
    try:
        db = get_db_client()
        
        # Extract regulation from rule_results (default to 'CRA' if not specified)
        regulation = "CRA"  # Default
        if compliance_report.rule_results:
            # Try to infer regulation from rule_ids (e.g., 'CRA-BASE-001' -> 'CRA')
            first_rule_id = compliance_report.rule_results[0].rule_id if compliance_report.rule_results else None
            if first_rule_id:
                if first_rule_id.startswith("CRA-"):
                    regulation = "CRA"
                elif first_rule_id.startswith("AI-ACT-") or first_rule_id.startswith("AI_ACT-"):
                    regulation = "AI_ACT"
        
        # Convert rule_results to dict format
        rule_results_dict = []
        for rule_result in compliance_report.rule_results:
            rule_results_dict.append({
                "rule_id": rule_result.rule_id,
                "status": rule_result.status,
                "confidence": rule_result.confidence,
                "reason": rule_result.reason,
                "evidence": {},  # RuleResult in requests.py doesn't have evidence
                "evaluated_at": compliance_report.evaluated_at,
            })
        
        # Calculate score if possible (simplified - could be enhanced)
        score = None
        if compliance_report.total_rules > 0:
            score = (compliance_report.passed / compliance_report.total_rules) * 100
        
        # Determine verdict from rule results
        verdict = "SHIP_ALLOWED"
        # Check if any blocking rules failed
        # Note: This is simplified - proper verdict logic is in VerdictGenerator
        
        report_id = db.save_compliance_report(
            scan_id=scan_id,
            project_id=project_id,
            regulation=regulation,
            verdict=verdict,  # Will be updated by VerdictGenerator later
            score=score,
            total_rules=compliance_report.total_rules,
            passed=compliance_report.passed,
            failed=compliance_report.failed,
            unknown=compliance_report.unknown,
            not_applicable=compliance_report.not_applicable,
            evaluated_at=compliance_report.evaluated_at,
            rule_results=rule_results_dict
        )
        
        return report_id
        
    except Exception as e:
        logger.error("Failed to save compliance report: %s", e)
        return None


def get_or_create_project(user_id: Optional[str] = None, repo_url: Optional[str] = None) -> Optional[str]:
    """Get or create project (backward compatibility wrapper)."""
    if not supabase:
        return None
    
    try:
        # This is a simplified implementation
        # In production, you'd want proper project creation logic
        logger.warning("get_or_create_project: Simplified implementation")
        return None
    except Exception as e:
        logger.error("Failed to get or create project: %s", e)
        return None

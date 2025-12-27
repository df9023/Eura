"""Core scan execution logic extracted for reuse across endpoints."""
import time
import uuid
from typing import List, Optional, Dict, Any, Tuple, Literal
from datetime import datetime, timezone
from fastapi import HTTPException
from app.core.config import MAX_FILES, MAX_FILE_BYTES, supabase
from app.core.logger import logger
from app.models.domain import Finding, Evidence
from app.schemas.requests import ScanResponse, ComplianceReport, RuleResult, Dependency
from app.schemas.scan_result_v1 import (
    ScanResultV1,
    RuleResultV1,
    EvidenceRefsV1,
    AdvisoryFindingV1
)
from app.services.compliance import load_rules_db


def convert_scan_result_v1_to_scan_response(scan_result: ScanResultV1) -> ScanResponse:
    """
    Convert ScanResultV1 back to ScanResponse for legacy endpoint compatibility.
    
    This is a temporary adapter for backward compatibility with the /scan-repo endpoint.
    Phase 0+ endpoints should use ScanResultV1 directly.
    
    Args:
        scan_result: ScanResultV1 object
    
    Returns:
        ScanResponse object for legacy API compatibility
    """
    # Reconstruct findings from advisory_findings (limited - only low/info severity)
    findings: List[Finding] = []
    for advisory in scan_result.advisory_findings:
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                title=advisory.message,
                severity="low" if advisory.category != "other" else "info",
                confidence=0.6,
                summary=advisory.message,
                details=advisory.message,
                evidence=[Evidence(file=advisory.file_path or "")] if advisory.file_path else [],
                recommendation=advisory.suggested_fix or "",
                category=advisory.category
            )
        )
    
    # Reconstruct dependencies (empty for now - would need to be stored separately)
    dependencies: List[Dependency] = []
    
    # Reconstruct compliance report from rule_results
    compliance_report = None
    if scan_result.rule_results:
        rule_results = []
        for rule_result_v1 in scan_result.rule_results:
            # Map status back (NOT_APPLICABLE stays, but we lost UNKNOWN distinction)
            status = rule_result_v1.status
            if status == "NOT_APPLICABLE":
                status = "NOT_APPLICABLE"
            
            rule_results.append(
                RuleResult(
                    rule_id=rule_result_v1.rule_id,
                    status=status,
                    confidence=rule_result_v1.evidence.get("confidence", 0.5),
                    reason=rule_result_v1.evidence.get("reason"),
                    evaluated_at=rule_result_v1.evidence.get("evaluated_at", scan_result.evaluated_at.isoformat())
                )
            )
        
        compliance_report = ComplianceReport(
            rule_results=rule_results,
            evaluated_at=scan_result.evaluated_at.isoformat(),
            total_rules=len(rule_results),
            passed=sum(1 for r in rule_results if r.status == "PASS"),
            failed=sum(1 for r in rule_results if r.status == "FAIL"),
            unknown=0,  # Lost in conversion
            not_applicable=sum(1 for r in rule_results if r.status == "NOT_APPLICABLE")
        )
    
    return ScanResponse(
        success=True,
        repo_name=scan_result.repo_url,
        total_files=0,  # Lost in conversion
        analyzed_files=0,  # Lost in conversion
        findings=findings,
        commit_hash=scan_result.commit_sha or None,
        dependencies=dependencies,
        compliance_report=compliance_report
    )
from app.services.github import (
    get_github_client,
    list_repo_files,
    read_repo_file,
    is_text_file,
    should_skip_path,
    get_repo_commit_hash,
)
from app.services.llm import analyze_file_with_llm
from app.services.dependencies import extract_dependencies
from app.services.compliance import evaluate_repo
from app.services.database import (
    create_scan_record,
    update_scan_success,
    update_scan_failure,
    update_project_last_scan,
    insert_findings,
    bulk_insert_dependencies,
    save_compliance_report,
)


async def execute_scan(
    repo_name: str,
    installation_id: Optional[int] = None,
    project_id: Optional[str] = None,
    max_files: Optional[int] = None,
    repo_url: Optional[str] = None,
    environment: Literal["dev", "staging", "production", "eu-production"] = "dev"
) -> ScanResultV1:
    """
    Execute a repository scan and return ScanResultV1 (Phase 0 API contract object).
    
    This is the core orchestrator that:
    - Fetches/clones the repository
    - Parses dependencies
    - Evaluates compliance rules
    - Persists to Supabase
    - Returns a verdict-first ScanResultV1 object
    
    Args:
        repo_name: Repository name in format "owner/repo"
        installation_id: Optional GitHub App installation ID (required for private repos, 
                        None for public repos uses unauthenticated or GITHUB_TOKEN)
        project_id: Optional project ID for persistence
        max_files: Optional max files to scan (defaults to MAX_FILES)
        repo_url: Repository URL or identifier (defaults to repo_name)
        environment: Deployment environment (defaults to "dev")
    
    Returns:
        ScanResultV1 object with verdict-first structure
    
    Raises:
        HTTPException: For invalid inputs or scan failures
    """
    scan_id: Optional[str] = None
    compliance_report_id: Optional[str] = None
    start_time = time.time()
    
    try:
        logger.info("Starting scan: project_id=%s, repo_name=%s", project_id, repo_name)
        
        if "/" not in repo_name:
            raise HTTPException(status_code=400, detail="repo_name must be in format 'owner/repo'")

        max_files = max_files or MAX_FILES

        # Public mode: installation_id is None, use public/unauthenticated access
        # GitHub App mode: installation_id provided, use app authentication
        if installation_id is None:
            logger.info("Using public mode: no installation_id provided")
        else:
            logger.info("Using GitHub App mode: installation_id=%d", installation_id)
        
        github_client = get_github_client(installation_id)
        
        try:
            logger.info("Fetching repository: %s", repo_name)
            repo = github_client.get_repo(repo_name)
            logger.info("Repository fetched successfully")
        except Exception as e:
            # Handle 404 (repo not found) gracefully
            error_msg = str(e)
            if "404" in error_msg or "Not Found" in error_msg:
                if project_id and scan_id and supabase:
                    duration_ms = int((time.time() - start_time) * 1000)
                    try:
                        update_scan_failure(scan_id, duration_ms, f"Repository not found: {repo_name}")
                    except Exception:
                        pass
                raise HTTPException(
                    status_code=404, 
                    detail=f"Repository not found or not accessible: {repo_name}. If this is a private repo, provide installation_id."
                )
            else:
                # Other errors (rate limits, auth issues, etc.)
                if project_id and scan_id and supabase:
                    duration_ms = int((time.time() - start_time) * 1000)
                    try:
                        update_scan_failure(scan_id, duration_ms, f"Repo access error: {e}")
                    except Exception:
                        pass
                raise HTTPException(status_code=500, detail=f"Failed to access repository: {e}")

        # Get commit hash (HEAD)
        commit_hash = get_repo_commit_hash(repo)
        if commit_hash:
            logger.info("Repository commit hash: %s", commit_hash)
        else:
            logger.warning("Could not determine commit hash")
            commit_hash = None

        # Create scan record (only if project_id is provided and Supabase is configured)
        if project_id and supabase:
            try:
                scan_id = create_scan_record(
                    project_id=project_id,
                    repo_name=repo_name,
                    installation_id=installation_id,
                    commit_hash=commit_hash
                )
                logger.info("Created scan record: scan_id=%s", scan_id)
            except Exception as e:
                logger.warning("Failed to create scan record (continuing without persistence): %s", e)
                scan_id = None
        else:
            if not project_id:
                logger.info("Ephemeral scan: project_id not provided, scan will not be persisted")
            elif not supabase:
                logger.warning("Supabase not configured: scan will not be persisted")
            scan_id = None

        # List all files
        logger.info("Listing repository files (max_files=%d)", max_files)
        try:
            all_files = list_repo_files(repo, max_files)
        except Exception as e:
            if project_id and scan_id and supabase:
                duration_ms = int((time.time() - start_time) * 1000)
                try:
                    update_scan_failure(scan_id, duration_ms, f"Failed to fetch repo contents: {e}")
                except Exception:
                    pass
            raise HTTPException(status_code=500, detail=f"Failed to fetch repo contents: {e}")

        # Filter to text files
        text_files = [p for p in all_files if is_text_file(p) and not should_skip_path(p)]
        text_files = text_files[:max_files]
        
        logger.info("Files to analyze: total=%d, text=%d, will analyze=%d", 
                   len(all_files), len(text_files), min(len(text_files), max_files))

        findings: List[Finding] = []
        dependencies: List[Dependency] = []
        files_processed = 0
        files_failed = 0

        for file_path in text_files:
            try:
                content = read_repo_file(repo, file_path)
                
                if content is None:
                    # File was skipped due to size
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            title="File skipped due to size limit",
                            severity="info",
                            confidence=1.0,
                            summary=f"Skipped {file_path} because it exceeds size limit.",
                            details=f"Limit: {MAX_FILE_BYTES} bytes.",
                            evidence=[Evidence(file=file_path)],
                            recommendation="Increase MAX_FILE_BYTES if you want to scan large files.",
                            category="other",
                        )
                    )
                    continue

                # Check if this is a dependency manifest file
                file_lower = file_path.lower()
                if any(file_lower.endswith(manifest) for manifest in ["requirements.txt", "package.json", "pyproject.toml"]):
                    logger.debug("Extracting dependencies from: %s", file_path)
                    try:
                        deps = extract_dependencies(file_path, content)
                        dep_objects = [Dependency(**dep) for dep in deps]
                        dependencies.extend(dep_objects)
                        
                        # Save dependencies immediately (even if LLM scan fails later)
                        if project_id and supabase and scan_id and dep_objects:
                            try:
                                bulk_insert_dependencies(
                                    scan_id=scan_id,
                                    project_id=project_id,
                                    dependencies=dep_objects
                                )
                                logger.debug("Saved %d dependencies from %s", len(dep_objects), file_path)
                            except Exception as e:
                                logger.warning("Failed to save dependencies from %s (non-fatal): %s", file_path, str(e)[:200])
                    except Exception as e:
                        logger.warning("Failed to extract dependencies from %s: %s", file_path, str(e)[:200])

                logger.debug("Analyzing file: %s", file_path)
                file_findings = await analyze_file_with_llm(file_path, content)
                findings.extend(file_findings)
                files_processed += 1
                
                if len(file_findings) > 0:
                    logger.debug("Found %d issues in %s", len(file_findings), file_path)

            except Exception as e:
                files_failed += 1
                logger.warning("Failed processing file %s: %s", file_path, str(e)[:200])
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title="File processing error",
                        severity="info",
                        confidence=0.6,
                        summary=f"Could not analyze {file_path}.",
                        details=str(e)[:1000],
                        evidence=[Evidence(file=file_path)],
                        recommendation="Check repository permissions and file encoding.",
                        category="other",
                    )
                )
        
        logger.info("File analysis complete: processed=%d, failed=%d, findings=%d, dependencies=%d", 
                   files_processed, files_failed, len(findings), len(dependencies))

        # Insert findings into database (only if project_id is provided and Supabase is configured)
        if project_id and supabase:
            logger.info("Inserting findings into database: count=%d", len(findings))
            try:
                insert_findings(scan_id=scan_id, project_id=project_id, findings=findings)
            except Exception as e:
                logger.error("Failed to insert findings (non-fatal): %s", e)
        else:
            if not project_id:
                logger.info("Ephemeral scan: skipping findings persistence (no project_id)")
            else:
                logger.warning("Skipping findings persistence: Supabase not configured")

        # Update scan record on success (only if project_id is provided and Supabase is configured)
        duration_ms = int((time.time() - start_time) * 1000)
        if project_id and supabase:
            try:
                update_scan_success(
                    scan_id=scan_id,
                    duration_ms=duration_ms,
                    total_files=len(all_files),
                    analyzed_files=len(text_files),
                    commit_hash=commit_hash
                )
                update_project_last_scan(project_id)
            except Exception as e:
                logger.error("Failed to update scan status (non-fatal): %s", e)

        if project_id:
            logger.info("Scan completed successfully: scan_id=%s, duration_ms=%d, findings=%d", 
                       scan_id, duration_ms, len(findings))
        else:
            logger.info("Ephemeral scan completed successfully: duration_ms=%d, findings=%d", 
                       duration_ms, len(findings))

        # Evaluate compliance rules
        compliance_report = None
        try:
            logger.info("Evaluating compliance rules...")
            compliance_report_dict = await evaluate_repo(
                findings=findings,
                dependencies=dependencies,
                repo_files=all_files,  # Use all_files to check for documentation files
                repo=repo,
                read_file_func=read_repo_file
            )
            # Phase 0: Set evaluated_at once at the end of orchestration, reused in persistence writes
            # Use the timestamp from compliance evaluation as the single source of truth
            evaluated_at_str = compliance_report_dict.get("evaluated_at")
            if evaluated_at_str:
                # Parse ISO format string to datetime
                try:
                    if evaluated_at_str.endswith("Z"):
                        evaluated_at_str = evaluated_at_str[:-1] + "+00:00"
                    evaluated_at = datetime.fromisoformat(evaluated_at_str.replace("Z", "+00:00"))
                    if evaluated_at.tzinfo is None:
                        evaluated_at = evaluated_at.replace(tzinfo=timezone.utc)
                except (ValueError, AttributeError):
                    evaluated_at = datetime.now(timezone.utc)
            else:
                evaluated_at = datetime.now(timezone.utc)
            
            # Convert to Pydantic model
            compliance_report = ComplianceReport(
                rule_results=[
                    RuleResult(**result) for result in compliance_report_dict["rule_results"]
                ],
                evaluated_at=evaluated_at.isoformat(),
                total_rules=compliance_report_dict["total_rules"],
                passed=compliance_report_dict["passed"],
                failed=compliance_report_dict["failed"],
                unknown=compliance_report_dict["unknown"],
                not_applicable=compliance_report_dict["not_applicable"]
            )
            logger.info("Compliance evaluation complete: passed=%d, failed=%d, unknown=%d, not_applicable=%d",
                       compliance_report.passed, compliance_report.failed, 
                       compliance_report.unknown, compliance_report.not_applicable)
            
            # Save compliance report to database (only if project_id is provided and Supabase is configured)
            if project_id and supabase and scan_id:
                logger.info("Saving compliance report to database...")
                try:
                    report_id = save_compliance_report(
                        scan_id=scan_id,
                        project_id=project_id,
                        compliance_report=compliance_report
                    )
                    if report_id:
                        compliance_report_id = report_id
                        logger.info("Saved compliance report: report_id=%s", report_id)
                    else:
                        logger.warning("Failed to save compliance report (returned None)")
                except Exception as e:
                    logger.error("Failed to save compliance report (non-fatal): %s", str(e)[:200])
            else:
                if not project_id:
                    logger.info("Ephemeral scan: skipping compliance report persistence (no project_id)")
                elif not supabase:
                    logger.warning("Skipping compliance report persistence: Supabase not configured")
                elif not scan_id:
                    logger.warning("Skipping compliance report persistence: no scan_id")
                    
        except Exception as e:
            logger.error("Failed to evaluate compliance rules (non-fatal): %s", str(e)[:200])
            # Continue without compliance report if evaluation fails
            evaluated_at = datetime.now(timezone.utc)
        
        # Generate scan_id if not provided (for ephemeral scans)
        if not scan_id:
            scan_id = str(uuid.uuid4())
            logger.debug("Generated ephemeral scan_id: %s", scan_id)
        
        # Use repo_url parameter or default to repo_name
        final_repo_url = repo_url or repo_name
        commit_sha = commit_hash or ""
        
        # Determine verdict: SHIP_BLOCKED if any rules failed, otherwise SHIP_ALLOWED
        # For Phase 0, we use simple logic: if any rule failed with high/critical severity, block shipping
        verdict = "SHIP_ALLOWED"
        blocking_rules: List[str] = []
        rule_results_v1: List[RuleResultV1] = []
        
        if compliance_report:
            # Load rules DB to get rule metadata
            rules_db = load_rules_db()
            rules_by_id = {rule.get("rule_id"): rule for rule in rules_db.get("rules", [])}
            
            # Build rule_results and determine blocking rules
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
            logger.warning("No compliance report available, verdict set to SHIP_ALLOWED")
        
        # Build evidence refs
        evidence_refs = EvidenceRefsV1(
            scan_id=scan_id,
            dependency_snapshot_id=scan_id,  # Use scan_id if snapshot not available
            compliance_report_id=compliance_report_id
        )
        
        # Convert findings to advisory_findings (non-blocking recommendations)
        advisory_findings: List[AdvisoryFindingV1] = []
        for finding in findings:
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
        
        # Phase 0 API contract object returned here
        return ScanResultV1(
            scan_id=scan_id,
            project_id=project_id,
            repo_url=final_repo_url,
            commit_sha=commit_sha,
            environment=environment,
            evaluated_at=evaluated_at,
            verdict=verdict,
            blocking_rules=blocking_rules,
            rule_results=rule_results_v1,
            evidence_refs=evidence_refs,
            advisory_findings=advisory_findings
        )

    except HTTPException:
        # HTTPExceptions are already properly formatted, but update scan status
        if project_id and scan_id and supabase:
            duration_ms = int((time.time() - start_time) * 1000)
            try:
                update_scan_failure(scan_id, duration_ms, "HTTP error occurred")
            except Exception:
                pass
        raise
    except Exception as e:
        logger.exception("execute_scan crashed")
        if project_id and scan_id and supabase:
            duration_ms = int((time.time() - start_time) * 1000)
            error_msg = f"Server error: {str(e)[:500]}"
            try:
                update_scan_failure(scan_id, duration_ms, error_msg)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=f"Server error: {e}")


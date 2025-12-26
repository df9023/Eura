"""API routes."""
import time
import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from starlette.responses import Response
from app.core.config import MAX_FILES, MAX_FILE_BYTES, supabase
from app.core.logger import logger
from app.schemas.requests import ScanRepoRequest, ScanResponse, ComplianceReport, RuleResult
from app.models.domain import Finding, Evidence
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
from app.schemas.requests import Dependency
from app.services.database import (
    create_scan_record,
    update_scan_success,
    update_scan_failure,
    update_project_last_scan,
    insert_findings,
    bulk_insert_dependencies,
)

router = APIRouter()


@router.options("/{path:path}")
async def options_preflight(path: str):
    """Handle CORS preflight requests."""
    return Response(status_code=204)


@router.post("/scan-repo", response_model=ScanResponse)
async def scan_repo(request: ScanRepoRequest):
    """Scan a repository for security issues."""
    scan_id: Optional[str] = None
    start_time = time.time()
    
    try:
        logger.info("Starting scan: project_id=%s, repo_name=%s", request.project_id, request.repo_name)
        
        if "/" not in request.repo_name:
            raise HTTPException(status_code=400, detail="repo_name must be in format 'owner/repo'")

        max_files = request.max_files or MAX_FILES

        logger.info("Fetching GitHub client for installation_id=%d", request.installation_id)
        github_client = get_github_client(request.installation_id)
        
        try:
            logger.info("Fetching repository: %s", request.repo_name)
            repo = github_client.get_repo(request.repo_name)
            logger.info("Repository fetched successfully")
        except Exception as e:
            if request.project_id and scan_id and supabase:
                duration_ms = int((time.time() - start_time) * 1000)
                try:
                    update_scan_failure(scan_id, duration_ms, f"Repo not accessible: {e}")
                except Exception:
                    pass
            raise HTTPException(status_code=404, detail=f"Repo not accessible: {e}")

        # Get commit hash (HEAD)
        commit_hash = get_repo_commit_hash(repo)
        if commit_hash:
            logger.info("Repository commit hash: %s", commit_hash)
        else:
            logger.warning("Could not determine commit hash")

        # Create scan record (only if project_id is provided and Supabase is configured)
        if request.project_id and supabase:
            try:
                scan_id = create_scan_record(
                    project_id=request.project_id,
                    repo_name=request.repo_name,
                    installation_id=request.installation_id,
                    commit_hash=commit_hash
                )
                logger.info("Created scan record: scan_id=%s", scan_id)
            except Exception as e:
                logger.warning("Failed to create scan record (continuing without persistence): %s", e)
                scan_id = None
        else:
            if not request.project_id:
                logger.info("Ephemeral scan: project_id not provided, scan will not be persisted")
            elif not supabase:
                logger.warning("Supabase not configured: scan will not be persisted")
            scan_id = None

        # List all files
        logger.info("Listing repository files (max_files=%d)", max_files)
        try:
            all_files = list_repo_files(repo, max_files)
        except Exception as e:
            if request.project_id and scan_id and supabase:
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
                        if request.project_id and supabase and scan_id and dep_objects:
                            try:
                                bulk_insert_dependencies(
                                    scan_id=scan_id,
                                    project_id=request.project_id,
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
        if request.project_id and supabase:
            logger.info("Inserting findings into database: count=%d", len(findings))
            try:
                insert_findings(scan_id=scan_id, project_id=request.project_id, findings=findings)
            except Exception as e:
                logger.error("Failed to insert findings (non-fatal): %s", e)
        else:
            if not request.project_id:
                logger.info("Ephemeral scan: skipping findings persistence (no project_id)")
            else:
                logger.warning("Skipping findings persistence: Supabase not configured")

        # Update scan record on success (only if project_id is provided and Supabase is configured)
        duration_ms = int((time.time() - start_time) * 1000)
        if request.project_id and supabase:
            try:
                update_scan_success(
                    scan_id=scan_id,
                    duration_ms=duration_ms,
                    total_files=len(all_files),
                    analyzed_files=len(text_files),
                    commit_hash=commit_hash
                )
                update_project_last_scan(request.project_id)
            except Exception as e:
                logger.error("Failed to update scan status (non-fatal): %s", e)

        if request.project_id:
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
            # Convert to Pydantic model
            compliance_report = ComplianceReport(
                rule_results=[
                    RuleResult(**result) for result in compliance_report_dict["rule_results"]
                ],
                evaluated_at=compliance_report_dict["evaluated_at"],
                total_rules=compliance_report_dict["total_rules"],
                passed=compliance_report_dict["passed"],
                failed=compliance_report_dict["failed"],
                unknown=compliance_report_dict["unknown"],
                not_applicable=compliance_report_dict["not_applicable"]
            )
            logger.info("Compliance evaluation complete: passed=%d, failed=%d, unknown=%d, not_applicable=%d",
                       compliance_report.passed, compliance_report.failed, 
                       compliance_report.unknown, compliance_report.not_applicable)
        except Exception as e:
            logger.error("Failed to evaluate compliance rules (non-fatal): %s", str(e)[:200])
            # Continue without compliance report if evaluation fails

        return ScanResponse(
            success=True,
            repo_name=request.repo_name,
            total_files=len(all_files),
            analyzed_files=len(text_files),
            findings=findings,
            commit_hash=commit_hash,
            dependencies=dependencies,
            compliance_report=compliance_report,
        )

    except HTTPException:
        # HTTPExceptions are already properly formatted, but update scan status
        if request.project_id and scan_id and supabase:
            duration_ms = int((time.time() - start_time) * 1000)
            try:
                update_scan_failure(scan_id, duration_ms, "HTTP error occurred")
            except Exception:
                pass
        raise
    except Exception as e:
        logger.exception("scan_repo crashed")
        if request.project_id and scan_id and supabase:
            duration_ms = int((time.time() - start_time) * 1000)
            error_msg = f"Server error: {str(e)[:500]}"
            try:
                update_scan_failure(scan_id, duration_ms, error_msg)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=f"Server error: {e}")


@router.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Repository Scanner API is running", "docs_url": "/docs"}


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


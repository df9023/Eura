"""API routes."""
import time
import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from starlette.responses import Response
from app.core.config import MAX_FILES, MAX_FILE_BYTES, supabase
from app.core.logger import logger
from app.schemas.requests import ScanRepoRequest, ScanResponse
from app.models.domain import Finding, Evidence
from app.services.github import (
    get_github_client,
    list_repo_files,
    read_repo_file,
    is_text_file,
    should_skip_path,
)
from app.services.llm import analyze_file_with_llm
from app.services.database import (
    create_scan_record,
    update_scan_success,
    update_scan_failure,
    update_project_last_scan,
    insert_findings,
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

        # Create scan record (only if project_id is provided and Supabase is configured)
        if request.project_id and supabase:
            try:
                scan_id = create_scan_record(
                    project_id=request.project_id,
                    repo_name=request.repo_name,
                    installation_id=request.installation_id
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
        
        logger.info("File analysis complete: processed=%d, failed=%d, findings=%d", 
                   files_processed, files_failed, len(findings))

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
                    analyzed_files=len(text_files)
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

        return ScanResponse(
            success=True,
            repo_name=request.repo_name,
            total_files=len(all_files),
            analyzed_files=len(text_files),
            findings=findings,
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


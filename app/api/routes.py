"""API routes."""
from fastapi import APIRouter, HTTPException
from starlette.responses import Response
from app.core.logger import logger
from app.schemas.requests import ScanRepoRequest, ScanResponse
from app.services.scan_executor import execute_scan, convert_scan_result_v1_to_scan_response
from app.schemas.scan_result_v1 import ScanRunRequestV1, ScanResultV1

router = APIRouter()


@router.options("/{path:path}")
async def options_preflight(path: str):
    """Handle CORS preflight requests."""
    return Response(status_code=204)


def parse_repo_url(repo_url: str) -> str:
    """
    Parse repository URL to extract owner/repo format.
    
    Handles:
    - Full GitHub URLs: https://github.com/owner/repo -> owner/repo
    - Already in owner/repo format: owner/repo -> owner/repo
    
    Args:
        repo_url: Repository URL or identifier
    
    Returns:
        Repository name in owner/repo format
    
    Raises:
        HTTPException: If repo_url format is invalid
    """
    repo_url = repo_url.strip()
    
    # Handle full GitHub URLs
    if "github.com" in repo_url:
        # Extract owner/repo from URL
        parts = repo_url.split("github.com/")
        if len(parts) > 1:
            repo_path = parts[1].rstrip("/").rstrip(".git")
            if "/" in repo_path:
                return repo_path
    
    # Already in owner/repo format
    if "/" in repo_url:
        return repo_url
    
    raise HTTPException(
        status_code=400,
        detail=f"Invalid repo_url format: '{repo_url}'. Expected 'owner/repo' or GitHub URL."
    )


@router.post("/scan-repo", response_model=ScanResponse)
async def scan_repo(request: ScanRepoRequest):
    """Scan a repository for security issues (legacy endpoint)."""
    # Execute scan returns ScanResultV1 (Phase 0 contract)
    scan_result = await execute_scan(
        repo_name=request.repo_name,
        installation_id=request.installation_id,
        project_id=request.project_id,
        max_files=request.max_files,
        repo_url=request.repo_name,
        environment="dev"  # Default for legacy endpoint
    )
    # Convert back to ScanResponse for backward compatibility
    return convert_scan_result_v1_to_scan_response(scan_result)


@router.post("/v1/scans/run", response_model=ScanResultV1)
async def run_scan_v1(request: ScanRunRequestV1):
    """
    V1 API endpoint for running a repository scan.
    
    Returns a verdict-first ScanResultV1 response with compliance evaluation.
    The endpoint delegates to execute_scan() which returns ScanResultV1 directly.
    """
    try:
        # Parse repo_url to extract owner/repo format
        repo_name = parse_repo_url(request.repo_url)
        
        # Validate installation_id is provided
        if request.installation_id is None:
            raise HTTPException(
                status_code=400,
                detail="installation_id is required for repository access"
            )
        
        # Execute scan returns ScanResultV1 directly (Phase 0 API contract)
        scan_result = await execute_scan(
            repo_name=repo_name,
            installation_id=request.installation_id,
            project_id=None,  # Ephemeral scan for v1 endpoint
            max_files=None,
            repo_url=request.repo_url,
            environment=request.environment
        )
        
        return scan_result
        
    except HTTPException:
        # Re-raise HTTPExceptions as-is
        raise
    except Exception as e:
        logger.exception("run_scan_v1 crashed")
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)[:200]}"
        )


@router.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Repository Scanner API is running", "docs_url": "/docs"}


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


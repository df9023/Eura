"""API routes."""
from urllib.parse import urlparse
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
    Robustly extracts 'owner/repo' from various GitHub URL formats.
    
    Handles:
    - https://github.com/owner/repo
    - https://github.com/owner/repo/
    - https://github.com/owner/repo.git
    - owner/repo
    
    Args:
        repo_url: Repository URL or identifier
    
    Returns:
        Repository name in owner/repo format
    
    Raises:
        HTTPException: If repo_url format is invalid
    """
    # Clean whitespace
    clean_url = repo_url.strip()
    
    # Handle "owner/repo" input directly
    if "github.com" not in clean_url and len(clean_url.split("/")) == 2:
        return clean_url
    
    # Handle full URLs
    parsed = urlparse(clean_url)
    path = parsed.path.strip("/")  # Remove leading/trailing slashes safely
    
    # Remove .git extension if present
    if path.endswith(".git"):
        path = path[:-4]
    
    # Validate that we have owner/repo format
    if "/" not in path or len(path.split("/")) != 2:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid repo_url format: '{repo_url}'. Expected 'owner/repo' or GitHub URL."
        )
    
    return path


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
        
        # Note: installation_id is optional - if None, uses public/unauthenticated access
        # Public repos can be scanned without installation_id
        # Private repos require installation_id
        
        # Execute scan returns ScanResultV1 directly (Phase 0 API contract)
        scan_result = await execute_scan(
            repo_name=repo_name,
            installation_id=request.installation_id,  # Can be None for public repos
            project_id=None,  # Ephemeral scan for v1 endpoint
            max_files=None,
            repo_url=request.repo_url,
            environment=request.environment,
            user_id=request.user_id  # Associate scan with logged-in user
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


"""API routes."""
from urllib.parse import urlparse
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, Path
from starlette.responses import Response
from datetime import datetime
from app.core.logger import logger
from app.core.config import supabase
from app.schemas.requests import ScanRepoRequest, ScanResponse
from app.services.scan_executor import execute_scan, convert_scan_result_v1_to_scan_response
from app.schemas.scan_result_v1 import ScanRunRequestV1, ScanResultV1
from app.schemas.api_v1 import (
    ScanResponseV1, ScanListResponseV1,
    ProjectCreateRequestV1, ProjectUpdateRequestV1, ProjectResponseV1, ProjectListResponseV1,
    RepositoryCreateRequestV1, RepositoryUpdateRequestV1, RepositoryResponseV1, RepositoryListResponseV1,
    RuleResponseV1, RuleListResponseV1,
    ComplianceReportResponseV1, ComplianceReportListResponseV1, ReportGenerateRequestV1,
    SbomGenerateRequestV1,
    SarifExportRequestV1,
    RemediationTemplateRequestV1, RemediationTemplateResponseV1,
)
from app.services.database import get_db_client
from app.services.sbom import generate_sbom
from app.services.sarif import generate_sarif
from app.services.remediation_templates import (
    TEMPLATE_GENERATORS,
    TEMPLATE_FILENAMES,
    TEMPLATE_RULES_MAP,
    list_available_templates,
)
from app.services.badge import (
    generate_verdict_badge,
    generate_score_badge,
    generate_compliance_badge,
    generate_error_badge,
)

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


# ============================================================================
# Legacy Endpoints
# ============================================================================

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


@router.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Repository Scanner API is running", "docs_url": "/docs"}


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


# ============================================================================
# V1 API Endpoints - Scan Management
# ============================================================================

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


@router.get("/v1/scans/{scan_id}", response_model=ScanResponseV1)
async def get_scan_v1(scan_id: str = Path(..., description="Scan ID")):
    """Get scan by ID."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        db = get_db_client()
        scan = db.get_scan(scan_id)
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Convert database record to response model
        return ScanResponseV1(
            id=scan["id"],
            project_id=scan.get("project_id"),
            repository_id=scan.get("repository_id"),
            status=scan["status"],
            repo_name=scan["repo_name"],
            commit_hash=scan.get("commit_hash"),
            installation_id=scan.get("installation_id"),
            total_files=scan.get("total_files"),
            analyzed_files=scan.get("analyzed_files"),
            duration_ms=scan.get("duration_ms"),
            error=scan.get("error"),
            verdict=scan.get("verdict"),
            created_at=datetime.fromisoformat(scan["created_at"].replace("Z", "+00:00")),
            completed_at=datetime.fromisoformat(scan["completed_at"].replace("Z", "+00:00")) if scan.get("completed_at") else None
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to get scan: {str(e)[:200]}")


@router.get("/v1/scans", response_model=ScanListResponseV1)
async def list_scans_v1(
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Maximum number of results")
):
    """List scans with optional filters."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        if project_id:
            db = get_db_client()
            scans = db.get_scans_by_project(project_id, limit=limit)
        else:
            # Get all scans with filters
            query = supabase.table("scans").select("*").order("created_at", desc=True)
            if status:
                query = query.eq("status", status)
            if limit:
                query = query.limit(limit)
            result = query.execute()
            scans = result.data or []
        
        # Convert to response models
        scan_responses = []
        for scan in scans:
            scan_responses.append(ScanResponseV1(
                id=scan["id"],
                project_id=scan.get("project_id"),
                repository_id=scan.get("repository_id"),
                status=scan["status"],
                repo_name=scan["repo_name"],
                commit_hash=scan.get("commit_hash"),
                installation_id=scan.get("installation_id"),
                total_files=scan.get("total_files"),
                analyzed_files=scan.get("analyzed_files"),
                duration_ms=scan.get("duration_ms"),
                error=scan.get("error"),
                verdict=scan.get("verdict"),
                created_at=datetime.fromisoformat(scan["created_at"].replace("Z", "+00:00")),
                completed_at=datetime.fromisoformat(scan["completed_at"].replace("Z", "+00:00")) if scan.get("completed_at") else None
            ))
        
        return ScanListResponseV1(scans=scan_responses, total=len(scan_responses))
    except Exception as e:
        logger.error("Failed to list scans: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to list scans: {str(e)[:200]}")


@router.delete("/v1/scans/{scan_id}")
async def delete_scan_v1(scan_id: str = Path(..., description="Scan ID")):
    """Delete scan by ID."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        # Verify scan exists
        db = get_db_client()
        scan = db.get_scan(scan_id)
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Delete scan (cascade will handle related records)
        supabase.table("scans").delete().eq("id", scan_id).execute()
        
        return {"message": f"Scan {scan_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete scan: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to delete scan: {str(e)[:200]}")


# ============================================================================
# V1 API Endpoints - Project Management
# ============================================================================

@router.post("/v1/projects", response_model=ProjectResponseV1, status_code=201)
async def create_project_v1(request: ProjectCreateRequestV1):
    """Create a new project."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        project_data = {
            "name": request.name,
            "organization_id": request.organization_id,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
        
        result = supabase.table("projects").insert(project_data).execute()
        
        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=500, detail="Failed to create project")
        
        project = result.data[0]
        return ProjectResponseV1(
            id=project["id"],
            organization_id=project.get("organization_id"),
            name=project["name"],
            created_at=datetime.fromisoformat(project["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(project["updated_at"].replace("Z", "+00:00")),
            last_scan_at=datetime.fromisoformat(project["last_scan_at"].replace("Z", "+00:00")) if project.get("last_scan_at") else None,
            last_scan_id=project.get("last_scan_id")
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create project: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to create project: {str(e)[:200]}")


@router.get("/v1/projects/{project_id}", response_model=ProjectResponseV1)
async def get_project_v1(project_id: str = Path(..., description="Project ID")):
    """Get project by ID."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        result = supabase.table("projects").select("*").eq("id", project_id).execute()
        
        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
        
        project = result.data[0]
        return ProjectResponseV1(
            id=project["id"],
            organization_id=project.get("organization_id"),
            name=project["name"],
            created_at=datetime.fromisoformat(project["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(project["updated_at"].replace("Z", "+00:00")),
            last_scan_at=datetime.fromisoformat(project["last_scan_at"].replace("Z", "+00:00")) if project.get("last_scan_at") else None,
            last_scan_id=project.get("last_scan_id")
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get project: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to get project: {str(e)[:200]}")


@router.get("/v1/projects", response_model=ProjectListResponseV1)
async def list_projects_v1(
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Maximum number of results")
):
    """List all projects."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        query = supabase.table("projects").select("*").order("created_at", desc=True)
        if limit:
            query = query.limit(limit)
        result = query.execute()
        projects = result.data or []
        
        project_responses = []
        for project in projects:
            project_responses.append(ProjectResponseV1(
                id=project["id"],
                organization_id=project.get("organization_id"),
                name=project["name"],
                created_at=datetime.fromisoformat(project["created_at"].replace("Z", "+00:00")),
                updated_at=datetime.fromisoformat(project["updated_at"].replace("Z", "+00:00")),
                last_scan_at=datetime.fromisoformat(project["last_scan_at"].replace("Z", "+00:00")) if project.get("last_scan_at") else None,
                last_scan_id=project.get("last_scan_id")
            ))
        
        return ProjectListResponseV1(projects=project_responses, total=len(project_responses))
    except Exception as e:
        logger.error("Failed to list projects: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to list projects: {str(e)[:200]}")


@router.put("/v1/projects/{project_id}", response_model=ProjectResponseV1)
async def update_project_v1(
    project_id: str = Path(..., description="Project ID"),
    request: ProjectUpdateRequestV1 = ...
):
    """Update project."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        # Verify project exists
        existing = supabase.table("projects").select("id").eq("id", project_id).execute()
        if not existing.data or len(existing.data) == 0:
            raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
        
        # Update project
        update_data = {"updated_at": datetime.utcnow().isoformat() + "Z"}
        if request.name is not None:
            update_data["name"] = request.name
        
        result = supabase.table("projects").update(update_data).eq("id", project_id).execute()
        
        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=500, detail="Failed to update project")
        
        project = result.data[0]
        return ProjectResponseV1(
            id=project["id"],
            organization_id=project.get("organization_id"),
            name=project["name"],
            created_at=datetime.fromisoformat(project["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(project["updated_at"].replace("Z", "+00:00")),
            last_scan_at=datetime.fromisoformat(project["last_scan_at"].replace("Z", "+00:00")) if project.get("last_scan_at") else None,
            last_scan_id=project.get("last_scan_id")
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to update project: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to update project: {str(e)[:200]}")


@router.delete("/v1/projects/{project_id}")
async def delete_project_v1(project_id: str = Path(..., description="Project ID")):
    """Delete project by ID."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        # Verify project exists
        existing = supabase.table("projects").select("id").eq("id", project_id).execute()
        if not existing.data or len(existing.data) == 0:
            raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
        
        # Delete project (cascade will handle related records)
        supabase.table("projects").delete().eq("id", project_id).execute()
        
        return {"message": f"Project {project_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete project: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to delete project: {str(e)[:200]}")


# ============================================================================
# V1 API Endpoints - Repository Management
# ============================================================================

@router.post("/v1/repositories", response_model=RepositoryResponseV1, status_code=201)
async def create_repository_v1(request: RepositoryCreateRequestV1):
    """Create a new repository."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        repository_data = {
            "project_id": request.project_id,
            "provider": request.provider,
            "owner": request.owner,
            "name": request.name,
            "url": request.url,
            "default_branch": request.default_branch or "main",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
        
        result = supabase.table("repositories").insert(repository_data).execute()
        
        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=500, detail="Failed to create repository")
        
        repo = result.data[0]
        return RepositoryResponseV1(
            id=repo["id"],
            project_id=repo["project_id"],
            provider=repo["provider"],
            owner=repo["owner"],
            name=repo["name"],
            url=repo["url"],
            default_branch=repo["default_branch"],
            created_at=datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(repo["updated_at"].replace("Z", "+00:00"))
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create repository: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to create repository: {str(e)[:200]}")


@router.get("/v1/repositories/{repository_id}", response_model=RepositoryResponseV1)
async def get_repository_v1(repository_id: str = Path(..., description="Repository ID")):
    """Get repository by ID."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        result = supabase.table("repositories").select("*").eq("id", repository_id).execute()
        
        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=404, detail=f"Repository {repository_id} not found")
        
        repo = result.data[0]
        return RepositoryResponseV1(
            id=repo["id"],
            project_id=repo["project_id"],
            provider=repo["provider"],
            owner=repo["owner"],
            name=repo["name"],
            url=repo["url"],
            default_branch=repo["default_branch"],
            created_at=datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(repo["updated_at"].replace("Z", "+00:00"))
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get repository: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to get repository: {str(e)[:200]}")


@router.get("/v1/repositories", response_model=RepositoryListResponseV1)
async def list_repositories_v1(
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Maximum number of results")
):
    """List repositories with optional filters."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        query = supabase.table("repositories").select("*").order("created_at", desc=True)
        if project_id:
            query = query.eq("project_id", project_id)
        if limit:
            query = query.limit(limit)
        result = query.execute()
        repos = result.data or []
        
        repo_responses = []
        for repo in repos:
            repo_responses.append(RepositoryResponseV1(
                id=repo["id"],
                project_id=repo["project_id"],
                provider=repo["provider"],
                owner=repo["owner"],
                name=repo["name"],
                url=repo["url"],
                default_branch=repo["default_branch"],
                created_at=datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00")),
                updated_at=datetime.fromisoformat(repo["updated_at"].replace("Z", "+00:00"))
            ))
        
        return RepositoryListResponseV1(repositories=repo_responses, total=len(repo_responses))
    except Exception as e:
        logger.error("Failed to list repositories: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to list repositories: {str(e)[:200]}")


@router.put("/v1/repositories/{repository_id}", response_model=RepositoryResponseV1)
async def update_repository_v1(
    repository_id: str = Path(..., description="Repository ID"),
    request: RepositoryUpdateRequestV1 = ...
):
    """Update repository."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        # Verify repository exists
        existing = supabase.table("repositories").select("id").eq("id", repository_id).execute()
        if not existing.data or len(existing.data) == 0:
            raise HTTPException(status_code=404, detail=f"Repository {repository_id} not found")
        
        # Update repository
        update_data = {"updated_at": datetime.utcnow().isoformat() + "Z"}
        if request.default_branch is not None:
            update_data["default_branch"] = request.default_branch
        
        result = supabase.table("repositories").update(update_data).eq("id", repository_id).execute()
        
        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=500, detail="Failed to update repository")
        
        repo = result.data[0]
        return RepositoryResponseV1(
            id=repo["id"],
            project_id=repo["project_id"],
            provider=repo["provider"],
            owner=repo["owner"],
            name=repo["name"],
            url=repo["url"],
            default_branch=repo["default_branch"],
            created_at=datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(repo["updated_at"].replace("Z", "+00:00"))
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to update repository: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to update repository: {str(e)[:200]}")


@router.delete("/v1/repositories/{repository_id}")
async def delete_repository_v1(repository_id: str = Path(..., description="Repository ID")):
    """Delete repository by ID."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        # Verify repository exists
        existing = supabase.table("repositories").select("id").eq("id", repository_id).execute()
        if not existing.data or len(existing.data) == 0:
            raise HTTPException(status_code=404, detail=f"Repository {repository_id} not found")
        
        # Delete repository (cascade will handle related records)
        supabase.table("repositories").delete().eq("id", repository_id).execute()
        
        return {"message": f"Repository {repository_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete repository: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to delete repository: {str(e)[:200]}")


# ============================================================================
# V1 API Endpoints - Rule Management
# ============================================================================

@router.get("/v1/rules", response_model=RuleListResponseV1)
async def list_rules_v1(
    regulation: Optional[str] = Query(None, description="Filter by regulation"),
    limit: Optional[int] = Query(1000, ge=1, le=10000, description="Maximum number of results")
):
    """List rules with optional filters."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        db = get_db_client()
        
        if regulation:
            rules = db.get_rules_by_regulation(regulation)
        else:
            rules = db.get_all_rules()
        
        # Limit results
        if limit:
            rules = rules[:limit]
        
        rule_responses = []
        for rule in rules:
            rule_responses.append(RuleResponseV1(
                id=rule["id"],
                rule_id=rule["rule_id"],
                version=rule["version"],
                regulation=rule["regulation"],
                title=rule["title"],
                description_short=rule.get("description_short"),
                description_long=rule.get("description_long"),
                severity=rule["severity"],
                is_blocking=rule.get("is_blocking", False),
                rule_definition=rule.get("rule_definition", {}),
                created_at=datetime.fromisoformat(rule["created_at"].replace("Z", "+00:00")),
                updated_at=datetime.fromisoformat(rule["updated_at"].replace("Z", "+00:00"))
            ))
        
        return RuleListResponseV1(rules=rule_responses, total=len(rule_responses))
    except Exception as e:
        logger.error("Failed to list rules: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to list rules: {str(e)[:200]}")


@router.get("/v1/rules/{rule_id}", response_model=RuleResponseV1)
async def get_rule_v1(rule_id: str = Path(..., description="Rule ID")):
    """Get rule by rule_id."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        db = get_db_client()
        rule = db.get_rule(rule_id)
        
        if not rule:
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
        
        return RuleResponseV1(
            id=rule["id"],
            rule_id=rule["rule_id"],
            version=rule["version"],
            regulation=rule["regulation"],
            title=rule["title"],
            description_short=rule.get("description_short"),
            description_long=rule.get("description_long"),
            severity=rule["severity"],
            is_blocking=rule.get("is_blocking", False),
            rule_definition=rule.get("rule_definition", {}),
            created_at=datetime.fromisoformat(rule["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(rule["updated_at"].replace("Z", "+00:00"))
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get rule: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to get rule: {str(e)[:200]}")


@router.get("/v1/rules/{rule_id}/versions")
async def get_rule_versions_v1(rule_id: str = Path(..., description="Rule ID")):
    """Get rule versions (placeholder - rule versioning not yet implemented)."""
    # TODO: Implement rule versioning system
    return {
        "rule_id": rule_id,
        "versions": [],
        "message": "Rule versioning not yet implemented"
    }


# ============================================================================
# V1 API Endpoints - Compliance Reports
# ============================================================================

@router.get("/v1/reports/{report_id}", response_model=ComplianceReportResponseV1)
async def get_report_v1(report_id: str = Path(..., description="Report ID")):
    """Get compliance report by ID."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        db = get_db_client()
        report = db.get_report(report_id)
        
        if not report:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        
        return ComplianceReportResponseV1(
            id=report["id"],
            scan_id=report["scan_id"],
            project_id=report["project_id"],
            regulation=report["regulation"],
            verdict=report["verdict"],
            score=report.get("score"),
            total_rules=report.get("total_rules"),
            passed=report.get("passed"),
            failed=report.get("failed"),
            unknown=report.get("unknown"),
            not_applicable=report.get("not_applicable"),
            evaluated_at=datetime.fromisoformat(report["evaluated_at"].replace("Z", "+00:00")),
            created_at=datetime.fromisoformat(report["created_at"].replace("Z", "+00:00"))
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get report: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to get report: {str(e)[:200]}")


@router.get("/v1/reports", response_model=ComplianceReportListResponseV1)
async def list_reports_v1(
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    regulation: Optional[str] = Query(None, description="Filter by regulation"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Maximum number of results")
):
    """List compliance reports with optional filters."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database not configured")
    
    try:
        db = get_db_client()
        
        if project_id:
            reports = db.get_reports_by_project(project_id, limit=limit)
        else:
            # Get all reports with filters
            query = supabase.table("compliance_reports").select("*").order("evaluated_at", desc=True)
            if regulation:
                query = query.eq("regulation", regulation)
            if limit:
                query = query.limit(limit)
            result = query.execute()
            reports = result.data or []
        
        report_responses = []
        for report in reports:
            report_responses.append(ComplianceReportResponseV1(
                id=report["id"],
                scan_id=report["scan_id"],
                project_id=report["project_id"],
                regulation=report["regulation"],
                verdict=report["verdict"],
                score=report.get("score"),
                total_rules=report.get("total_rules"),
                passed=report.get("passed"),
                failed=report.get("failed"),
                unknown=report.get("unknown"),
                not_applicable=report.get("not_applicable"),
                evaluated_at=datetime.fromisoformat(report["evaluated_at"].replace("Z", "+00:00")),
                created_at=datetime.fromisoformat(report["created_at"].replace("Z", "+00:00"))
            ))
        
        return ComplianceReportListResponseV1(reports=report_responses, total=len(report_responses))
    except Exception as e:
        logger.error("Failed to list reports: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to list reports: {str(e)[:200]}")


@router.post("/v1/reports/generate")
async def generate_report_v1(request: ReportGenerateRequestV1):
    """Generate compliance report (placeholder - reports are generated during scan)."""
    # Reports are automatically generated during scan execution
    # This endpoint could be used to regenerate reports or generate custom reports
    return {
        "message": "Reports are automatically generated during scan execution",
        "scan_id": request.scan_id,
        "regulation": request.regulation or "all"
    }


@router.get("/v1/reports/{report_id}/export")
async def export_report_v1(
    report_id: str = Path(..., description="Report ID"),
    format: str = Query("json", regex="^(json|pdf|excel)$", description="Export format")
):
    """Export compliance report (placeholder - export functionality not yet implemented)."""
    # TODO: Implement PDF and Excel export
    if format == "json":
        # Return JSON representation
        if not supabase:
            raise HTTPException(status_code=503, detail="Database not configured")
        
        db = get_db_client()
        report = db.get_report(report_id)
        
        if not report:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        
        return report
    
    return {
        "message": f"Export format '{format}' not yet implemented",
        "report_id": report_id
    }


# ============================================================================
# SBOM Endpoints (local-only; no GitHub/DB required)
# ============================================================================

@router.post("/v1/sbom/generate")
async def generate_sbom_v1(request: SbomGenerateRequestV1):
    """
    Generate SBOM (Software Bill of Materials) in SPDX 2.3 or CycloneDX 1.5 format.

    Accepts a list of dependencies and returns a standard SBOM. No external services
    (GitHub, database) required—suitable for local use and CRA-SBOM-004 compliance.
    """
    deps = [d.model_dump() for d in request.dependencies]
    sbom = generate_sbom(
        deps,
        request.format,
        name=request.name or "EURA SBOM",
        repo_name=request.repo_name,
        commit_sha=request.commit_sha,
    )
    return sbom


# ============================================================================
# SARIF Export Endpoint (local-only; no GitHub/DB required)
# ============================================================================

@router.post("/v1/exports/sarif")
async def export_sarif_v1(request: SarifExportRequestV1):
    """
    Generate a SARIF 2.1.0 JSON report from EURA scan data.

    Accepts rule evaluation results, optional security findings, and optional
    vulnerability report. Returns a standards-compliant SARIF document suitable
    for GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF tools.

    No external services (GitHub, database) required.
    """
    # Convert Pydantic models to dicts
    rule_results = [rr.model_dump() for rr in request.rule_results]

    findings = None
    if request.findings:
        findings = [f.model_dump() for f in request.findings]

    vuln_report = None
    if request.vulnerability_report:
        vuln_report = request.vulnerability_report.model_dump()

    sarif = generate_sarif(
        rule_results=rule_results,
        findings=findings,
        vulnerability_report=vuln_report,
        repo_name=request.repo_name,
        commit_sha=request.commit_sha,
        scan_id=request.scan_id,
    )

    return sarif


# ============================================================================
# Remediation Template Endpoints
# ============================================================================

@router.get("/v1/remediation/templates")
async def list_remediation_templates():
    """
    List all available remediation templates with metadata.

    Returns template IDs, target filenames, and which CRA rules each template
    helps satisfy.
    """
    return {"templates": list_available_templates(), "total": len(TEMPLATE_GENERATORS)}


@router.post("/v1/remediation/generate")
async def generate_remediation_template(request: RemediationTemplateRequestV1):
    """
    Generate a remediation compliance document from a template.

    Returns Markdown content ready to commit to a repository.
    Supports: SECURITY.md, CHANGELOG.md, SUPPORT.md, CONTRIBUTING.md,
    and security configuration guides.
    """
    template_id = request.template_id
    generator = TEMPLATE_GENERATORS.get(template_id)

    if not generator:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown template_id: {template_id}. "
                   f"Valid: {list(TEMPLATE_GENERATORS.keys())}",
        )

    # Build kwargs based on template type
    kwargs = {"project_name": request.project_name}

    if template_id == "security-md":
        kwargs.update({
            "contact_email": request.contact_email,
            "pgp_key_url": request.pgp_key_url,
            "response_hours": request.response_hours,
            "disclosure_days": request.disclosure_days,
        })
    elif template_id == "changelog-md":
        kwargs["initial_version"] = request.initial_version
    elif template_id == "support-md":
        kwargs.update({
            "support_email": request.contact_email,
            "support_years": request.support_years,
        })

    content = generator(**kwargs)

    return RemediationTemplateResponseV1(
        template_id=template_id,
        filename=TEMPLATE_FILENAMES[template_id],
        content=content,
        addresses_rules=TEMPLATE_RULES_MAP.get(template_id, []),
    )


# ============================================================================
# V1 API Endpoints - Compliance Badges
# ============================================================================

# SVG response headers (cache for 5 minutes, allow CDN caching)
_BADGE_HEADERS = {
    "Content-Type": "image/svg+xml",
    "Cache-Control": "public, max-age=300, s-maxage=300",
}


def _badge_query_params(
    style: Optional[str] = Query("flat", regex="^(flat|flat-square)$", description="Badge style"),
    regulation: Optional[str] = Query(None, description="Regulation filter (CRA, AI_ACT)"),
    type: Optional[str] = Query("verdict", regex="^(verdict|score|compliance)$", description="Badge type"),
):
    """Shared query parameters for badge endpoints."""
    return {"style": style or "flat", "regulation": regulation, "type": type or "verdict"}


def _build_badge_svg(
    verdict: Optional[str],
    score: Optional[float],
    style: str,
    regulation: Optional[str],
    badge_type: str,
) -> str:
    """Build badge SVG from scan/report data."""
    if badge_type == "score" and score is not None:
        return generate_score_badge(score, regulation or "CRA", style)
    if badge_type == "compliance" and verdict:
        return generate_compliance_badge(verdict, regulation or "CRA", style)
    if verdict:
        label = regulation or "EURA"
        return generate_verdict_badge(verdict, label, style)
    return generate_error_badge()


@router.get("/v1/badges/{project_id}")
async def get_project_badge(
    project_id: str = Path(..., description="Project ID"),
    style: Optional[str] = Query("flat", regex="^(flat|flat-square)$", description="Badge style"),
    regulation: Optional[str] = Query(None, description="Regulation filter (CRA, AI_ACT)"),
    type: Optional[str] = Query("verdict", regex="^(verdict|score|compliance)$", description="Badge type: verdict, score, or compliance"),
):
    """
    Get a compliance badge SVG for a project.

    Returns an SVG image based on the project's latest compliance scan.
    Embed in your README with:

        ![EURA Compliance](https://your-api/api/v1/badges/{project_id})
        ![CRA Score](https://your-api/api/v1/badges/{project_id}?type=score&regulation=CRA)
        ![CRA](https://your-api/api/v1/badges/{project_id}?type=compliance&regulation=CRA)
    """
    badge_style = style or "flat"
    badge_type = type or "verdict"

    if not supabase:
        svg = generate_error_badge(regulation or "EURA", "no db", badge_style)
        return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)

    try:
        # Find latest scan for this project
        result = (
            supabase.table("scans")
            .select("verdict")
            .eq("project_id", project_id)
            .eq("status", "completed")
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )

        verdict = None
        score = None

        if result.data and len(result.data) > 0:
            verdict = result.data[0].get("verdict")

        # If score badge requested, fetch from compliance_reports
        if badge_type == "score" and verdict:
            report_query = (
                supabase.table("compliance_reports")
                .select("score, regulation, verdict")
                .eq("project_id", project_id)
                .order("evaluated_at", desc=True)
            )
            if regulation:
                report_query = report_query.eq("regulation", regulation)
            report_query = report_query.limit(1)
            report_result = report_query.execute()

            if report_result.data and len(report_result.data) > 0:
                score = report_result.data[0].get("score")
                # Use regulation-specific verdict if available
                verdict = report_result.data[0].get("verdict", verdict)

        if not verdict:
            svg = generate_error_badge(regulation or "EURA", "no scans", badge_style)
        else:
            svg = _build_badge_svg(verdict, score, badge_style, regulation, badge_type)

        return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)

    except Exception as e:
        logger.error("Failed to generate project badge: %s", e)
        svg = generate_error_badge(regulation or "EURA", "error", badge_style)
        return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)


@router.get("/v1/badges/scan/{scan_id}")
async def get_scan_badge(
    scan_id: str = Path(..., description="Scan ID"),
    style: Optional[str] = Query("flat", regex="^(flat|flat-square)$", description="Badge style"),
    regulation: Optional[str] = Query(None, description="Regulation filter (CRA, AI_ACT)"),
    type: Optional[str] = Query("verdict", regex="^(verdict|score|compliance)$", description="Badge type: verdict, score, or compliance"),
):
    """
    Get a compliance badge SVG for a specific scan.

    Returns an SVG image based on a single scan's results.
    Useful for pinning a badge to a specific point-in-time scan.

        ![Scan Result](https://your-api/api/v1/badges/scan/{scan_id})
    """
    badge_style = style or "flat"
    badge_type = type or "verdict"

    if not supabase:
        svg = generate_error_badge(regulation or "EURA", "no db", badge_style)
        return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)

    try:
        db = get_db_client()
        scan = db.get_scan(scan_id)

        if not scan:
            svg = generate_error_badge(regulation or "EURA", "not found", badge_style)
            return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)

        verdict = scan.get("verdict")
        score = None

        # Fetch score from compliance_reports if needed
        if badge_type == "score" and scan.get("project_id"):
            report_query = (
                supabase.table("compliance_reports")
                .select("score, regulation, verdict")
                .eq("scan_id", scan_id)
            )
            if regulation:
                report_query = report_query.eq("regulation", regulation)
            report_query = report_query.limit(1)
            report_result = report_query.execute()

            if report_result.data and len(report_result.data) > 0:
                score = report_result.data[0].get("score")
                verdict = report_result.data[0].get("verdict", verdict)

        if not verdict:
            svg = generate_error_badge(regulation or "EURA", "pending", badge_style)
        else:
            svg = _build_badge_svg(verdict, score, badge_style, regulation, badge_type)

        return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)

    except Exception as e:
        logger.error("Failed to generate scan badge: %s", e)
        svg = generate_error_badge(regulation or "EURA", "error", badge_style)
        return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)


@router.get("/v1/badges/repo/{owner}/{repo}")
async def get_repo_badge(
    owner: str = Path(..., description="Repository owner"),
    repo: str = Path(..., description="Repository name"),
    style: Optional[str] = Query("flat", regex="^(flat|flat-square)$", description="Badge style"),
    regulation: Optional[str] = Query(None, description="Regulation filter (CRA, AI_ACT)"),
    type: Optional[str] = Query("verdict", regex="^(verdict|score|compliance)$", description="Badge type: verdict, score, or compliance"),
):
    """
    Get a compliance badge SVG by repository owner/name.

    Looks up the latest completed scan for the given repository.

        ![CRA](https://your-api/api/v1/badges/repo/octocat/hello-world?type=compliance&regulation=CRA)
    """
    badge_style = style or "flat"
    badge_type = type or "verdict"
    repo_name = f"{owner}/{repo}"

    if not supabase:
        svg = generate_error_badge(regulation or "EURA", "no db", badge_style)
        return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)

    try:
        # Find latest completed scan by repo_name
        result = (
            supabase.table("scans")
            .select("id, verdict, project_id")
            .eq("repo_name", repo_name)
            .eq("status", "completed")
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )

        verdict = None
        score = None

        if result.data and len(result.data) > 0:
            scan = result.data[0]
            verdict = scan.get("verdict")
            scan_id = scan.get("id")

            # Fetch score from compliance_reports if needed
            if badge_type == "score" and scan_id:
                report_query = (
                    supabase.table("compliance_reports")
                    .select("score, regulation, verdict")
                    .eq("scan_id", scan_id)
                )
                if regulation:
                    report_query = report_query.eq("regulation", regulation)
                report_query = report_query.limit(1)
                report_result = report_query.execute()

                if report_result.data and len(report_result.data) > 0:
                    score = report_result.data[0].get("score")
                    verdict = report_result.data[0].get("verdict", verdict)

        if not verdict:
            svg = generate_error_badge(regulation or "EURA", "no scans", badge_style)
        else:
            svg = _build_badge_svg(verdict, score, badge_style, regulation, badge_type)

        return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)

    except Exception as e:
        logger.error("Failed to generate repo badge: %s", e)
        svg = generate_error_badge(regulation or "EURA", "error", badge_style)
        return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)

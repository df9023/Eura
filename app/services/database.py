"""Database client for Supabase operations."""
from typing import Optional, Dict, Any, List
from datetime import datetime
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
    
    def create_scan(self, repo_id: str, commit_hash: Optional[str] = None) -> str:
        """
        Create a new scan record.
        
        Args:
            repo_id: UUID of the repository to scan
            commit_hash: Optional Git commit hash to scan
        
        Returns:
            scan_id: UUID of the created scan record
        
        Raises:
            HTTPException: If Supabase is not configured or creation fails
            ValueError: If repo_id is invalid or repository doesn't exist
        """
        try:
            # Verify repository exists
            repo_result = self.client.table("repositories").select("id, project_id").eq("id", repo_id).execute()
            
            if not repo_result.data or len(repo_result.data) == 0:
                raise ValueError(f"Repository with id {repo_id} not found")
            
            repository = repo_result.data[0]
            project_id = repository.get("project_id")
            
            # Create scan record
            scan_data = {
                "repository_id": repo_id,
                "project_id": project_id,
                "status": "queued",
                "commit_hash": commit_hash,
                "created_at": datetime.utcnow().isoformat() + "Z",
            }
            
            result = self.client.table("scans").insert(scan_data).execute()
            
            if not result.data or len(result.data) == 0:
                raise ValueError("Failed to create scan record")
            
            scan_id = result.data[0]["id"]
            logger.info("Created scan: scan_id=%s, repo_id=%s, commit_hash=%s", 
                       scan_id, repo_id, commit_hash)
            
            return scan_id
            
        except ValueError as e:
            logger.error("Validation error creating scan: %s", e)
            raise
        except Exception as e:
            logger.error("Failed to create scan: %s", e)
            raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")
    
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
            results: Optional dictionary containing scan results (rule_results, scores, etc.)
        
        Raises:
            HTTPException: If Supabase is not configured or update fails
            ValueError: If scan_id is invalid or verdict is invalid
        """
        if verdict not in ["SHIP_ALLOWED", "SHIP_BLOCKED"]:
            raise ValueError(f"Invalid verdict: {verdict}. Must be 'SHIP_ALLOWED' or 'SHIP_BLOCKED'")
        
        try:
            # Verify scan exists
            scan_result = self.client.table("scans").select("id, status").eq("id", scan_id).execute()
            
            if not scan_result.data or len(scan_result.data) == 0:
                raise ValueError(f"Scan with id {scan_id} not found")
            
            # Prepare update data
            update_data = {
                "status": "completed",
                "verdict": verdict,
                "completed_at": datetime.utcnow().isoformat() + "Z",
            }
            
            # Add results if provided
            if results:
                # Store results as JSONB if your schema supports it
                # Otherwise, extract specific fields
                if "score" in results:
                    update_data["score"] = results["score"]
                if "total_rules" in results:
                    update_data["total_rules"] = results["total_rules"]
                if "passed" in results:
                    update_data["passed"] = results["passed"]
                if "failed" in results:
                    update_data["failed"] = results["failed"]
                if "blocking_rules" in results:
                    update_data["blocking_rules"] = results["blocking_rules"]
                # Store full results as JSONB if column exists
                if "results_json" in results:
                    update_data["results_json"] = results["results_json"]
            
            # Update scan record
            self.client.table("scans").update(update_data).eq("id", scan_id).execute()
            
            logger.info("Updated scan verdict: scan_id=%s, verdict=%s", scan_id, verdict)
            
        except ValueError as e:
            logger.error("Validation error updating scan verdict: %s", e)
            raise
        except Exception as e:
            logger.error("Failed to update scan verdict: %s", e)
            raise HTTPException(status_code=500, detail=f"Failed to update scan verdict: {str(e)}")


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

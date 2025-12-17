import os
import time
import jwt
import requests
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from github import Github

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="Repository Scanner API",
    description="API for scanning GitHub repositories using GitHub App authentication",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all frontends to connect
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (POST, GET, etc.)
    allow_headers=["*"],  # Allows all headers
)

# Environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY")

# Validate required environment variables
if not GITHUB_APP_ID or not GITHUB_PRIVATE_KEY:
    raise ValueError("GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be set in environment variables")


class ScanRepoRequest(BaseModel):
    repo_name: str
    installation_id: int


def get_github_client(installation_id: int) -> Github:
    """
    Authenticate as a GitHub App Installation and return a PyGithub client.
    
    Args:
        installation_id: The GitHub App installation ID
        
    Returns:
        Authenticated Github client instance
        
    Raises:
        ValueError: If authentication fails
    """
    if not GITHUB_APP_ID or not GITHUB_PRIVATE_KEY:
        raise ValueError("GitHub App credentials not configured")
    
    # Generate JWT token for GitHub App
    app_id = int(GITHUB_APP_ID)
    
    # Parse the private key (handle both raw string and file path)
    private_key = GITHUB_PRIVATE_KEY
    if private_key.startswith("-----BEGIN"):
        # Already a PEM-formatted string
        pass
    else:
        # Assume it's a file path or needs to be read
        if os.path.exists(private_key):
            with open(private_key, 'r') as f:
                private_key = f.read()
    
    # Create JWT token
    now = int(time.time())
    payload = {
        "iat": now - 60,  # Issued at time (60 seconds ago to account for clock skew)
        "exp": now + 600,  # Expires in 10 minutes
        "iss": app_id  # Issuer (GitHub App ID)
    }
    
    try:
        jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
    except Exception as e:
        raise ValueError(f"Failed to generate JWT token: {str(e)}")
    
    # Get installation access token
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    
    try:
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        installation_token = response.json()["token"]
    except requests.exceptions.RequestException as e:
        raise ValueError(f"Failed to get installation access token: {str(e)}")
    
    # Create and return authenticated GitHub client
    return Github(installation_token)


@app.post("/scan-repo")
async def scan_repo(request: ScanRepoRequest):
    """
    Scan a GitHub repository and return the file tree.
    
    Args:
        request: ScanRepoRequest containing repo_name and installation_id
        
    Returns:
        Dictionary with success status and file list
    """
    try:
        # Validate repo_name format
        if "/" not in request.repo_name:
            raise HTTPException(
                status_code=400,
                detail="repo_name must be in format 'owner/repo'"
            )
        
        # Get authenticated GitHub client
        github_client = get_github_client(request.installation_id)
        
        # Get repository
        try:
            repo = github_client.get_repo(request.repo_name)
        except Exception as e:
            raise HTTPException(
                status_code=404,
                detail=f"Repository '{request.repo_name}' not found or not accessible: {str(e)}"
            )
        
        # Get file tree (get all files recursively)
        files = []
        try:
            contents = repo.get_contents("")
            while contents:
                file_content = contents.pop(0)
                if file_content.type == "file":
                    files.append(file_content.path)
                elif file_content.type == "dir":
                    contents.extend(repo.get_contents(file_content.path))
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to fetch repository contents: {str(e)}"
            )
        
        # Print files to console (for testing)
        print(f"\n=== Files in repository '{request.repo_name}' ===")
        for file_path in sorted(files):
            print(file_path)
        print(f"=== Total files: {len(files)} ===\n")
        
        return {
            "success": True,
            "repo_name": request.repo_name,
            "file_count": len(files),
            "files": sorted(files)
        }
        
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error: {str(e)}"
        )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


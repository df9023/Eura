import os
import time
import jwt
import requests
import traceback
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from github import Github
from openai import AsyncOpenAI

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
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Validate required environment variables
if not GITHUB_APP_ID or not GITHUB_PRIVATE_KEY:
    raise ValueError("GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be set in environment variables")

# Initialize OpenAI client
openai_client = None
if OPENAI_API_KEY:
    openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)


class ScanRepoRequest(BaseModel):
    repo_name: str
    installation_id: int


def is_text_file(file_path: str) -> bool:
    """
    Check if a file is a text/code file that should be analyzed.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if the file should be analyzed, False otherwise
    """
    # Define text/code file extensions
    text_extensions = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.md', '.txt', '.json', '.yaml', '.yml',
        '.html', '.css', '.scss', '.sass', '.less', '.xml', '.csv', '.sql', '.sh', '.bash',
        '.zsh', '.fish', '.ps1', '.bat', '.cmd', '.go', '.rs', '.java', '.cpp', '.c', '.h',
        '.hpp', '.cc', '.cxx', '.cs', '.php', '.rb', '.swift', '.kt', '.scala', '.clj',
        '.cljs', '.r', '.R', '.m', '.mm', '.pl', '.pm', '.lua', '.vim', '.vimrc', '.dockerfile',
        '.makefile', '.cmake', '.gradle', '.maven', '.pom', '.toml', '.ini', '.cfg', '.conf',
        '.config', '.env', '.gitignore', '.gitattributes', '.editorconfig', '.eslintrc',
        '.prettierrc', '.babelrc', '.tsconfig', '.jsconfig', '.package.json', '.requirements.txt',
        '.gemfile', '.cargo', '.lock', '.log', '.readme', '.license', '.licence', '.authors',
        '.contributors', '.changelog', '.history', '.todo', '.notes', '.markdown'
    }
    
    # Define binary file extensions to skip
    binary_extensions = {
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico', '.webp', '.tiff', '.tif',
        '.pyc', '.pyo', '.pyd', '.so', '.dll', '.exe', '.dylib', '.bin', '.dat', '.db',
        '.sqlite', '.sqlite3', '.pdf', '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.ogg', '.wav', '.flac',
        '.woff', '.woff2', '.ttf', '.otf', '.eot',
        '.class', '.jar', '.war', '.ear', '.o', '.obj', '.a', '.lib'
    }
    
    file_lower = file_path.lower()
    
    # Check if it's a binary file extension
    for ext in binary_extensions:
        if file_lower.endswith(ext):
            return False
    
    # Check if it's a text file extension
    for ext in text_extensions:
        if file_lower.endswith(ext):
            return True
    
    # Check if it's a dotfile (like .gitignore, .env, etc.)
    basename = os.path.basename(file_lower)
    if basename.startswith('.'):
        # Allow common dotfiles
        if basename in {'.gitignore', '.gitattributes', '.env', '.editorconfig'}:
            return True
    
    # Default: skip files without recognized extensions
    return False


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
    try:
        print("DEBUG: Starting scan-repo endpoint")
        
        # Explicitly check if GITHUB_APP_ID and GITHUB_PRIVATE_KEY exist
        print("DEBUG: Checking environment variables")
        if not GITHUB_APP_ID:
            raise ValueError("GITHUB_APP_ID is missing in environment variables")
        if not GITHUB_PRIVATE_KEY:
            raise ValueError("GITHUB_PRIVATE_KEY is missing in environment variables")
        if not OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is missing in environment variables")
        if not openai_client:
            raise ValueError("OpenAI client not initialized")
        
        # Validate repo_name format
        print("DEBUG: Validating repo_name format")
        if "/" not in request.repo_name:
            raise HTTPException(
                status_code=400,
                detail="repo_name must be in format 'owner/repo'"
            )
        
        # Get authenticated GitHub client
        print("DEBUG: Auth started")
        github_client = get_github_client(request.installation_id)
        
        # Get repository
        print(f"DEBUG: Fetching repository '{request.repo_name}'")
        try:
            repo = github_client.get_repo(request.repo_name)
        except Exception as e:
            raise HTTPException(
                status_code=404,
                detail=f"Repository '{request.repo_name}' not found or not accessible: {str(e)}"
            )
        
        print("DEBUG: Repo fetched")
        
        # Get file tree (get all files recursively)
        print("DEBUG: Fetching file tree")
        all_files = []
        try:
            contents = repo.get_contents("")
            while contents:
                file_content = contents.pop(0)
                if file_content.type == "file":
                    all_files.append(file_content.path)
                elif file_content.type == "dir":
                    contents.extend(repo.get_contents(file_content.path))
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to fetch repository contents: {str(e)}"
            )
        
        print(f"DEBUG: File tree fetched, found {len(all_files)} total files")
        
        # Filter files to only process text/code files
        print("DEBUG: Filtering text/code files")
        text_files = [f for f in all_files if is_text_file(f)]
        print(f"DEBUG: Found {len(text_files)} text/code files to analyze")
        
        # Analyze files with AI
        print("DEBUG: Starting AI analysis")
        results: List[Dict[str, str]] = []
        
        for file_path in text_files:
            try:
                print(f"DEBUG: Analyzing file: {file_path}")
                
                # Read file content
                file_content_obj = repo.get_contents(file_path)
                file_content = file_content_obj.decoded_content.decode('utf-8', errors='ignore')
                
                # Prepare the prompt
                system_prompt = "You are a compliance auditor. Check this code for security issues (hardcoded keys, weak passwords) and style violations. Be concise."
                
                # Call OpenAI API
                try:
                    response = await openai_client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": f"File: {file_path}\n\nCode:\n{file_content}"}
                        ],
                        max_tokens=500,
                        temperature=0.3
                    )
                    
                    analysis = response.choices[0].message.content.strip()
                    results.append({
                        "file": file_path,
                        "analysis": analysis
                    })
                    print(f"DEBUG: Completed analysis for {file_path}")
                    
                except Exception as e:
                    # If OpenAI call fails for a specific file, log it but continue
                    error_analysis = f"Error analyzing file: {str(e)}"
                    results.append({
                        "file": file_path,
                        "analysis": error_analysis
                    })
                    print(f"DEBUG: Error analyzing {file_path}: {str(e)}")
                    
            except Exception as e:
                # If reading file fails, log it but continue
                error_analysis = f"Error reading file: {str(e)}"
                results.append({
                    "file": file_path,
                    "analysis": error_analysis
                })
                print(f"DEBUG: Error reading {file_path}: {str(e)}")
        
        print(f"DEBUG: AI analysis complete, analyzed {len(results)} files")
        print("DEBUG: Scan complete, returning response")
        
        return {
            "success": True,
            "repo_name": request.repo_name,
            "total_files": len(all_files),
            "analyzed_files": len(text_files),
            "results": results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        # Capture the exception
        error_msg = f"SERVER CRASHED: {str(e)}"
        print(error_msg)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=error_msg)

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)


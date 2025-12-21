"""GitHub client and repository file operations."""
import os
import time
import jwt
import requests
from typing import List, Optional
from github import Github
from app.core.config import GITHUB_APP_ID, GITHUB_PRIVATE_KEY, MAX_FILE_BYTES, MAX_CHARS_PER_FILE, SKIP_DIRS
from app.core.logger import logger


def is_text_file(file_path: str) -> bool:
    """Check if a file is a text/code file."""
    text_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".md", ".txt", ".json", ".yaml", ".yml",
        ".html", ".css", ".xml", ".csv", ".sql", ".sh", ".go", ".rs", ".java", ".c",
        ".cpp", ".h", ".hpp", ".cs", ".php", ".rb", ".swift", ".kt", ".toml", ".ini",
        ".cfg", ".conf", ".env", ".gitignore", ".editorconfig", ".dockerfile"
    }

    binary_extensions = {
        ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
        ".mp3", ".mp4", ".woff", ".woff2", ".ttf", ".otf", ".class", ".jar", ".exe",
        ".dll", ".so", ".dylib"
    }

    file_lower = file_path.lower()

    if any(file_lower.endswith(ext) for ext in binary_extensions):
        return False

    if any(file_lower.endswith(ext) for ext in text_extensions):
        return True

    base = os.path.basename(file_lower)
    if base.startswith(".") and base in {".gitignore", ".gitattributes", ".env", ".editorconfig"}:
        return True

    return False


def should_skip_path(path: str) -> bool:
    """Check if a path should be skipped based on directory patterns."""
    parts = [p for p in path.split("/") if p]
    return any(part in SKIP_DIRS for part in parts)


def get_private_key_pem() -> str:
    """Get GitHub private key in PEM format."""
    private_key = GITHUB_PRIVATE_KEY or ""
    if private_key.startswith("-----BEGIN"):
        return private_key
    if os.path.exists(private_key):
        with open(private_key, "r", encoding="utf-8") as f:
            return f.read()
    raise ValueError("GITHUB_PRIVATE_KEY must be PEM content or a valid file path")


def get_github_client(installation_id: int) -> Github:
    """Get authenticated GitHub client for installation."""
    app_id = int(GITHUB_APP_ID)
    private_key_pem = get_private_key_pem()

    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": app_id}

    try:
        jwt_token = jwt.encode(payload, private_key_pem, algorithm="RS256")
    except Exception as e:
        raise ValueError(f"Failed to generate JWT: {e}") from e

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
    }

    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"

    try:
        resp = requests.post(url, headers=headers, timeout=20)
        resp.raise_for_status()
        installation_token = resp.json()["token"]
        logger.debug("Successfully obtained GitHub installation token")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to get installation token: %s", e)
        raise ValueError(f"Failed to get installation token: {e}") from e

    return Github(installation_token)


def list_repo_files(repo: any, max_files: int) -> List[str]:
    """List all files in repository, respecting skip directories and limits."""
    all_files: List[str] = []
    try:
        contents = repo.get_contents("")
        while contents and len(all_files) < max_files * 5:
            item = contents.pop(0)
            if should_skip_path(item.path):
                continue
            if item.type == "file":
                all_files.append(item.path)
            elif item.type == "dir":
                contents.extend(repo.get_contents(item.path))
    except Exception as e:
        logger.error("Failed to list repo files: %s", e)
        raise
    
    return all_files


def truncate_for_llm(content: str) -> str:
    """Truncate file content to fit within LLM limits while preserving context."""
    if len(content) <= MAX_CHARS_PER_FILE:
        return content
    # Keep start and end so configs and exports remain visible
    head = content[: int(MAX_CHARS_PER_FILE * 0.7)]
    tail = content[-int(MAX_CHARS_PER_FILE * 0.3):]
    return head + "\n\n...TRUNCATED...\n\n" + tail


def read_repo_file(repo: any, file_path: str) -> Optional[str]:
    """Read file content from repository, handling size limits and encoding."""
    try:
        file_obj = repo.get_contents(file_path)
        
        # Skip large blobs
        if getattr(file_obj, "size", 0) and file_obj.size > MAX_FILE_BYTES:
            logger.debug("Skipping large file %s: %d bytes", file_path, file_obj.size)
            return None
        
        content = file_obj.decoded_content.decode("utf-8", errors="ignore")
        return truncate_for_llm(content)
    except Exception as e:
        logger.warning("Failed to read file %s: %s", file_path, str(e)[:200])
        raise


def get_repo_commit_hash(repo: any) -> Optional[str]:
    """Get the current commit SHA (HEAD) from the repository."""
    try:
        # Get the default branch (usually 'main' or 'master')
        default_branch = repo.default_branch
        branch = repo.get_branch(default_branch)
        commit_sha = branch.commit.sha
        logger.debug("Repository commit SHA: %s", commit_sha)
        return commit_sha
    except Exception as e:
        logger.warning("Failed to get commit hash: %s", str(e)[:200])
        return None


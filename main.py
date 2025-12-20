import os
import time
import uuid
import logging
import traceback
import hashlib
import json
from typing import List, Dict, Optional, Literal
from datetime import datetime
import jwt
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response
from pydantic import BaseModel, Field
from github import Github
from openai import AsyncOpenAI
from supabase import create_client, Client

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("repo-scanner")


# ----------------------------
# Config
# ----------------------------
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# MVP safety limits
MAX_FILES = int(os.getenv("MAX_FILES", "120"))
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", "120000"))  # 120 KB
MAX_CHARS_PER_FILE = int(os.getenv("MAX_CHARS_PER_FILE", "12000"))

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", ".nuxt",
    ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    "coverage", ".coverage", "target"
}

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "")
if ALLOWED_ORIGINS:
    allow_origins = [o.strip() for o in ALLOWED_ORIGINS.split(",") if o.strip()]
else:
    allow_origins = ["*"]
logger.info("CORS: Allowed origins configured as: %s", allow_origins)

if not GITHUB_APP_ID or not GITHUB_PRIVATE_KEY:
    raise ValueError("GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be set")

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY must be set")

openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

# Supabase initialization (optional)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

supabase: Optional[Client] = None
try:
    if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    else:
        logger.warning("Supabase not configured: missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY.")
except Exception as e:
    supabase = None
    logger.exception("Supabase client init failed: %s", e)


# ----------------------------
# API Models
# ----------------------------
class ScanRepoRequest(BaseModel):
    project_id: str = Field(..., description="UUID of the project")
    repo_name: str = Field(..., description="Format: owner/repo")
    installation_id: int
    max_files: Optional[int] = Field(None, description="Override MAX_FILES for this scan")


Severity = Literal["high", "medium", "low", "info"]


class Evidence(BaseModel):
    file: str
    lines: Optional[str] = None
    snippet: Optional[str] = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    details: str
    evidence: List[Evidence]
    recommendation: str
    category: Optional[str] = None  # ex: secrets, auth, crypto, config


class ScanResponse(BaseModel):
    success: bool
    repo_name: str
    total_files: int
    analyzed_files: int
    findings: List[Finding]


# ----------------------------
# FastAPI app
# ----------------------------
app = FastAPI(
    title="Repository Scanner API",
    description="API for scanning GitHub repositories using GitHub App authentication",
    version="1.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)


# ----------------------------
# Helpers
# ----------------------------
def is_text_file(file_path: str) -> bool:
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
    parts = [p for p in path.split("/") if p]
    return any(part in SKIP_DIRS for part in parts)


def get_private_key_pem() -> str:
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


def truncate_for_llm(content: str) -> str:
    """Truncate file content to fit within LLM limits while preserving context."""
    if len(content) <= MAX_CHARS_PER_FILE:
        return content
    # Keep start and end so configs and exports remain visible
    head = content[: int(MAX_CHARS_PER_FILE * 0.7)]
    tail = content[-int(MAX_CHARS_PER_FILE * 0.3):]
    return head + "\n\n...TRUNCATED...\n\n" + tail


def make_parse_failure_finding(file_path: str, raw_response: str) -> Finding:
    """Create a finding for LLM parse failures."""
    return Finding(
        id=str(uuid.uuid4()),
        title="LLM output parsing failed",
        severity="info",
        confidence=0.2,
        summary="The model did not return valid JSON.",
        details=raw_response[:2000] if raw_response else "Empty response from LLM",
        evidence=[Evidence(file=file_path)],
        recommendation="Retry the scan or adjust the prompt to force strict JSON output.",
        category="other",
    )


def normalize_findings(findings_in: List[Dict], file_path: str) -> List[Finding]:
    """Normalize and validate findings from LLM output."""
    findings: List[Finding] = []
    allowed_severities = {"high", "medium", "low", "info"}
    
    for f in findings_in:
        # Ensure evidence has file path
        evidence_items = []
        for ev in f.get("evidence", []) or []:
            evidence_items.append(
                Evidence(
                    file=ev.get("file") or file_path,  # Use file_path if missing
                    lines=ev.get("lines"),
                    snippet=ev.get("snippet"),
                )
            )
        if not evidence_items:
            evidence_items = [Evidence(file=file_path)]

        # Normalize severity
        severity = f.get("severity", "info").lower()
        if severity not in allowed_severities:
            severity = "info"

        # Clamp confidence
        confidence = float(f.get("confidence", 0.4))
        confidence = max(0.0, min(1.0, confidence))

        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                title=f.get("title", "Untitled finding") or "Untitled finding",
                severity=severity,
                confidence=confidence,
                summary=f.get("summary", "") or "",
                details=f.get("details", "") or "",
                evidence=evidence_items,
                recommendation=f.get("recommendation", "") or "",
                category=f.get("category"),
            )
        )

    return findings


async def analyze_file_with_llm(file_path: str, file_content: str) -> List[Finding]:
    """Analyze file with LLM, enforcing JSON output with retry."""
    system_prompt = """You are a security code auditor. Return ONLY valid JSON matching this exact schema:
{
  "findings": [
    {
      "title": "string",
      "severity": "high|medium|low|info",
      "confidence": 0.0-1.0,
      "summary": "1 sentence",
      "details": "short paragraph",
      "recommendation": "clear fix instruction",
      "category": "secrets|auth|crypto|injection|config|logging|dependency|other",
      "evidence": [
        { "file": "string", "lines": "string|null", "snippet": "string|null" }
      ]
    }
  ]
}

Rules:
- Return ONLY JSON, no markdown, no code blocks, no explanation.
- Only report issues you can justify from the provided code.
- If unsure, lower confidence and severity.
- If no issues, return {"findings": []}.
- Evidence snippets must be copied from the code (short).
- Every evidence entry must include "file" field."""

    user_prompt = f"File: {file_path}\n\nCode:\n{file_content}"

    # Try with JSON mode first (if supported), then fallback to prompt enforcement
    max_retries = 1
    for attempt in range(max_retries + 1):
        try:
            # Try with response_format="json_object" if available
            create_kwargs = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": 2000,
                "temperature": 0.2,
            }
            
            # Try to use JSON mode if available in the SDK
            try:
                create_kwargs["response_format"] = {"type": "json_object"}
            except (TypeError, AttributeError):
                # If response_format not supported, rely on prompt
                pass

            resp = await openai_client.chat.completions.create(**create_kwargs)
            raw = (resp.choices[0].message.content or "").strip()

            # Remove markdown code blocks if present
            if raw.startswith("```"):
                lines = raw.split("\n")
                if lines[0].startswith("```json") or lines[0].startswith("```"):
                    raw = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

            # Parse JSON
            try:
                data = json.loads(raw)
                findings_in = data.get("findings", [])
                if not isinstance(findings_in, list):
                    findings_in = []
                
                return normalize_findings(findings_in, file_path)
            except json.JSONDecodeError as e:
                if attempt < max_retries:
                    logger.warning("JSON parse failed (attempt %d/%d) for %s, retrying: %s", 
                                  attempt + 1, max_retries + 1, file_path, str(e)[:100])
                    continue
                else:
                    logger.error("JSON parse failed after retries for %s: %s", file_path, str(e)[:100])
                    return [make_parse_failure_finding(file_path, raw)]
        except Exception as e:
            if attempt < max_retries:
                logger.warning("LLM call failed (attempt %d/%d) for %s, retrying: %s", 
                              attempt + 1, max_retries + 1, file_path, str(e)[:100])
                continue
            else:
                logger.error("LLM call failed after retries for %s: %s", file_path, str(e)[:100])
                return [make_parse_failure_finding(file_path, f"LLM error: {str(e)[:500]}")]

    # Should not reach here, but safety fallback
    return [make_parse_failure_finding(file_path, "Unknown error")]


# ----------------------------
# Supabase Helpers
# ----------------------------
def generate_fingerprint(project_id: str, vuln_category: str, title: str, evidence: List[Evidence]) -> str:
    """Generate SHA256 fingerprint for deduplication."""
    if not evidence:
        content = f"{project_id}:{vuln_category}:{title}:"
    else:
        ev0 = evidence[0]
        content = f"{project_id}:{vuln_category}:{title}:{ev0.file}:{ev0.lines or ''}"
    return hashlib.sha256(content.encode()).hexdigest()


def parse_line_number(lines_str: Optional[str]) -> Optional[int]:
    """Parse line number from '10-18' format, return first number."""
    if not lines_str:
        return None
    try:
        parts = lines_str.split("-")
        return int(parts[0].strip())
    except (ValueError, AttributeError):
        return None


def create_scan_record(project_id: str, repo_name: str, installation_id: int) -> str:
    """Create a scan record and return scan_id."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        result = supabase.table("scans").insert({
            "project_id": project_id,
            "status": "processing",
            "repo_name": repo_name,
            "installation_id": installation_id,
        }).execute()
        
        if not result.data or len(result.data) == 0:
            raise ValueError("Failed to create scan record")
        
        scan_id = result.data[0]["id"]
        logger.info("Created scan record: scan_id=%s, project_id=%s", scan_id, project_id)
        return scan_id
    except Exception as e:
        logger.error("Failed to create scan record: %s", e)
        raise


def update_scan_success(scan_id: str, duration_ms: int, total_files: int, analyzed_files: int):
    """Update scan record on success."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        supabase.table("scans").update({
            "status": "completed",
            "duration_ms": duration_ms,
            "total_files": total_files,
            "analyzed_files": analyzed_files,
            "error": None,
        }).eq("id", scan_id).execute()
        logger.info("Updated scan success: scan_id=%s, duration_ms=%d", scan_id, duration_ms)
    except Exception as e:
        logger.error("Failed to update scan success: %s", e)
        raise


def update_scan_failure(scan_id: str, duration_ms: int, error_msg: str):
    """Update scan record on failure."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        supabase.table("scans").update({
            "status": "failed",
            "duration_ms": duration_ms,
            "error": error_msg[:5000] if error_msg else None,  # Truncate if too long
        }).eq("id", scan_id).execute()
        logger.error("Updated scan failure: scan_id=%s, error=%s", scan_id, error_msg[:200])
    except Exception as e:
        logger.error("Failed to update scan failure: %s", e)
        # Don't raise - we're already in error handling


def update_project_last_scan(project_id: str):
    """Update project's last_scan_at timestamp."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    try:
        supabase.table("projects").update({
            "last_scan_at": datetime.utcnow().isoformat() + "Z",
        }).eq("id", project_id).execute()
        logger.info("Updated project last_scan_at: project_id=%s", project_id)
    except Exception as e:
        logger.warning("Failed to update project last_scan_at: %s", e)
        # Don't raise - this is not critical


def insert_findings(scan_id: str, project_id: str, findings: List[Finding]):
    """Insert findings with deduplication by fingerprint."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    if not findings:
        logger.info("No findings to insert")
        return
    
    # Deduplicate by fingerprint
    seen_fingerprints = set()
    unique_findings = []
    
    for finding in findings:
        vuln_category = finding.category or "other"
        evidence = finding.evidence or []
        ev0 = evidence[0] if evidence else Evidence(file="")
        
        fingerprint = generate_fingerprint(
            project_id=project_id,
            vuln_category=vuln_category,
            title=finding.title,
            evidence=evidence
        )
        
        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            unique_findings.append((finding, fingerprint, vuln_category, ev0))
    
    logger.info("Deduplicated findings: %d -> %d", len(findings), len(unique_findings))
    
    # Map severity to allowed values (info|low|medium|high|critical)
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    
    # Prepare insert data
    insert_data = []
    for finding, fingerprint, vuln_category, ev0 in unique_findings:
        # Map severity to allowed values, default to "info"
        # Note: "critical" is allowed but should be used sparingly
        mapped_severity = severity_map.get(finding.severity.lower(), "info")
        
        line_number = parse_line_number(ev0.lines if ev0 else None)
        
        # Prepare evidence_json
        evidence_json = []
        for ev in (finding.evidence or []):
            evidence_json.append({
                "file": ev.file,
                "lines": ev.lines,
                "snippet": ev.snippet,
            })
        
        insert_data.append({
            "scan_id": scan_id,
            "project_id": project_id,
            "severity": mapped_severity,
            "category": "security",  # Always "security"
            "vuln_category": vuln_category,
            "title": finding.title,
            "description": finding.summary,  # Old column
            "summary": finding.summary,
            "details": finding.details,
            "confidence": finding.confidence,
            "recommendation": finding.recommendation,
            "suggested_fix": finding.recommendation,  # Old column
            "evidence_json": evidence_json,
            "file_path": ev0.file if ev0 else None,
            "line_number": line_number,
            "code_snippet_before": ev0.snippet if ev0 else None,
            "fingerprint": fingerprint,
        })
    
    if not insert_data:
        logger.info("No findings to insert after deduplication")
        return
    
    # Batch insert
    try:
        # Insert in batches to avoid payload size issues
        batch_size = 100
        total_inserted = 0
        
        for i in range(0, len(insert_data), batch_size):
            batch = insert_data[i:i + batch_size]
            result = supabase.table("findings").insert(batch).execute()
            inserted_count = len(result.data) if result.data else 0
            total_inserted += inserted_count
            logger.info("Inserted batch: %d findings", inserted_count)
        
        logger.info("Inserted findings: total=%d", total_inserted)
    except Exception as e:
        logger.error("Failed to insert findings: %s", e)
        # Check if it's a duplicate constraint error
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            logger.warning("Duplicate findings detected (constraint violation), continuing")
        else:
            raise


# ----------------------------
# Routes
# ----------------------------
@app.options("/{path:path}")
async def options_preflight(path: str):
    return Response(status_code=204)


@app.post("/scan-repo", response_model=ScanResponse)
async def scan_repo(request: ScanRepoRequest):
    scan_id: Optional[str] = None
    start_time = time.time()
    
    try:
        logger.info("Starting scan: project_id=%s, repo_name=%s", request.project_id, request.repo_name)
        
        if "/" not in request.repo_name:
            raise HTTPException(status_code=400, detail="repo_name must be in format 'owner/repo'")

        # Create scan record (only if Supabase is configured)
        if supabase:
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
            if scan_id and supabase:
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
            if scan_id and supabase:
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

        # Insert findings into database
        if supabase:
            logger.info("Inserting findings into database: count=%d", len(findings))
            try:
                insert_findings(scan_id=scan_id, project_id=request.project_id, findings=findings)
            except Exception as e:
                logger.error("Failed to insert findings (non-fatal): %s", e)
        else:
            logger.warning("Skipping findings persistence: Supabase not configured")

        # Update scan record on success
        duration_ms = int((time.time() - start_time) * 1000)
        if supabase:
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

        logger.info("Scan completed successfully: scan_id=%s, duration_ms=%d, findings=%d", 
                   scan_id, duration_ms, len(findings))

        return ScanResponse(
            success=True,
            repo_name=request.repo_name,
            total_files=len(all_files),
            analyzed_files=len(text_files),
            findings=findings,
        )

    except HTTPException:
        # HTTPExceptions are already properly formatted, but update scan status
        if scan_id and supabase:
            duration_ms = int((time.time() - start_time) * 1000)
            try:
                update_scan_failure(scan_id, duration_ms, "HTTP error occurred")
            except Exception:
                pass
        raise
    except Exception as e:
        logger.exception("scan_repo crashed")
        if scan_id and supabase:
            duration_ms = int((time.time() - start_time) * 1000)
            error_msg = f"Server error: {str(e)[:500]}"
            try:
                update_scan_failure(scan_id, duration_ms, error_msg)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=f"Server error: {e}")


@app.get("/")
async def root():
    return {"message": "Repository Scanner API is running", "docs_url": "/docs"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}

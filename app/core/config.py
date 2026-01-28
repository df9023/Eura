"""Configuration and environment variables."""
import os
from typing import Optional
from supabase import create_client, Client
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()

# GitHub App credentials
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
# Handle private key - replace \n with actual newlines if needed (for quoted env vars)
_private_key_raw = os.getenv("GITHUB_PRIVATE_KEY", "")
GITHUB_PRIVATE_KEY = _private_key_raw.replace("\\n", "\n") if _private_key_raw else ""
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# MVP safety limits
MAX_FILES = int(os.getenv("MAX_FILES", "120"))
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", "120000"))  # 120 KB
MAX_CHARS_PER_FILE = int(os.getenv("MAX_CHARS_PER_FILE", "12000"))

# Skip directories
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", ".nuxt",
    ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    "coverage", ".coverage", "target"
}

# CORS configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "")
if ALLOWED_ORIGINS:
    allow_origins = [o.strip() for o in ALLOWED_ORIGINS.split(",") if o.strip()]
else:
    allow_origins = ["*"]

# Validation
if not GITHUB_APP_ID or not GITHUB_PRIVATE_KEY:
    raise ValueError("GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be set")

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY must be set")

# Initialize OpenAI client
openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

# Supabase initialization (optional)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

supabase: Optional[Client] = None
try:
    # Check for valid (non-empty) values
    if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY and SUPABASE_SERVICE_ROLE_KEY.strip() and SUPABASE_SERVICE_ROLE_KEY != "your-service-role-key-here":
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
        import logging
        logging.getLogger("repo-scanner").info("Supabase client initialized successfully.")
    else:
        # Supabase is optional - this is informational, not an error
        import logging
        logging.getLogger("repo-scanner").info("Supabase not configured (optional): Database persistence features disabled. Scans will work without database.")
except Exception as e:
    supabase = None
    # Logger will be imported after config loads to avoid circular import
    import logging
    logging.getLogger("repo-scanner").warning("Supabase client init failed (optional): %s. Database features disabled.", e)


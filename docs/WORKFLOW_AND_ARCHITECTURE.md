# EURA Workflow and Architecture Documentation

## 1. Overview

### What is EURA?

EURA is a compliance scanning platform that evaluates software repositories against the EU Cyber Resilience Act (CRA), and other EU Regulations. It translates regulatory requirements into executable rules that can be automatically evaluated by scanning repository structure, files, dependencies, and code.

### MVP Capabilities (Current State)

- **Repository Scanning**: Fetches and analyzes GitHub repositories using GitHub App authentication or public/unauthenticated access
- **Public Mode**: Supports scanning public repositories without GitHub App installation (uses GITHUB_TOKEN or unauthenticated access)
- **Dependency Extraction**: Deterministically parses dependencies from manifest files (requirements.txt, package.json, pyproject.toml)
- **Code Analysis**: Optional LLM-based security scanning for advisory findings (non-blocking)
- **Compliance Evaluation**: Evaluates repositories against 18 CRA rules (CRA-BASE-001 through CRA-BASE-018)
- **Verdict Generation**: Returns deterministic SHIP_ALLOWED or SHIP_BLOCKED verdict based on rule failures
- **Persistence**: Stores scan results, findings, dependencies, and compliance reports in Supabase
- **Phase 0 API Contract**: Returns verdict-first ScanResultV1 objects with structured rule results
- **CI/CD Integration**: CI gatekeeper script for blocking deployments based on compliance verdict

### Core Principle

**Regulation as executable rules + deterministic evidence + optional LLM advisory**

- **Executable Rules**: CRA requirements are encoded as testable rules with structured applicability conditions
- **Deterministic Evidence**: Dependency parsing, file presence checks, and metadata extraction are deterministic (no LLM)
- **Optional LLM Advisory**: Code analysis via LLM provides advisory findings only (low/info severity) and does not block shipping

---

## 2. End-to-End Workflow

### Step-by-Step Scan Flow

1. **Frontend Request** (Lovable React)
   - User initiates scan via frontend
   - Frontend calls `POST /v1/scans/run` with `{ repo_url, environment, installation_id? }`
   - `installation_id` is optional (required for private repos, optional for public repos)
   - Request sent to FastAPI backend (deployed on Railway)

2. **Backend Endpoint** (`app/api/routes.py`)
   - `run_scan_v1()` receives request
   - `parse_repo_url()` robustly extracts `owner/repo` from various GitHub URL formats
   - `installation_id` is optional - public repos can be scanned without it
   - Calls `execute_scan()` orchestrator function

3. **Repository Fetch** (`app/services/github.py`)
   - `get_github_client()` supports two modes:
     - **Public Mode** (installation_id=None): Uses GITHUB_TOKEN env var if available, otherwise unauthenticated access
     - **GitHub App Mode** (installation_id provided): Authenticates as GitHub App Installation
       - Generates JWT token using GitHub App credentials
       - Exchanges JWT for installation access token
   - `github_client.get_repo(repo_name)` fetches repository object
   - `get_repo_commit_hash()` retrieves HEAD commit SHA
   - Handles 404 errors gracefully with clear error messages

4. **File Discovery** (`app/services/github.py`)
   - `list_repo_files()` recursively lists all files in repository
   - Filters out skipped directories (node_modules, .git, etc.)
   - Limits to MAX_FILES (default 120)
   - `is_text_file()` filters to text/code files only

5. **Deterministic Dependency Parsing** (`app/services/dependencies.py`)
   - For each manifest file (requirements.txt, package.json, pyproject.toml):
     - `extract_dependencies()` uses regex/parsing (no LLM)
     - Extracts package name, version, type, file_source
     - Immediately saved to `scan_dependencies` table if `project_id` provided

6. **Optional Code Scanning** (`app/services/llm.py`)
   - For each text file:
     - `analyze_file_with_llm()` sends code to OpenAI (gpt-4o-mini)
     - LLM returns JSON with security findings (secrets, auth issues, etc.)
     - Findings are normalized and validated
     - Only low/info severity findings become advisory_findings (non-blocking)

7. **Compliance Evaluation** (`app/services/compliance.py`)
   - `evaluate_repo()` loads rules from `app/data/rules_db.json`
   - `build_signals_from_scan()` extracts signals (has_security_policy, dependency_count, etc.)
   - For each rule:
     - `check_applicability()` evaluates boolean logic conditions
     - Rule-specific evaluation (dependency rules, finding rules, documentation rules)
     - LLM fallback for documentation quality checks (CRA-BASE-001, CRA-BASE-007)
   - Returns rule_results with PASS/FAIL/NOT_APPLICABLE status

8. **Persistence to Supabase** (`app/services/database.py`)
   - If `project_id` provided:
     - `create_scan_record()` creates row in `scans` table (status="processing")
     - `bulk_insert_dependencies()` saves dependencies to `scan_dependencies`
     - `insert_findings()` saves findings to `findings` table (with deduplication)
     - `save_compliance_report()` saves to `compliance_reports` and `compliance_details`
     - `update_scan_success()` updates scan status to "completed"
     - `update_project_last_scan()` updates project timestamp

9. **Response Generation** (`app/services/scan_executor.py`)
   - `execute_scan()` assembles `ScanResultV1` object:
     - Sets `evaluated_at` once (timezone-aware UTC)
     - Determines `verdict` (SHIP_BLOCKED if any high/critical severity rules failed)
     - Builds `rule_results` with rule metadata from rules_db
     - Converts findings to `advisory_findings` (low/info only)
     - Creates `evidence_refs` with scan_id and compliance_report_id
   - Returns `ScanResultV1` (Phase 0 API contract)

10. **Response Returned**
    - Endpoint returns `ScanResultV1` directly
    - Frontend receives verdict-first response with all rule evaluations
    - UI can immediately render shipping decision and compliance status

---

## 3. Local Development Workflow

### Prerequisites

- **Python 3.11+**: Backend runtime
- **Node.js**: For frontend (if developing Lovable React app separately)
- **Supabase Account**: For database access
- **GitHub App**: Registered GitHub App with installation access
- **OpenAI API Key**: For LLM code analysis

### Environment Variables

Create a `.env` file in the project root with:

```
# GitHub App Authentication (required for private repos)
GITHUB_APP_ID=<your-app-id>
GITHUB_PRIVATE_KEY=<your-private-key-pem>

# GitHub Personal Access Token (optional, for public repo scanning with higher rate limits)
GITHUB_TOKEN=<your-personal-access-token>

# OpenAI API
OPENAI_API_KEY=<your-openai-key>

# Supabase (optional for local dev)
SUPABASE_URL=<your-supabase-url>
SUPABASE_SERVICE_ROLE_KEY=<your-service-role-key>

# CORS (optional)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Limits (optional, defaults shown)
MAX_FILES=120
MAX_FILE_BYTES=120000
MAX_CHARS_PER_FILE=12000
```

### Running Backend Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run FastAPI server
uvicorn app.main:app --reload --port 8000

# Server available at http://localhost:8000
# API docs at http://localhost:8000/docs
```

### Running Frontend Locally

The frontend is built with Lovable (React). If developing separately:

```bash
# Frontend typically runs on port 3000 or 5173
# Ensure ALLOWED_ORIGINS in .env includes frontend URL
```

### Running Tests

```bash
# Install test dependencies (pytest, pytest-asyncio)
pip install -r requirements.txt

# Run all tests
pytest tests/ -v

# Run Phase 0 contract tests
pytest tests/test_phase0_contract.py -v

# Run with coverage
pytest tests/ --cov=app --cov-report=term-missing
```

### Suggested Branching and PR Style

- **Main branch**: Production-ready code
- **Feature branches**: `feature/description` (e.g., `feature/add-new-rule`)
- **PR naming**: Descriptive titles, include context in description
- **Testing**: Run tests before PR, ensure Phase 0 contract tests pass
- **Code review**: Focus on contract compliance, error handling, logging

---

## 4. Repository Structure

```
Eura/
├── app/                          # Main application code
│   ├── __init__.py
│   ├── main.py                   # FastAPI app entry point
│   ├── api/                      # API routes
│   │   ├── __init__.py
│   │   └── routes.py             # Endpoints: /scan-repo, /v1/scans/run
│   ├── core/                     # Core configuration
│   │   ├── __init__.py
│   │   ├── config.py             # Environment variables, Supabase/OpenAI init
│   │   └── logger.py             # Logging configuration
│   ├── models/                    # Domain models
│   │   ├── __init__.py
│   │   └── domain.py             # Finding, Evidence models
│   ├── schemas/                    # API request/response schemas
│   │   ├── __init__.py
│   │   ├── requests.py           # ScanRepoRequest, ScanResponse, ComplianceReport
│   │   └── scan_result_v1.py    # ScanResultV1, RuleResultV1, EvidenceRefsV1
│   ├── services/                 # Business logic services
│   │   ├── __init__.py
│   │   ├── compliance.py        # Rule evaluation engine
│   │   ├── database.py           # Supabase operations
│   │   ├── dependencies.py       # Dependency parsing (deterministic)
│   │   ├── github.py             # GitHub API client
│   │   ├── llm.py                # OpenAI code analysis
│   │   ├── scan_executor.py      # Core scan orchestrator
│   │   └── scan_result_adapter.py # Legacy compatibility adapter
│   └── data/                     # Data files (rules_db.json location)
│
├── docs/                          # Documentation
│   └── WORKFLOW_AND_ARCHITECTURE.md
│
├── eura_knowledge/                # Regulatory knowledge layer
│   ├── schema_v0.1.json          # JSON Schema for rules and evaluation
│   └── cra_rule_pack_v0.1.txt    # Human-readable rule pack
│
├── scripts/                       # Utility scripts
│   ├── ingest_rules.py           # Converts rule pack to rules_db.json
│   └── ci_gatekeeper.py          # CI/CD gatekeeper script for deployment blocking
│
├── tests/                         # Test suite
│   ├── __init__.py
│   ├── README.md
│   └── test_phase0_contract.py   # Phase 0 contract validation tests
│
├── .env                           # Environment variables (not in git)
├── .gitignore
├── Procfile                       # Railway deployment config
├── pytest.ini                     # Pytest configuration
├── requirements.txt               # Python dependencies
└── runtime.txt                    # Python version specification
```

---

## 5. Module-by-Module Explanation

### `app/main.py`

**Purpose**: FastAPI application entry point and middleware configuration.

**Key Components**:
- FastAPI app initialization
- CORS middleware configuration (allows frontend requests)
- Router inclusion from `app/api/routes.py`

**Where Used**: Railway deployment (via Procfile), local development (uvicorn)

---

### `app/api/routes.py`

**Purpose**: API endpoint definitions and request handling.

**Key Functions**:
- `parse_repo_url()`: Robustly extracts owner/repo from various GitHub URL formats (handles URLs with/without trailing slashes, .git extension, direct owner/repo format)
- `scan_repo()`: Legacy `/scan-repo` endpoint (returns ScanResponse)
- `run_scan_v1()`: Phase 0 `/v1/scans/run` endpoint (returns ScanResultV1)
- `root()`: Health check endpoint
- `options_preflight()`: CORS preflight handler

**Inputs**: HTTP requests with JSON bodies
**Outputs**: JSON responses (ScanResponse or ScanResultV1)
**Invariants**: 
- `installation_id` is optional (public repos don't require it)
- `repo_url` format is validated and parsed robustly

**Where Used**: Called by FastAPI router, invoked by frontend HTTP requests

---

### `app/services/scan_executor.py`

**Purpose**: Core scan orchestration - coordinates all scan phases and returns ScanResultV1.

**Key Functions**:
- `execute_scan()`: Main orchestrator function
  - Fetches repository via GitHub API
  - Lists and filters files
  - Extracts dependencies (deterministic)
  - Analyzes files with LLM (optional, advisory)
  - Evaluates compliance rules
  - Persists to Supabase (if project_id provided)
  - Returns ScanResultV1 (Phase 0 contract)
- `convert_scan_result_v1_to_scan_response()`: Legacy compatibility adapter

**Inputs**: 
- `repo_name`: "owner/repo" format
- `installation_id`: Optional GitHub App installation ID (None for public repos)
- `project_id`: Optional UUID for persistence
- `max_files`: Optional file limit
- `repo_url`: Repository URL/identifier
- `environment`: Deployment environment

**Outputs**: `ScanResultV1` object

**Invariants**:
- Always returns ScanResultV1 (even for ephemeral scans)
- `evaluated_at` is set once and reused in persistence
- Verdict is deterministic based on rule failures
- Ephemeral scans (no project_id) still return valid ScanResultV1
- Supports both public and private repository scanning

**Where Used**: Called by API endpoints (`/scan-repo`, `/v1/scans/run`)

---

### `app/services/compliance.py`

**Purpose**: Compliance rule evaluation engine - evaluates CRA rules against scan results.

**Key Functions**:
- `load_rules_db()`: Loads rules from `app/data/rules_db.json` (cached in memory)
- `check_applicability()`: Evaluates boolean logic conditions (AND/OR/NOT) to determine if rule applies
- `evaluate_dependency_rule()`: Evaluates dependency-related rules (CRA-BASE-002, CRA-BASE-003, CRA-BASE-009)
- `evaluate_finding_rule()`: Evaluates finding-based rules (CRA-BASE-008 for secrets)
- `evaluate_documentation_rule_with_llm()`: Uses LLM to evaluate documentation rules (CRA-BASE-001, CRA-BASE-007)
- `build_signals_from_scan()`: Extracts signals from scan results (has_security_policy, dependency_count, etc.)
- `evaluate_repo()`: Main evaluation function - iterates through all rules and evaluates them

**Inputs**:
- `findings`: List of security findings from LLM analysis
- `dependencies`: List of extracted dependencies
- `repo_files`: List of file paths in repository
- `repo`: Optional GitHub repo object
- `read_file_func`: Optional function to read file content

**Outputs**: Dictionary with `rule_results`, `evaluated_at`, counts (passed/failed/unknown/not_applicable)

**Invariants**:
- Rules are loaded once and cached
- Applicability is checked before evaluation
- UNKNOWN status is returned when evidence is insufficient
- LLM is only used for documentation quality checks (not for blocking decisions)

**Where Used**: Called by `execute_scan()` after file analysis completes

---

### `app/services/dependencies.py`

**Purpose**: Deterministic dependency extraction from package manifest files.

**Key Functions**:
- `extract_dependencies()`: Main entry point - detects file type and routes to parser
- `_parse_requirements_txt()`: Parses Python requirements.txt using regex
- `_parse_package_json()`: Parses Node.js package.json using JSON parsing
- `_parse_pyproject_toml()`: Parses Poetry pyproject.toml using regex (basic TOML parsing)

**Inputs**: 
- `file_path`: Path to manifest file
- `content`: File content as string

**Outputs**: List of dictionaries with keys: `name`, `version`, `type`, `file_source`

**Invariants**:
- No LLM or external API calls (fully deterministic)
- Handles version ranges, comments, and edge cases
- Returns empty list on parse failure (non-fatal)

**Where Used**: Called by `execute_scan()` when processing manifest files

---

### `app/services/llm.py`

**Purpose**: Optional LLM-based code analysis for advisory findings.

**Key Functions**:
- `analyze_file_with_llm()`: Sends code to OpenAI, enforces JSON output, retries on parse failure
- `normalize_findings()`: Validates and normalizes LLM output to Finding objects
- `make_parse_failure_finding()`: Creates fallback finding when LLM output is invalid

**Inputs**:
- `file_path`: Path to file being analyzed
- `file_content`: File content (truncated to MAX_CHARS_PER_FILE)

**Outputs**: List of `Finding` objects (severity: high/medium/low/info)

**Invariants**:
- Only low/info findings become advisory_findings (non-blocking)
- JSON output is enforced with retry logic
- Parse failures result in low-confidence info findings (non-fatal)
- File content is truncated to prevent token limits

**Where Used**: Called by `execute_scan()` for each text file (optional, can be skipped)

---

### `app/services/github.py`

**Purpose**: GitHub API client and repository file operations.

**Key Functions**:
- `get_github_client()`: Returns PyGithub client with flexible authentication:
  - **Public Mode** (installation_id=None): Uses GITHUB_TOKEN if available (5,000 req/hour), otherwise unauthenticated (60 req/hour)
  - **GitHub App Mode** (installation_id provided): Authenticates as GitHub App Installation
- `list_repo_files()`: Recursively lists all files in repository
- `read_repo_file()`: Reads file content with size limits and encoding handling
- `get_repo_commit_hash()`: Fetches HEAD commit SHA
- `is_text_file()`: Determines if file is text/code (by extension)
- `should_skip_path()`: Checks if path should be skipped (node_modules, .git, etc.)
- `truncate_for_llm()`: Truncates content for LLM while preserving context

**Inputs**: Repository object, file paths, optional installation_id
**Outputs**: File lists, file content, commit hashes

**Invariants**:
- Files exceeding MAX_FILE_BYTES return None (skipped)
- Content is truncated to MAX_CHARS_PER_FILE for LLM
- Encoding errors are handled gracefully (errors="ignore")
- 404 errors are handled gracefully with clear error messages suggesting installation_id for private repos

**Where Used**: Called by `execute_scan()` for repository access

---

### `app/services/database.py`

**Purpose**: Supabase database operations - all persistence logic.

**Key Functions**:
- `create_scan_record()`: Creates row in `scans` table, returns scan_id
- `update_scan_success()`: Updates scan status to "completed" with metrics
- `update_scan_failure()`: Updates scan status to "failed" with error message
- `update_project_last_scan()`: Updates project's last_scan_at timestamp
- `insert_findings()`: Bulk inserts findings with deduplication by fingerprint
- `bulk_insert_dependencies()`: Bulk inserts dependencies to `scan_dependencies` table
- `save_compliance_report()`: Saves compliance report and rule results to `compliance_reports` and `compliance_details`
- `generate_fingerprint()`: Creates SHA256 hash for finding deduplication
- `parse_line_number()`: Parses line numbers from "10-18" format

**Inputs**: Scan data, findings, dependencies, compliance reports
**Outputs**: Database record IDs (scan_id, report_id, etc.)

**Invariants**:
- All operations are non-fatal (exceptions logged but don't crash scan)
- Deduplication prevents duplicate findings
- Batch inserts are used for performance (100 items per batch)
- Supabase client is optional (ephemeral scans work without DB)

**Where Used**: Called by `execute_scan()` for persistence (only if project_id provided)

---

### `app/schemas/scan_result_v1.py`

**Purpose**: Phase 0 API contract - verdict-first response models.

**Key Models**:
- `ScanResultV1`: Main response model with verdict, rule_results, evidence_refs
- `RuleResultV1`: Individual rule evaluation result
- `EvidenceRefsV1`: References to stored evidence (scan_id, compliance_report_id)
- `AdvisoryFindingV1`: Non-blocking recommendations
- `ScanRunRequestV1`: V1 endpoint request model

**Invariants**:
- `evaluated_at` is validated to be timezone-aware (UTC)
- `verdict` is Literal["SHIP_ALLOWED", "SHIP_BLOCKED"]
- `environment` is Literal["dev", "staging", "production", "eu-production"]
- All fields are typed and validated by Pydantic

**Where Used**: Returned by `/v1/scans/run` endpoint, created by `execute_scan()`

---

### `app/core/config.py`

**Purpose**: Environment variable loading and service initialization.

**Key Components**:
- GitHub App credentials (GITHUB_APP_ID, GITHUB_PRIVATE_KEY)
- OpenAI client initialization (AsyncOpenAI)
- Supabase client initialization (optional, non-fatal on failure)
- CORS configuration (ALLOWED_ORIGINS)
- Safety limits (MAX_FILES, MAX_FILE_BYTES, MAX_CHARS_PER_FILE)
- Skip directories list (SKIP_DIRS)

**Invariants**:
- GitHub and OpenAI credentials are required (raises ValueError if missing)
- Supabase is optional (warns but doesn't crash)
- CORS defaults to ["*"] if ALLOWED_ORIGINS not set

**Where Used**: Imported by all service modules for configuration

---

### Knowledge Layer Files

**`eura_knowledge/schema_v0.1.json`**:
- JSON Schema (Draft 2020-12) defining Rule, Signal, Evidence, EvaluationResult structures
- Example rule and signal definitions
- Used as reference for rule structure

**`eura_knowledge/cra_rule_pack_v0.1.txt`**:
- Human-readable rule pack with 18 CRA rules
- Each rule includes: description, applicability, evidence requirements, remediation guidance
- Remediation catalog (REM-001 through REM-018)

**`app/data/rules_db.json`** (generated):
- Structured JSON database of rules (generated by `scripts/ingest_rules.py`)
- Contains rule objects matching schema_v0.1.json
- Loaded by `compliance.py` on first evaluation (cached in memory)

**`scripts/ingest_rules.py`**:
- Converts `cra_rule_pack_v0.1.txt` to `rules_db.json`
- Uses LLM to parse rule text into structured JSON
- Must be run before compliance evaluation works

---

## 6. Database Schema

### Tables and Relationships

#### `projects`
- **Primary Key**: `id` (UUID)
- **Fields**: `repo_url`, `last_scan_at`, other project metadata
- **Relationships**: One-to-many with `scans`
- **Mutability**: `last_scan_at` is updated on each scan

#### `scans`
- **Primary Key**: `id` (UUID, scan_id)
- **Foreign Keys**: `project_id` → `projects.id`
- **Fields**:
  - `status`: ENUM (queued|processing|completed|failed)
  - `repo_name`: Text
  - `installation_id`: BigInt
  - `commit_hash`: Text (Git SHA)
  - `total_files`: Integer
  - `analyzed_files`: Integer
  - `duration_ms`: Integer
  - `error`: Text (nullable)
  - `created_at`: Timestamp
- **Relationships**: 
  - One-to-many with `findings`
  - One-to-many with `scan_dependencies`
  - One-to-one with `compliance_reports`
- **Mutability**: Status and metrics updated during scan lifecycle

#### `scan_dependencies`
- **Primary Key**: `id` (UUID)
- **Foreign Keys**: 
  - `scan_id` → `scans.id`
  - `project_id` → `projects.id`
- **Fields**: `name`, `version`, `type`, `file_source`
- **Relationships**: Many-to-one with `scans`
- **Mutability**: Immutable after insert

#### `findings`
- **Primary Key**: `id` (UUID)
- **Foreign Keys**: 
  - `scan_id` → `scans.id`
  - `project_id` → `projects.id`
- **Fields**:
  - `severity`: ENUM (info|low|medium|high|critical)
  - `category`: ENUM (ai_act|cra|gdpr|security) - always "security" for LLM findings
  - `vuln_category`: Text (secrets|auth|crypto|injection|config|logging|dependency|other)
  - `title`, `summary`, `details`, `recommendation`
  - `confidence`: Double (0.0-1.0)
  - `file_path`, `line_number`, `code_snippet_before`
  - `evidence_json`: JSONB (full evidence array)
  - `fingerprint`: Text (SHA256 for deduplication)
- **Relationships**: Many-to-one with `scans`
- **Mutability**: Immutable after insert (deduplicated by fingerprint)

#### `compliance_reports`
- **Primary Key**: `id` (UUID, compliance_report_id)
- **Foreign Keys**: 
  - `scan_id` → `scans.id`
  - `project_id` → `projects.id`
- **Fields**:
  - `score`: Decimal (percentage of passed rules)
  - `summary`: Text (e.g., "5 passed, 2 failed, 10 unknown")
  - `evaluated_at`: Timestamp
  - `total_rules`, `passed`, `failed`, `unknown`, `not_applicable`: Integers
- **Relationships**: One-to-many with `compliance_details`
- **Mutability**: Immutable after insert

#### `compliance_details`
- **Primary Key**: `id` (UUID)
- **Foreign Keys**: 
  - `report_id` → `compliance_reports.id`
  - `scan_id` → `scans.id`
  - `project_id` → `projects.id`
- **Fields**:
  - `rule_id`: Text (e.g., "CRA-BASE-001")
  - `status`: Text (PASS|FAIL|UNKNOWN|NOT_APPLICABLE)
  - `confidence`: Double (0.0-1.0)
  - `reason`: Text (nullable)
  - `evaluated_at`: Timestamp
- **Relationships**: Many-to-one with `compliance_reports`
- **Mutability**: Immutable after insert

### Data Flow

1. **Scan Lifecycle**: `scans` row created with status="processing" → updated to "completed" or "failed"
2. **Dependencies**: Saved immediately when manifest files are parsed
3. **Findings**: Saved after LLM analysis completes (with deduplication)
4. **Compliance**: Saved after rule evaluation completes (report + details)

---

## 7. API Contract: ScanResultV1

### JSON Shape (Example Response)

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "project_id": null,
  "repo_url": "owner/repo",
  "commit_sha": "abc123def456789",
  "environment": "dev",
  "evaluated_at": "2024-12-21T12:00:00Z",
  "verdict": "SHIP_BLOCKED",
  "blocking_rules": ["CRA-BASE-008", "CRA-BASE-001"],
  "rule_results": [
    {
      "rule_id": "CRA-BASE-001",
      "title": "Security Policy Documentation Present",
      "description": "Repository must have a security policy document",
      "status": "FAIL",
      "is_blocking": true,
      "evidence": {
        "reason": "No SECURITY.md or security policy file found",
        "confidence": 0.9,
        "evaluated_at": "2024-12-21T12:00:00Z"
      }
    },
    {
      "rule_id": "CRA-BASE-002",
      "title": "Dependency Inventory (SBOM)",
      "description": "Maintain an inventory of all dependencies",
      "status": "PASS",
      "is_blocking": false,
      "evidence": {
        "reason": "Found 15 dependencies in manifest files",
        "confidence": 0.9,
        "evaluated_at": "2024-12-21T12:00:00Z"
      }
    }
  ],
  "evidence_refs": {
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "dependency_snapshot_id": "550e8400-e29b-41d4-a716-446655440000",
    "compliance_report_id": "660e8400-e29b-41d4-a716-446655440001"
  },
  "advisory_findings": [
    {
      "category": "security",
      "message": "Consider using environment variables for API keys",
      "file_path": "config.py",
      "line_start": 42,
      "line_end": 42,
      "suggested_fix": "Move API key to environment variable"
    }
  ]
}
```

### Field Explanations

- **`scan_id`**: UUID of the scan record (generated for ephemeral scans if not persisted)
- **`project_id`**: UUID of project (null for ephemeral scans via v1 endpoint)
- **`repo_url`**: Repository identifier (as provided in request)
- **`commit_sha`**: Git commit SHA that was evaluated (empty string if unavailable)
- **`environment`**: Deployment environment (dev/staging/production/eu-production)
- **`evaluated_at`**: UTC timestamp when evaluation completed (timezone-aware datetime)
- **`verdict`**: SHIP_ALLOWED or SHIP_BLOCKED (deterministic, based on rule failures)
- **`blocking_rules`**: List of rule IDs that are blocking shipping (empty if SHIP_ALLOWED)
- **`rule_results`**: Complete list of all rule evaluations (PASS/FAIL/NOT_APPLICABLE)
- **`evidence_refs`**: References to stored evidence in database (for retrieving full details)
- **`advisory_findings`**: Non-blocking recommendations (low/info severity findings from LLM)

### Design Principles

- **Verdict-First**: Clear shipping decision at top level
- **Deterministic**: Verdict and rule results are reproducible (no LLM in blocking decisions)
- **Advisory Separation**: LLM findings are advisory only (low/info), never block shipping
- **Evidence References**: Full evidence stored in DB, referenced by ID (not duplicated in response)

---

## 8. Operational Notes

### Railway Deployment

- **Procfile**: Defines `web: uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Environment Variables**: Set in Railway dashboard (same as .env file)
- **Auto-Deploy**: Pushes to main branch trigger automatic deployment
- **Logs**: Available in Railway dashboard, structured logging via Python logger

### CORS Boundary

- **Frontend (Lovable)**: Typically runs on different origin (e.g., lovable.app domain)
- **Backend (Railway)**: FastAPI server with CORS middleware
- **Configuration**: `ALLOWED_ORIGINS` env var (comma-separated) or defaults to ["*"]
- **Preflight**: OPTIONS requests handled by `options_preflight()` endpoint
- **Credentials**: `allow_credentials=True` in middleware

### Common Failure Modes and Debugging

#### Repository Fetch Fails
- **Symptom**: 404 error "Repository not found or not accessible"
- **Causes**: 
  - Invalid repo_name format
  - Private repo without installation_id (public repos can be scanned without installation_id)
  - installation_id doesn't have access to repository
  - Repository doesn't exist
- **Debug**: 
  - For public repos: Verify repo_name format, ensure repository is public
  - For private repos: Check GitHub App installation has access to repository, verify installation_id is correct
  - Check error message for specific guidance

#### Dependency Parsing Fails
- **Symptom**: No dependencies extracted, warning in logs
- **Causes**: Unsupported manifest format, malformed file, encoding issues
- **Debug**: Check logs for "Failed to extract dependencies", verify file format matches parser expectations
- **Impact**: Non-fatal, scan continues

#### LLM Analysis Fails
- **Symptom**: Parse failure findings, or no findings returned
- **Causes**: Invalid JSON from LLM, API rate limits, token limits exceeded
- **Debug**: Check logs for "JSON parse failed" or "LLM call failed", verify OPENAI_API_KEY is valid
- **Impact**: Non-fatal, scan continues with empty findings list

#### Supabase Insert Fails
- **Symptom**: Warning in logs, data not persisted
- **Causes**: Invalid credentials, network issues, constraint violations (duplicates)
- **Debug**: Check SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY, verify table schemas match
- **Impact**: Non-fatal for ephemeral scans, fatal for scans with project_id (should raise HTTPException)

#### Compliance Evaluation Fails
- **Symptom**: No compliance_report in response, warning in logs
- **Causes**: rules_db.json not found, invalid rule structure, LLM evaluation timeout
- **Debug**: Verify `app/data/rules_db.json` exists (run `scripts/ingest_rules.py`), check compliance.py logs
- **Impact**: Non-fatal, verdict defaults to SHIP_ALLOWED with empty rule_results

### Logging

- **Structured Logging**: Python `logging` module with logger name "repo-scanner"
- **Log Levels**: INFO (normal flow), WARNING (non-fatal issues), ERROR (failures), DEBUG (detailed tracing)
- **Key Log Points**: Scan start, repo fetch, file counts, dependency extraction, findings count, compliance evaluation, scan completion
- **Authentication Mode**: Logs indicate "public mode" vs "GitHub App mode" for debugging

### CI/CD Integration

**CI Gatekeeper Script** (`scripts/ci_gatekeeper.py`):
- Simulates a CI/CD pipeline step that calls the Phase 0 API contract
- Blocks deployment (exit code 1) if verdict is SHIP_BLOCKED
- Allows deployment (exit code 0) if verdict is SHIP_ALLOWED
- Fails closed (exit code 1) if API is unavailable or returns errors
- Usage:
  ```bash
  python scripts/ci_gatekeeper.py --repo_url owner/repo --environment production
  python scripts/ci_gatekeeper.py --repo_url owner/repo --environment production --installation_id 12345
  python scripts/ci_gatekeeper.py --repo_url owner/repo --environment production --api_url http://api.eura.com
  ```

---

## TODO: Code Improvements

The following items were identified during documentation and should be addressed:

1. **Missing rules_db.json**: The compliance service expects `app/data/rules_db.json` but it may not exist. Document that `scripts/ingest_rules.py` must be run first.

2. **Function Documentation**: Some functions in `scan_executor.py` and `compliance.py` could benefit from more detailed docstrings explaining edge cases.

3. **Error Handling**: Some database operations catch exceptions but don't distinguish between fatal and non-fatal errors clearly in logs.

4. **Dependency Parsing**: The pyproject.toml parser is basic (regex-based). Consider using a proper TOML library for production.

5. **Test Coverage**: Only Phase 0 contract tests exist. Consider adding tests for dependency parsing, compliance evaluation logic, and error handling paths.

6. **Frontend Integration**: Document how the Lovable React frontend integrates with the backend (if that code exists in this repo, it wasn't found).

7. **Environment Variable Validation**: Some env vars are required but validation happens at import time. Consider startup validation with clearer error messages.


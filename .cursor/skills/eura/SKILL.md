---
name: eura
description: EURA 2.0 Compliance Platform - EU CRA and AI Act compliance scanning. Use when working on backend services, rule evaluation, compliance logic, API endpoints, or regulatory compliance scanning. Coordinates specialized subagents for validation, testing, and security.
---

# EURA 2.0 Development Skill

You are working on **EURA**, an EU regulatory compliance scanning platform that evaluates software repositories against the **Cyber Resilience Act (CRA)** and **EU AI Act**.

## Quick Reference

| Resource | Location |
|----------|----------|
| PRD | `EURA_2.0_PRD.md` |
| Progress | `IMPLEMENTATION_STATUS.md` |
| Flow Logic | `docs/EURA_FLOW.md` |
| Architecture | `docs/WORKFLOW_AND_ARCHITECTURE.md` |
| Rules | `app/data/rules_db.json` |

## Available Subagents

EURA has specialized subagents for different tasks. Use them for thorough validation:

| Subagent | Invoke With | Purpose |
|----------|-------------|---------|
| **rule-validator** | `/rule-validator` | Validate rule implementations for determinism, evidence, status values |
| **compliance-tester** | `/compliance-tester` | Run scans, analyze results, verify verdict logic |
| **api-verifier** | `/api-verifier` | Check API endpoints match PRD contract |
| **prd-verifier** | `/prd-verifier` | Verify features match PRD specification |
| **security-auditor** | `/security-auditor` | Audit for secrets, auth issues, vulnerabilities |

### When to Use Subagents

```
Creating/modifying a rule?     → /rule-validator
Testing scan behavior?         → /compliance-tester  
Changing API endpoints?        → /api-verifier
Completing a feature?          → /prd-verifier
Touching auth/secrets/tokens?  → /security-auditor
```

### Orchestration Pattern

For complex changes, chain subagents:

1. **Implement** the feature
2. **Validate** with appropriate subagent (`/rule-validator`, `/api-verifier`)
3. **Test** with `/compliance-tester`
4. **Verify** against PRD with `/prd-verifier`
5. **Audit** security with `/security-auditor`

## Core Principles: "Code is Truth"

| Principle | Rule |
|-----------|------|
| **Determinism** | Same input → same output. No randomness in rules. |
| **Evidence** | Every `FAIL` must have concrete proof in `evidence` dict. |
| **LLM Boundaries** | LLM for doc quality only. Never for pass/fail decisions. |
| **Type Safety** | Pydantic everywhere. No `Any` types. |
| **Async** | All DB operations must be `async`. |

## Architecture

```
app/
├── api/routes.py              # 25+ REST endpoints
├── core/
│   ├── config.py             # Env vars, clients
│   └── logger.py             # Structured logging
├── data/rules_db.json        # 35 CRA rule definitions (BASE/SEC/VULN/DOC/LIFE)
├── schemas/
│   ├── api_v1.py            # Request/response models
│   └── scan_result_v1.py    # ScanResultV1 contract
└── services/
    ├── scan_executor.py      # Orchestration
    ├── rule_engine.py        # Rule evaluation (repo_scan_static, file_presence, dependency, content)
    ├── compliance_evaluation.py  # Verdict & scoring
    ├── dependencies.py       # Polyglot parsers (Python/Node/Java/Go/Rust/Ruby — 10 manifest types)
    ├── osv.py                # OSV vulnerability scanning (PyPI, npm, Go, crates.io, Maven, RubyGems, NuGet)
    ├── sbom.py               # SPDX 2.3 + CycloneDX 1.5 generation with purls for all ecosystems
    ├── sarif.py              # SARIF 2.1.0 export (rules + findings + vulns)
    ├── remediation_templates.py  # 5 compliance document generators
    ├── ai_detector.py        # AI/ML detection
    ├── database.py           # Supabase ops
    └── github.py             # GitHub API
```

## Common Tasks

### Development Commands

```bash
# Start server
uvicorn app.main:app --reload --port 8000

# Run all tests
pytest tests/ -v

# Run specific test files
pytest tests/test_phase0_contract.py -v
pytest tests/test_sbom.py -v
pytest tests/test_cra_rules.py -v    # 87 tests for CRA rule expansion
pytest tests/test_sarif.py -v        # 42 tests for SARIF 2.1.0 export
pytest tests/test_remediation.py -v  # 54 tests for remediation templates
pytest tests/test_dependency_parsers.py -v  # 59 tests for polyglot parsers
pytest tests/test_vex.py -v               # 42 tests for VEX (OpenVEX) export
pytest tests/test_csaf.py -v              # 47 tests for CSAF 2.0 export

# Local scan (CLI)
python -m cli.eura_cli scan ./path/to/repo
python -m cli.eura_cli scan . --format json
python -m cli.eura_cli scan . --environment production --output report.json
```

### GitHub Action (CI/CD)

```yaml
# In your .github/workflows/compliance.yml
- uses: your-org/eura/.github/actions/eura-scan@main
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  with:
    environment: production
    fail-on-block: true      # Fail workflow on SHIP_BLOCKED
    comment-on-pr: true      # Post summary as PR comment
```

### Key API Endpoints

```
POST /api/v1/scans/run          # Run compliance scan
GET  /api/v1/scans/{id}         # Get scan results
GET  /api/v1/rules              # List all rules
GET  /api/v1/rules?regulation=CRA  # Filter by regulation
POST /api/v1/sbom/generate      # Generate SBOM (✅ implemented)
GET  /api/v1/projects           # List projects
GET  /api/v1/badges/{project_id}          # SVG badge for project (✅ implemented)
GET  /api/v1/badges/scan/{scan_id}        # SVG badge for scan
GET  /api/v1/badges/repo/{owner}/{repo}   # SVG badge by repo name
```

### Compliance Artifact Exports (PRD 3.8)

Machine-readable exports for EU regulatory audits:

| Artifact | Endpoint | Status | Format |
|----------|----------|--------|--------|
| **SBOM** | `POST /api/v1/sbom/generate` | ✅ Done | CycloneDX/SPDX JSON |
| **OSV Vuln Scan** | (integrated into scans) | ✅ Done | osv.dev batch API |
| **VEX** | `POST /api/v1/exports/vex` | ✅ Done | OpenVEX JSON |
| **CSAF** | `POST /api/v1/exports/csaf` | ✅ Done | CSAF 2.0 JSON |
| **SARIF** | `POST /api/v1/exports/sarif` | ✅ Done | SARIF 2.1.0 JSON |
| **Model Card** | `POST /api/v1/exports/model-card` | 🔲 TODO | JSON/Markdown |
| **Risk Register** | `POST /api/v1/exports/risk-register` | 🔲 TODO | JSON/CSV |
| **Technical File** | `POST /api/v1/exports/technical-file` | 🔲 TODO | Markdown/PDF |

### Remediation Templates

Generate ready-to-commit compliance documents:

| Template | Endpoint | Filename | CRA Rules |
|----------|----------|----------|-----------|
| `security-md` | `POST /api/v1/remediation/generate` | SECURITY.md | CRA-BASE-001, CRA-VULN-001/002, CRA-BASE-014 |
| `changelog-md` | `POST /api/v1/remediation/generate` | CHANGELOG.md | CRA-BASE-005/017, CRA-VULN-004, CRA-LIFE-003 |
| `support-md` | `POST /api/v1/remediation/generate` | SUPPORT.md | CRA-LIFE-001/002, CRA-BASE-011 |
| `contributing-md` | `POST /api/v1/remediation/generate` | CONTRIBUTING.md | CRA-VULN-003 |
| `security-config` | `POST /api/v1/remediation/generate` | docs/security-configuration.md | CRA-DOC-001, CRA-SEC-004 |

List all: `GET /api/v1/remediation/templates`

**Cannot auto-generate** (requires user input):
- Art 12 Activity Logs (runtime data)
- Human Oversight Logs (intervention records)
- Training Data Provenance (dataset metadata)
- EU Declaration of Conformity (legal signature)

## CRA Rule Categories (35 rules)

| Category | IDs | CRA Article | Focus |
|----------|-----|-------------|-------|
| **BASE** (18) | CRA-BASE-001..018 | Art. 10-11 | Security policy, dependencies, secrets, CI/CD, containers, lifecycle |
| **SEC** (5) | CRA-SEC-001..005 | Art. 10(1) | Input validation, auth, least privilege, error handling, cryptography |
| **VULN** (4) | CRA-VULN-001..004 | Art. 11 | CVD process, security advisories, vulnerability tracking, patch SLA |
| **DOC** (4) | CRA-DOC-001..004 | Art. 13 | User security guide, API docs, architecture/threat model, install guide |
| **LIFE** (4) | CRA-LIFE-001..004 | Art. 12 | EOL policy, active maintenance, update notifications, migration support |

## Rule Implementation Guide

### Rule Result Structure

```python
RuleResult(
    rule_id="CRA-BASE-001",
    status="FAIL",  # PASS | FAIL | UNKNOWN | NOT_APPLICABLE
    confidence=0.9,
    evidence={
        "missing_file": "SECURITY.md",
        "searched_paths": ["./", ".github/", "docs/"]
    },
    reason="No SECURITY.md found in repository"
)
```

### Verdict Logic

```python
# Severity determines what blocks shipping
if severity == "critical":
    blocks = ["dev", "staging", "production", "eu-production"]
elif severity == "high":
    blocks = ["production", "eu-production"]  # warning only for dev/staging
else:  # medium, low
    blocks = []  # advisory only
```

### Creating a New Rule

1. Add rule definition to `app/data/rules_db.json`
2. Implement evaluator in `app/services/rule_engine.py`
3. Run `/rule-validator` to check compliance
4. Run `/compliance-tester` to verify behavior
5. Add tests if not covered

## Context Files

When working in specific areas, read these CONTEXT.md files:

| Area | Context File |
|------|--------------|
| Backend/API | `backend/CONTEXT.md` |
| Rules | `backend/app/rules/CONTEXT.md` |
| Frontend | `frontend/CONTEXT.md` |
| Infrastructure | `infrastructure/CONTEXT.md` |
| CI/CD | `.github/CONTEXT.md` |

## Environment Variables

Required in `.env`:

```env
# GitHub (required for private repos)
GITHUB_APP_ID=...
GITHUB_PRIVATE_KEY=...
GITHUB_TOKEN=...  # optional, for public repos

# OpenAI (required)
OPENAI_API_KEY=sk-...

# Supabase (required for persistence)
SUPABASE_URL=https://...supabase.co
SUPABASE_SERVICE_ROLE_KEY=...
```

## Workflow: Implementing a Feature

### Standard Workflow

```
1. Read PRD section for requirements
2. Implement the feature
3. Run tests: pytest tests/ -v
4. Run /compliance-tester (if rule-related)
5. Run /api-verifier (if API-related)
6. Run /prd-verifier to confirm compliance
7. Run /security-auditor (if touching auth/secrets)
```

### Parallel Validation

For comprehensive validation, run multiple subagents:

```
> Validate the new CRA-SEC-001 rule implementation. 
> Run rule-validator, compliance-tester, and security-auditor in parallel.
```

## Asking Questions

If requirements are unclear, ask:

- Which regulation? (CRA, AI Act, or both)
- Which environment? (dev, staging, production)
- Should this block shipping or be advisory?
- Is this a new rule or modifying existing?
- What evidence should be collected?

## Quick Debugging

| Symptom | Check |
|---------|-------|
| Scan returns wrong verdict | Verdict logic in `compliance_evaluation.py` |
| Rule always returns UNKNOWN | Evidence collection in `rule_engine.py` |
| API returns 500 | Logs + async/await patterns |
| Tests fail | `pytest tests/ -v --tb=short` |
| GitHub rate limited | Check `GITHUB_TOKEN` in `.env` |

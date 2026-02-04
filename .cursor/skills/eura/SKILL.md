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
├── data/rules_db.json        # Rule definitions
├── schemas/
│   ├── api_v1.py            # Request/response models
│   └── scan_result_v1.py    # ScanResultV1 contract
└── services/
    ├── scan_executor.py      # Orchestration
    ├── rule_engine.py        # Rule evaluation
    ├── compliance_evaluation.py  # Verdict & scoring
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

# Local scan (CLI)
python -m cli.eura_cli scan ./path/to/repo
python -m cli.eura_cli scan . --format json
```

### Key API Endpoints

```
POST /api/v1/scans/run          # Run compliance scan
GET  /api/v1/scans/{id}         # Get scan results
GET  /api/v1/rules              # List all rules
GET  /api/v1/rules?regulation=CRA  # Filter by regulation
POST /api/v1/sbom/generate      # Generate SBOM
GET  /api/v1/projects           # List projects
```

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

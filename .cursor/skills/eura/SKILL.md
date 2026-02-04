---
name: eura
description: EURA 2.0 Compliance Platform - EU CRA and AI Act compliance scanning. Use when working on backend services, rule evaluation, compliance logic, API endpoints, or anything related to regulatory compliance scanning.
---

# EURA 2.0 Development Skill

You are working on **EURA**, an EU regulatory compliance scanning platform that evaluates software repositories against the **Cyber Resilience Act (CRA)** and **EU AI Act**.

## Core Principles

### "Code is Truth" Philosophy

1. **Determinism** — Rule evaluations must be reproducible given same input
2. **Evidence-Based** — Every FAIL verdict must have concrete proof
3. **LLM for Quality Only** — LLM assists documentation quality checks, never determines pass/fail
4. **Typed Everything** — Pydantic models for all data, no `Any` types

## Architecture Overview

```
app/
├── api/routes.py           # REST API endpoints (FastAPI)
├── core/config.py          # Environment variables, clients
├── data/rules_db.json      # CRA/AI Act rule definitions
├── schemas/                # Pydantic request/response models
│   ├── api_v1.py          # API v1 schemas
│   └── scan_result_v1.py  # ScanResultV1 contract
└── services/
    ├── scan_executor.py    # Scan orchestration
    ├── rule_engine.py      # Rule evaluation engine
    ├── compliance_evaluation.py  # Verdict & scoring
    ├── ai_detector.py      # AI/ML framework detection
    ├── dependencies.py     # Dependency extraction
    ├── database.py         # Supabase operations
    └── github.py           # GitHub API client
```

## When Working on Backend

Read `backend/CONTEXT.md` for full rules. Key points:

- **Python 3.11+, FastAPI 0.104+, Pydantic v2**
- All DB operations must be `async`
- All API endpoints need explicit `response_model`
- Secrets via `app/core/config.py` only
- Structured JSON logging via `app/core/logger.py`

## When Working on Rules

Read `backend/app/rules/CONTEXT.md` for full rules. Key points:

- Rules return: `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`
- Every `FAIL` needs `evidence` dict with proof
- No randomness, no `time.now()` in evaluation
- LLM only for doc quality assessment

### Rule Result Structure

```python
RuleResult(
    rule_id="CRA-BASE-001",
    status="FAIL",  # or PASS, UNKNOWN, NOT_APPLICABLE
    confidence=0.9,
    evidence={"missing_file": "SECURITY.md", "searched_paths": ["./", ".github/"]},
    reason="No SECURITY.md found in repository"
)
```

## When Working on Frontend

Read `frontend/CONTEXT.md` for full rules. Key points:

- **React 18+, TypeScript strict, Vite**
- Shadcn/ui components, no manual CSS
- React Query for all API calls
- High-density data visualization

## Common Tasks

### Run the Server

```bash
uvicorn app.main:app --reload --port 8000
```

### Run Tests

```bash
pytest tests/ -v
pytest tests/test_phase0_contract.py -v  # Contract tests
pytest tests/test_sbom.py -v             # SBOM tests
```

### Run Local Scan (CLI)

```bash
python -m cli.eura_cli scan ./path/to/repo
python -m cli.eura_cli scan ./path/to/repo --format json
```

### Key API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/scans/run` | Run compliance scan |
| GET | `/api/v1/scans/{id}` | Get scan results |
| GET | `/api/v1/rules` | List all rules |
| POST | `/api/v1/sbom/generate` | Generate SBOM |

## Verdict Logic

```python
# Environment-aware blocking
if severity == "critical":
    blocks_all_environments = True
elif severity == "high":
    blocks_production_only = True  # dev/staging: warning only
elif severity in ("medium", "low"):
    advisory_only = True
```

## Key Files Reference

| File | Purpose |
|------|---------|
| `EURA_2.0_PRD.md` | Full technical requirements |
| `IMPLEMENTATION_STATUS.md` | Current progress |
| `docs/EURA_FLOW.md` | Compliance evaluation logic |
| `docs/WORKFLOW_AND_ARCHITECTURE.md` | System architecture |
| `app/data/rules_db.json` | Rule definitions |

## Environment Variables

Required in `.env`:
- `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY` — GitHub App auth
- `OPENAI_API_KEY` — LLM analysis
- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` — Database

## Asking Clarifying Questions

If requirements are unclear, ask the user:
- Which regulation (CRA, AI Act, or both)?
- Which environment (dev, staging, production)?
- Should this block shipping or be advisory?

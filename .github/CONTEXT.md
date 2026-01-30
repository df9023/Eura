# GitHub CI/CD Context

## 1. The Agent Persona

**The CI Enforcer** — owns GitHub Actions workflows, PR checks, and deployment gates. You ensure nothing ships without passing compliance verification. You are the last line of defense before code reaches production. Your workflows are deterministic, fast, and secure.

---

## 2. Technical Stack & Constraints

| Technology | Purpose |
|------------|---------|
| GitHub Actions | CI/CD orchestration |
| pytest | Python unit/integration tests |
| Jest | TypeScript/React tests |
| Docker | Container builds |
| EURA API | Compliance scanning |
| Vercel | Frontend deployment |
| Railway/AWS | Backend deployment |

**CI Performance Targets:**
- PR checks: <5 minutes
- Full test suite: <10 minutes
- Docker build: <3 minutes
- Compliance scan: <30 seconds

---

## 3. "Code is Truth" Rules

1. **Block on SHIP_BLOCKED** — CI MUST fail when EURA returns `SHIP_BLOCKED` verdict. No exceptions for production deployments. Dev/staging may have warnings but production is strict.

2. **PR Gates Required** — ALL pull requests MUST pass before merge:
   - ✅ Linting (ruff, eslint)
   - ✅ Type checking (mypy, tsc)
   - ✅ Unit tests (pytest, jest)
   - ✅ EURA compliance scan
   - ✅ Security scan (dependabot, CodeQL)

3. **Secrets in GitHub Secrets** — ALL secrets MUST use GitHub Secrets. Never in workflow files, never in environment files committed to repo. Reference via `${{ secrets.NAME }}`.

4. **Manual Approval for Production** — Deployment to production MUST require:
   - Passing compliance check
   - Manual approval from designated reviewers
   - Environment protection rules enabled

5. **Workflow Timeouts Required** — EVERY job MUST have `timeout-minutes` set:
   - Lint/type check: 10 minutes
   - Tests: 20 minutes
   - Build: 15 minutes
   - Deploy: 10 minutes

---

## 4. Key Files & Responsibilities

| File | Responsibility |
|------|----------------|
| `workflows/ci.yml` | Main CI pipeline: lint, type check, test, build |
| `workflows/compliance.yml` | EURA compliance scan on PR and push |
| `workflows/deploy-staging.yml` | Auto-deploy to staging on main branch |
| `workflows/deploy-production.yml` | Manual production deployment with approval |
| `workflows/security.yml` | CodeQL and dependency scanning |
| `actions/eura-scan/action.yml` | Reusable EURA compliance action |
| `CODEOWNERS` | Required reviewers per directory |
| `dependabot.yml` | Automated dependency updates |

---

## Quick Reference

```yaml
# GOOD: Complete CI workflow with all gates
name: CI

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install ruff mypy
      - run: ruff check .
      - run: mypy app/

  test:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v --cov=app

  compliance:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - name: Run EURA Compliance Scan
        uses: ./.github/actions/eura-scan
        with:
          api_key: ${{ secrets.EURA_API_KEY }}
          environment: ${{ github.ref == 'refs/heads/main' && 'staging' || 'dev' }}
      - name: Check Verdict
        if: always()
        run: |
          if [ "${{ steps.scan.outputs.verdict }}" == "SHIP_BLOCKED" ]; then
            echo "::error::Compliance check failed. Blocking rules: ${{ steps.scan.outputs.blocking_rules }}"
            exit 1
          fi
```

```yaml
# GOOD: Reusable EURA scan action
# .github/actions/eura-scan/action.yml
name: 'EURA Compliance Scan'
description: 'Check repository compliance with EU CRA and AI Act'

inputs:
  api_url:
    description: 'EURA API URL'
    required: false
    default: 'https://api.eura.dev'
  api_key:
    description: 'EURA API key'
    required: true
  environment:
    description: 'Target environment (dev, staging, production)'
    required: false
    default: 'production'
  regulations:
    description: 'Comma-separated regulations to check'
    required: false
    default: 'CRA,AI_ACT'

outputs:
  verdict:
    description: 'SHIP_ALLOWED or SHIP_BLOCKED'
  score:
    description: 'Compliance score (0-100)'
  blocking_rules:
    description: 'List of blocking rule IDs'

runs:
  using: 'composite'
  steps:
    - name: Run Compliance Scan
      id: scan
      shell: bash
      run: |
        response=$(curl -s -X POST "${{ inputs.api_url }}/api/v1/scans/run" \
          -H "Authorization: Bearer ${{ inputs.api_key }}" \
          -H "Content-Type: application/json" \
          -d '{
            "repo_url": "${{ github.repository }}",
            "environment": "${{ inputs.environment }}",
            "regulations": ["CRA", "AI_ACT"]
          }')
        
        echo "verdict=$(echo $response | jq -r '.verdict')" >> $GITHUB_OUTPUT
        echo "score=$(echo $response | jq -r '.compliance_scores.CRA')" >> $GITHUB_OUTPUT
        echo "blocking_rules=$(echo $response | jq -r '.blocking_rules | join(",")')" >> $GITHUB_OUTPUT
```

```yaml
# GOOD: Production deployment with approval gate
name: Deploy Production

on:
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to deploy'
        required: true

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/eura-scan
        with:
          api_key: ${{ secrets.EURA_API_KEY }}
          environment: production

  deploy:
    needs: compliance-check
    runs-on: ubuntu-latest
    timeout-minutes: 15
    environment:
      name: production
      url: https://api.eura.com
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to Production
        run: |
          echo "Deploying version ${{ inputs.version }}"
          # Deployment commands here
```

---

## PR Check Status Display

```
┌─────────────────────────────────────────────────────────┐
│ Pull Request #123: Add new CRA rule                     │
├─────────────────────────────────────────────────────────┤
│ Checks                                                  │
│ ├── ✅ lint (2m 15s)                                    │
│ ├── ✅ type-check (1m 42s)                              │
│ ├── ✅ test (8m 33s) - 142 passed                       │
│ ├── ✅ compliance (28s) - SHIP_ALLOWED, Score: 94%      │
│ └── ✅ security (3m 12s) - No vulnerabilities           │
├─────────────────────────────────────────────────────────┤
│ ✅ All checks passed — Ready to merge                   │
└─────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────┐
│ Pull Request #124: Remove SECURITY.md (bad idea)        │
├─────────────────────────────────────────────────────────┤
│ Checks                                                  │
│ ├── ✅ lint (2m 15s)                                    │
│ ├── ✅ type-check (1m 42s)                              │
│ ├── ✅ test (8m 33s) - 142 passed                       │
│ ├── ❌ compliance (28s) - SHIP_BLOCKED                  │
│ │      └── Blocking: CRA-BASE-001 (SECURITY.md missing) │
│ └── ✅ security (3m 12s)                                │
├─────────────────────────────────────────────────────────┤
│ ❌ Some checks failed — Cannot merge                    │
└─────────────────────────────────────────────────────────┘
```

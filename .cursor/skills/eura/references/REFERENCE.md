# EURA Reference Documentation

This reference provides quick lookup for common EURA development tasks.

## Rule Status Values

| Status | Meaning | Blocks Shipping? |
|--------|---------|------------------|
| `PASS` | Rule satisfied | No |
| `FAIL` | Rule violated | Yes (if severity high/critical) |
| `UNKNOWN` | Cannot determine | No (needs review) |
| `NOT_APPLICABLE` | Rule doesn't apply | No |

## Severity Levels

| Severity | Blocks Dev | Blocks Staging | Blocks Production |
|----------|------------|----------------|-------------------|
| `critical` | Yes | Yes | Yes |
| `high` | No | No | Yes |
| `medium` | No | No | No |
| `low` | No | No | No |

## CRA Rule Categories

| Prefix | Article | Category |
|--------|---------|----------|
| `CRA-SEC-*` | Art. 10 | Security-by-Design |
| `CRA-VULN-*` | Art. 11 | Vulnerability Handling |
| `CRA-DOC-*` | Art. 13 | Documentation |
| `CRA-SBOM-*` | Art. 10 | Software Bill of Materials |
| `CRA-LIFE-*` | Art. 12 | Lifecycle Management |

## AI Act Rule Categories

| Prefix | Scope |
|--------|-------|
| `AI-ACT-CLASS-*` | AI System Classification |
| `AI-ACT-HR-*` | High-Risk AI Requirements |
| `AI-ACT-LR-*` | Limited-Risk AI Requirements |
| `AI-ACT-GPAI-*` | General-Purpose AI Models |

## AI Risk Classifications

| Classification | Definition |
|----------------|------------|
| `prohibited` | Banned AI practices (social scoring, manipulation) |
| `high_risk` | Critical applications (biometrics, healthcare, law enforcement) |
| `limited_risk` | Requires transparency (chatbots, deepfakes) |
| `minimal_risk` | No specific requirements |

## API Response Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `201` | Created |
| `400` | Bad request (validation error) |
| `404` | Resource not found |
| `500` | Internal server error |
| `503` | Service unavailable (GitHub/OpenAI down) |

## Database Tables

| Table | Purpose |
|-------|---------|
| `organizations` | Multi-tenant orgs |
| `projects` | Project containers |
| `repositories` | Git repos linked to projects |
| `scans` | Scan records |
| `rule_results` | Individual rule evaluations |
| `findings` | Security findings |
| `scan_dependencies` | Extracted dependencies |
| `compliance_reports` | Compliance summaries |
| `compliance_details` | Rule-level report details |
| `ai_systems` | Detected AI systems |
| `model_cards` | AI model documentation |

## File Extensions for AI Detection

**Model Files:**
`.h5`, `.pkl`, `.onnx`, `.pb`, `.pt`, `.pth`, `.safetensors`, `.gguf`, `.bin`

**Training Indicators:**
`train.py`, `training.py`, `trainer.py`, `*_train.py`

**AI Framework Packages:**
- Python: `tensorflow`, `torch`, `keras`, `sklearn`, `transformers`, `openai`, `langchain`
- Node: `@tensorflow/tfjs`, `brain.js`, `ml5`
- Java: `deeplearning4j`

## Manifest Files

| File | Ecosystem |
|------|-----------|
| `requirements.txt` | Python (pip) |
| `pyproject.toml` | Python (Poetry/modern) |
| `package.json` | Node.js |
| `pom.xml` | Java (Maven) |
| `build.gradle` | Java (Gradle) |
| `go.mod` | Go |
| `Cargo.toml` | Rust |
| `Gemfile` | Ruby |

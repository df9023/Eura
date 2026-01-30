# Eura-Flow: Compliance Evaluation Logic

**Version:** 1.0  
**Date:** January 30, 2026  
**Purpose:** Define exactly how Eura determines CRA and AI Act compliance

---

## 1. Overview

Eura evaluates repository compliance through a **deterministic, evidence-based pipeline**:

```
Repository → Signal Extraction → Rule Evaluation → Verdict
```

Every verdict is backed by concrete evidence. Rules are either:
- **Deterministic** (file presence, dependency count, pattern matching) — no LLM needed
- **LLM-assisted** (documentation quality, security posture) — LLM provides confidence score

**No RAG required** for core compliance. LLM is used only for "soft" quality checks where human judgment would otherwise be needed.

---

## 2. Signal Extraction Pipeline

### 2.1 What We Extract Automatically

| Signal Category | Signals | Source |
|----------------|---------|--------|
| **Files** | `file_list`, `has_security_md`, `has_readme`, `has_changelog`, `has_license`, `has_dockerfile`, `has_cicd_config` | FileDiscoveryService |
| **Dependencies** | `dependency_count`, `dependencies[]`, `has_lockfile`, `ecosystems[]` | DependencyExtractor |
| **SBOM** | `sbom_component_count`, `sbom_licenses[]`, `sbom_purls[]` | SBOM Service |
| **Secrets** | `has_secrets`, `secret_count`, `secret_types[]` | SecretDetector |
| **AI/ML** | `has_ai`, `ai_frameworks[]`, `model_files[]`, `training_files[]`, `inference_files[]`, `ai_confidence` | AIDetector |
| **Code patterns** | `has_auth_code`, `has_encryption_imports`, `has_logging` | Pattern matching (future) |

### 2.2 Signal Extraction Code Flow

```
1. GitHub API → list files
2. For each file:
   a. FileDiscoveryService → categorize (manifest, config, doc, code)
   b. If manifest → DependencyExtractor → dependencies[]
   c. If code → SecretDetector → secrets[]
   d. If code → AIDetector → ai_imports[]
3. AIDetector.detect_ai_components() → comprehensive AI signals
4. Generate SBOM from dependencies → sbom signals
5. Build signals dict for rule evaluation
```

### 2.3 SBOM-Derived Signals

CycloneDX provides these compliance-relevant fields:

| CycloneDX Field | Compliance Signal | Used By Rules |
|-----------------|-------------------|---------------|
| `components[].name` | Package inventory | CRA-SBOM-001 |
| `components[].version` | Version pinning check | CRA-BASE-009 |
| `components[].purl` | Vulnerability lookup (future) | CRA-BASE-003 |
| `components[].licenses` | License compliance (future) | CRA-SBOM-003 |
| `metadata.timestamp` | SBOM freshness | CRA-SBOM-002 |
| `dependencies[]` | Dependency graph (future) | CRA-SBOM-002 |

**Current:** We generate SBOM from extracted dependencies.  
**Future:** Parse external SBOMs if provided; add license detection; integrate vulnerability DB via purl lookup.

---

## 3. CRA Compliance Rules

### 3.1 Rule Categories and Evaluation Method

| Category | Article | Rule IDs | Evaluation Method |
|----------|---------|----------|-------------------|
| **Security-by-Design** | Art. 10 | CRA-SEC-* | File presence + pattern matching |
| **Vulnerability Handling** | Art. 11 | CRA-VULN-* | File presence + LLM quality check |
| **Documentation** | Art. 13 | CRA-DOC-* | File presence + LLM quality check |
| **SBOM** | Art. 10 | CRA-SBOM-* | SBOM analysis (deterministic) |
| **Lifecycle** | Art. 12 | CRA-LIFE-* | File presence + git metadata |

### 3.2 Deterministic Rules (No LLM)

These rules PASS/FAIL based solely on extracted signals:

#### CRA-SBOM-001: Dependency Manifest Present
```
IF dependency_count > 0:
    PASS (evidence: manifest files found)
ELIF has_lockfile:
    PASS (evidence: lockfile found)
ELSE:
    FAIL (evidence: no manifest or lockfile)
```

#### CRA-SBOM-002: Complete Dependency Tree
```
IF sbom_component_count > 0:
    PASS (evidence: SBOM generated with N components)
ELSE:
    FAIL (evidence: cannot generate SBOM)
```

#### CRA-SBOM-004: SBOM Exportable
```
ALWAYS PASS (evidence: Eura can export SPDX 2.3 and CycloneDX 1.5)
```

#### CRA-BASE-001: Security Policy (SECURITY.md)
```
IF "SECURITY.md" OR ".github/SECURITY.md" OR "docs/SECURITY.md" in file_list:
    PASS (evidence: file path)
ELSE:
    FAIL (evidence: file not found)
```

#### CRA-BASE-008: No Hardcoded Secrets
```
IF secret_count == 0:
    PASS (evidence: no secrets detected)
ELIF secret_count > 0 AND all secrets have confidence < 0.7:
    UNKNOWN (evidence: possible false positives)
ELSE:
    FAIL (evidence: N secrets detected, types: [...])
```

#### CRA-BASE-009: Dependency Pinning
```
FOR each dependency:
    IF version contains "^" OR "~" OR "*" OR "latest":
        unpinned_count += 1
IF unpinned_count == 0:
    PASS
ELIF unpinned_count / total < 0.1:
    PASS (warning: some deps unpinned)
ELSE:
    FAIL (evidence: N unpinned dependencies)
```

### 3.3 LLM-Assisted Rules

These rules use LLM to assess quality/completeness with a confidence score:

#### CRA-VULN-002: Vulnerability Disclosure Process
```
1. Find SECURITY.md content
2. LLM prompt:
   "Analyze this SECURITY.md file. Does it contain:
    1. How to report vulnerabilities (email/form/process)
    2. Response time commitment
    3. Scope of what to report
   
   Return JSON: {
     "has_reporting_process": bool,
     "has_response_time": bool,
     "has_scope": bool,
     "confidence": 0.0-1.0,
     "summary": string
   }"

3. IF all true AND confidence >= 0.7:
     PASS
   ELIF some true:
     UNKNOWN (partial compliance)
   ELSE:
     FAIL
```

#### CRA-DOC-001: Security Documentation Quality
```
1. Find docs/security.md OR README.md security section
2. LLM prompt:
   "Analyze this documentation for security guidance. Does it explain:
    1. Security features of the product
    2. How to configure securely
    3. Security considerations for deployment
   
   Return JSON: {
     "has_security_features": bool,
     "has_secure_config_guide": bool,
     "has_deployment_security": bool,
     "confidence": 0.0-1.0,
     "summary": string
   }"

3. Score based on coverage and confidence
```

### 3.4 CRA Rule Summary Table

| Rule ID | Title | Method | Signals Used |
|---------|-------|--------|--------------|
| CRA-SBOM-001 | Manifest Present | Deterministic | `dependency_count`, `has_lockfile` |
| CRA-SBOM-002 | Dependency Tree | Deterministic | `sbom_component_count` |
| CRA-SBOM-003 | License Info | Deterministic | `sbom_licenses[]` (future) |
| CRA-SBOM-004 | SBOM Export | Deterministic | Always PASS (Eura capability) |
| CRA-BASE-001 | Security Policy | Deterministic | `file_list` |
| CRA-BASE-002 | Dependency Inventory | Deterministic | `dependency_count` |
| CRA-BASE-003 | Vuln Management | Deterministic + Future | `vulnerabilities[]` (needs OSV) |
| CRA-BASE-008 | No Hardcoded Secrets | Deterministic | `secret_count`, `secrets[]` |
| CRA-BASE-009 | Dependency Pinning | Deterministic | `dependencies[]` (version check) |
| CRA-VULN-001 | SECURITY.md Present | Deterministic | `file_list` |
| CRA-VULN-002 | Disclosure Process | LLM-assisted | SECURITY.md content |
| CRA-DOC-001 | Security Docs | LLM-assisted | docs content |
| CRA-LIFE-001 | Update Procedures | LLM-assisted | CHANGELOG.md, docs |

---

## 4. AI Act Compliance Rules

### 4.1 AI System Detection Flow

```
1. Check dependencies for AI frameworks:
   - Python: tensorflow, torch, keras, sklearn, transformers, openai, langchain
   - Node: @tensorflow/tfjs, brain.js
   - Java: deeplearning4j
   
2. Check for model files:
   - Extensions: .h5, .pkl, .onnx, .pb, .pt, .safetensors, .gguf
   
3. Check for training/inference code:
   - Files: train.py, training.py, predict.py, inference.py
   - Patterns: model.fit(), model.predict(), model.forward()

4. Calculate AI confidence:
   - +0.4 if frameworks detected
   - +0.3 if model files found
   - +0.2 if training code found
   - +0.1 if inference code found
   
5. IF ai_confidence >= 0.3:
     has_ai = true
     → trigger AI Act rules
```

### 4.2 AI System Classification

```
FUNCTION classify_ai_system(frameworks, signals):
    
    # Check for prohibited use indicators (manual override required)
    # These cannot be auto-detected reliably
    
    # High-risk indicators
    high_risk_frameworks = {transformers, langchain, llama-index, openai, anthropic}
    
    IF framework in high_risk_frameworks:
        IF has_model_files OR has_training_code:
            classification = "high_risk"
        ELSE:
            classification = "limited_risk"
    ELIF has_model_files:
        classification = "limited_risk"
    ELIF frameworks:
        classification = "minimal_risk"
    ELSE:
        classification = "not_ai"
    
    RETURN classification
```

### 4.3 AI Act Rules by Classification

| Classification | Required Rules | Evaluation |
|---------------|----------------|------------|
| **Prohibited** | Manual review required | Cannot auto-detect social scoring, manipulation, etc. |
| **High-Risk** | AI-ACT-HR-001 to HR-010 | Documentation checks + LLM quality |
| **Limited-Risk** | AI-ACT-LR-001 to LR-003 | Disclosure/transparency checks |
| **Minimal-Risk** | None required | Advisory only |

### 4.4 High-Risk AI Rules

#### AI-ACT-HR-001: Risk Management Documentation
```
IF classification == "high_risk":
    LOOK FOR: risk*.md, risk-management.md, RISK.md in file_list
    
    IF found:
        LLM: "Does this document describe risks, mitigations, and residual risks?"
        IF yes with confidence >= 0.7:
            PASS
        ELSE:
            FAIL (incomplete risk documentation)
    ELSE:
        FAIL (no risk documentation found)
ELSE:
    NOT_APPLICABLE
```

#### AI-ACT-HR-003: Technical Documentation (Model Card)
```
IF classification == "high_risk":
    LOOK FOR: MODEL_CARD.md, model-card.*, modelcard.* in file_list
    
    IF found:
        LLM: "Does this model card contain:
              1. Model architecture
              2. Training data description
              3. Performance metrics
              4. Limitations and biases
              5. Intended use cases"
        
        Score = count(true items) / 5
        IF Score >= 0.8: PASS
        ELIF Score >= 0.6: UNKNOWN (partial)
        ELSE: FAIL
    ELSE:
        FAIL (no model card found)
ELSE:
    NOT_APPLICABLE
```

### 4.5 Limited-Risk AI Rules

#### AI-ACT-LR-001: AI Disclosure
```
IF classification in ("high_risk", "limited_risk"):
    LOOK FOR in code/docs:
        - "powered by AI"
        - "AI-generated"
        - "machine learning"
        - Disclosure statement
    
    IF found:
        PASS (evidence: disclosure location)
    ELSE:
        FAIL (no AI disclosure found)
ELSE:
    NOT_APPLICABLE
```

---

## 5. LLM Usage Strategy

### 5.1 When to Use LLM

| Use Case | LLM Required | Reason |
|----------|--------------|--------|
| File presence check | No | Deterministic |
| Dependency parsing | No | Deterministic |
| Secret detection | No | Pattern matching |
| AI framework detection | No | Package name matching |
| Documentation quality | **Yes** | Human judgment needed |
| Security policy adequacy | **Yes** | Content analysis |
| Risk assessment quality | **Yes** | Content analysis |
| Use case classification | **Partial** | Framework gives hints; LLM confirms |

### 5.2 LLM Prompt Templates

All LLM calls return structured JSON for deterministic processing:

```python
PROMPT_TEMPLATE = """
You are a compliance analyst. Analyze the following {doc_type} for {regulation} compliance.

Document content:
{content}

Check for the following requirements:
{requirements_list}

Return ONLY valid JSON:
{{
  "requirements": {{
    "requirement_1": {{"present": bool, "evidence": "quote or null"}},
    "requirement_2": {{"present": bool, "evidence": "quote or null"}},
    ...
  }},
  "overall_confidence": 0.0-1.0,
  "summary": "one sentence"
}}
"""
```

### 5.3 LLM Confidence Thresholds

| Confidence | Interpretation | Rule Status |
|------------|----------------|-------------|
| >= 0.8 | High confidence | PASS or FAIL (deterministic) |
| 0.5 - 0.79 | Medium confidence | Include in result with warning |
| < 0.5 | Low confidence | UNKNOWN (needs human review) |

### 5.4 RAG: Not Required

**Why no RAG:**
1. Regulation text is static — can be embedded in prompts
2. Rule definitions are in `rules_db.json` — deterministic lookup
3. LLM only evaluates document quality, not regulation interpretation
4. Adding RAG would increase latency and cost without improving accuracy

**When RAG might help (future):**
- User asks "What does Article 10(3) require?" → RAG could fetch exact text
- Custom enterprise policies need to be checked → RAG over policy docs
- But core compliance checking remains deterministic + LLM quality checks

---

## 6. Verdict Generation

### 6.1 Verdict Logic

```python
def generate_verdict(rule_results, environment):
    blocking_rules = []
    
    for result in rule_results:
        if result.status != "FAIL":
            continue
        
        severity = get_rule_severity(result.rule_id)
        
        # Critical always blocks
        if severity == "critical":
            blocking_rules.append(result.rule_id)
        
        # High blocks in production only
        elif severity == "high":
            if environment in ("production", "eu-production"):
                blocking_rules.append(result.rule_id)
    
    if blocking_rules:
        return "SHIP_BLOCKED", blocking_rules
    else:
        return "SHIP_ALLOWED", []
```

### 6.2 Severity Mapping

| Severity | Blocks Dev | Blocks Staging | Blocks Production |
|----------|------------|----------------|-------------------|
| Critical | Yes | Yes | Yes |
| High | No | No | Yes |
| Medium | No | No | No |
| Low | No | No | No |

### 6.3 Per-Regulation Scores

```
CRA Score = (passed_weight / total_weight) * 100
AI Act Score = (passed_weight / total_weight) * 100

where weight = {critical: 4, high: 3, medium: 2, low: 1}
```

---

## 7. Implementation Checklist

### 7.1 Currently Implemented ✅

- [x] File discovery and categorization
- [x] Dependency extraction (Python, Node, Poetry)
- [x] SBOM generation (SPDX 2.3, CycloneDX 1.5)
- [x] Secret detection with confidence scoring
- [x] AI/ML framework and model file detection
- [x] AI system classification
- [x] 18 CRA-BASE rules in rules_db.json
- [x] Parallel rule evaluation
- [x] Verdict generation with environment awareness
- [x] Compliance scoring

### 7.2 To Implement 🔲

**Phase 1 (Priority):**
- [ ] Version pinning check (CRA-BASE-009) — parse version strings
- [ ] LLM documentation quality prompts
- [ ] Structured LLM response parsing
- [ ] License detection from manifest files

**Phase 2:**
- [ ] OSV/Snyk integration for vulnerability data (CRA-BASE-003)
- [ ] More AI Act rules (AI-ACT-HR-002 through HR-010)
- [ ] Limited-risk AI disclosure check
- [ ] Model card validation

**Phase 3:**
- [ ] Additional dependency parsers (Java, Go, Rust)
- [ ] Transitive dependency resolution
- [ ] External SBOM parsing (accept user-provided SBOM)
- [ ] CI/CD integration

---

## 8. Rule Definition Schema

All rules follow this JSON schema (in `rules_db.json`):

```json
{
  "rule_id": "CRA-SBOM-001",
  "title": "Dependency Manifest Present",
  "description_short": "Repository must have dependency manifest files",
  "description_long": "...",
  "regulation": "CRA",
  "article": "Article 10",
  "evaluation_method": "deterministic",  // or "llm_assisted"
  "signals_required": ["dependency_count", "has_lockfile"],
  "severity": {
    "impact": "high",
    "likelihood": "high",
    "overall": "high"
  },
  "applicability": {
    "operator": "OR",
    "conditions": [
      {"signal": "dependency_count", "operator": "greater_than", "value": 0},
      {"signal": "has_lockfile", "operator": "exists"}
    ]
  },
  "evaluation_logic": {
    "pass_if": "dependency_count > 0 OR has_lockfile",
    "fail_if": "dependency_count == 0 AND NOT has_lockfile"
  },
  "remediation_guidance": {
    "steps": ["Create requirements.txt or package.json", "..."],
    "examples": ["..."]
  }
}
```

---

## 9. Summary

**Eura Vision:**

1. **Deterministic first** — most rules are simple signal checks (file exists, count > 0, pattern found)
2. **LLM for quality** — documentation adequacy, security guidance completeness
3. **No RAG needed** — regulation is static; LLM only judges document quality
4. **Evidence-based** — every verdict cites specific files, counts, or quotes
5. **Environment-aware** — dev is lenient, production is strict
6. **SBOM-integrated** — CycloneDX purl enables future vulnerability lookup

**The logic is sound if:**
- Signals are extracted correctly (tested in extraction services)
- Rule conditions match regulation requirements (verified against CRA/AI Act text)
- LLM prompts return structured, parseable JSON
- Confidence thresholds are calibrated over time

---

**Document Owner:** Eura Team  
**Last Updated:** January 30, 2026

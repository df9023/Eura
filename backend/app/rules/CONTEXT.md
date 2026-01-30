# Rules Engine Context

## 1. The Agent Persona

**The Logic Gatekeeper** — owns the rule engine, compliance evaluation, and verdict generation. You guard against non-determinism, hallucinations, and ambiguity. Every verdict you produce must be backed by concrete, verifiable evidence. You are the arbiter of truth for CRA and AI Act compliance.

---

## 2. Technical Stack & Constraints

| Component | Technology | Purpose |
|-----------|------------|---------|
| Rule Definitions | JSON (`rules_db.json`) | Declarative rule specifications |
| Evaluation Engine | `asyncio.gather()` | Parallel rule evaluation |
| Signal Builder | Python dataclasses | Extract signals from scan results |
| Evidence Collector | Python dicts | Gather proof for each rule |
| LLM Integration | OpenAI API | Documentation quality checks ONLY |
| Confidence Scoring | float (0.0-1.0) | Certainty of evaluation |

**Rule Categories:**
- CRA Rules: CRA-BASE-*, CRA-SEC-*, CRA-VULN-*, CRA-DOC-*, CRA-SBOM-*, CRA-LIFE-*
- AI Act Rules: AI-ACT-CLASS-*, AI-ACT-HR-*, AI-ACT-LR-*, AI-ACT-GPAI-*

---

## 3. "Code is Truth" Rules

1. **Determinism is Mandatory** — Rule evaluations MUST be reproducible. Given the same input signals and evidence, the same verdict MUST be returned. No randomness, no `time.now()` in evaluation logic, no external API calls during rule execution (except pre-approved LLM calls for doc quality).

2. **Evidence Required for FAIL** — Every `FAIL` verdict MUST have an `evidence` field containing concrete proof: file paths, line numbers, code snippets, dependency names, or specific missing items. "Failed because it failed" is forbidden.

3. **LLM for Quality, Not Verdicts** — LLM MAY ONLY be used for documentation quality assessment (e.g., "Is this SECURITY.md complete?"). LLM MUST NEVER determine pass/fail verdicts directly. The rule logic makes the final call based on LLM confidence scores.

4. **Four Valid Statuses** — All rules MUST return exactly one of:
   - `PASS` — Rule satisfied with evidence
   - `FAIL` — Rule violated with evidence
   - `UNKNOWN` — Cannot determine (low confidence or missing data)
   - `NOT_APPLICABLE` — Rule does not apply to this repository

5. **No Side Effects** — Rule evaluation MUST NOT modify any state. No database writes, no file writes, no external API calls that change state. Rules are pure functions: `(signals, evidence) → RuleResult`.

---

## 4. Key Files & Responsibilities

| File | Responsibility |
|------|----------------|
| `rule_engine.py` | Core engine: `RuleModule`, `RuleEvaluationEngine`, `SignalBuilder`, `EvidenceCollector`, `RuleLoader` |
| `ai_act_rules.py` | AI Act specific rules: `AIClassificationRule`, `HighRiskAIDocumentationRule` |
| `compliance_evaluation.py` | `VerdictGenerator` (SHIP_ALLOWED/SHIP_BLOCKED) and `ComplianceScorer` (0-100 weighted score) |
| `compliance.py` | Legacy compliance checks (to be migrated to RuleModule pattern) |
| `../data/rules_db.json` | JSON rule definitions with schema, conditions, and remediation guidance |

---

## Rule Evaluation Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐     ┌────────────┐
│ Scan Result │ ──▶ │ SignalBuilder │ ──▶ │ EvidenceCollector│ ──▶ │ RuleModule │
└─────────────┘     └──────────────┘     └─────────────────┘     └────────────┘
                                                                        │
                    ┌──────────────────┐     ┌────────────────┐        │
                    │ ComplianceScorer │ ◀── │ VerdictGenerator│ ◀─────┘
                    └──────────────────┘     └────────────────┘
                            │
                            ▼
                    ┌──────────────────┐
                    │ SHIP_ALLOWED or  │
                    │ SHIP_BLOCKED     │
                    └──────────────────┘
```

---

## Quick Reference

```python
# GOOD: Deterministic rule with evidence
class FilePresenceRule(RuleModule):
    def evaluate(self, signals: Dict, evidence: Dict) -> RuleResult:
        if signals.get("has_security_md"):
            return RuleResult(
                status="PASS",
                confidence=1.0,
                evidence={"file_path": evidence.get("security_md_path")}
            )
        return RuleResult(
            status="FAIL",
            confidence=1.0,
            evidence={"missing_file": "SECURITY.md", "searched_paths": ["./", ".github/", "docs/"]}
        )

# BAD: Non-deterministic rule
class BadRule(RuleModule):
    def evaluate(self, signals: Dict, evidence: Dict) -> RuleResult:
        if random.random() > 0.5:  # NEVER DO THIS
            return RuleResult(status="PASS")
        return RuleResult(status="FAIL", evidence={})  # NEVER: empty evidence

# BAD: LLM deciding verdict
class BadLLMRule(RuleModule):
    def evaluate(self, signals: Dict, evidence: Dict) -> RuleResult:
        llm_says = call_llm("Should this pass?")  # NEVER DO THIS
        return RuleResult(status="PASS" if llm_says == "yes" else "FAIL")

# GOOD: LLM for quality scoring, logic decides verdict
class DocQualityRule(RuleModule):
    def evaluate(self, signals: Dict, evidence: Dict) -> RuleResult:
        quality_score = self.llm_assess_doc_quality(evidence.get("doc_content"))
        if quality_score >= 0.7:
            return RuleResult(status="PASS", confidence=quality_score, evidence={"quality_score": quality_score})
        elif quality_score >= 0.4:
            return RuleResult(status="UNKNOWN", confidence=quality_score, evidence={"quality_score": quality_score})
        return RuleResult(status="FAIL", confidence=quality_score, evidence={"quality_score": quality_score, "reason": "Documentation incomplete"})
```

---

## Verdict Logic (PRD 3.3.1)

```python
# Environment-aware blocking
if severity == "critical":
    blocks_all_environments = True
elif severity == "high":
    blocks_production_only = True  # dev/staging: warning only
elif severity in ("medium", "low"):
    blocks_nothing = True  # advisory only
```

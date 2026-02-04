# EURA 2.0 Technical Product Requirements Document (PRD)
## AI Act & Cyber Resilience Act Compliance Platform - Technical Specification

**Version:** 2.0  
**Date:** January 2026  
**Status:** Draft  
**Focus:** Technical Implementation and Architecture

---

## 1. System Overview

### 1.1 Platform Purpose

EURA 2.0 is a compliance scanning and evaluation platform that:
- Scans software repositories to extract code, dependencies, documentation, and metadata
- Evaluates compliance against EU Cyber Resilience Act (CRA) and EU AI Act using executable rules
- Generates deterministic verdicts (SHIP_ALLOWED/SHIP_BLOCKED) based on rule failures
- Provides detailed compliance reports with evidence, findings, and remediation guidance
- Integrates with CI/CD pipelines to enforce compliance gates
- Tracks compliance history and generates audit reports

### 1.2 Core Technical Principles

1. **Deterministic Evaluation**: Rule evaluations must be reproducible and deterministic (no randomness)
2. **Evidence-Based**: All rule evaluations must be backed by concrete evidence
3. **Performance**: Scans must complete in <30 seconds for typical repositories (<1000 files)
4. **Scalability**: Support 1000+ concurrent scans
5. **Extensibility**: Rule system must support easy addition of new rules and regulations
6. **API-First**: All functionality exposed via well-documented APIs

---

## 2. Regulatory Framework Requirements

### 2.1 EU Cyber Resilience Act (CRA)

**Technical Requirements:**

#### 2.1.1 Rule Coverage
- **Current**: 18 rules (CRA-BASE-001 through CRA-BASE-018)
- **Target**: 50+ rules covering all CRA articles
- **Rule Format**: JSON schema compliant with `eura_knowledge/schema_v0.1.json`

#### 2.1.2 Rule Categories

**Security-by-Design Rules (Article 10):**
- CRA-SEC-001: Secure default configurations detected
- CRA-SEC-002: Dependencies are up-to-date (no known vulnerabilities)
- CRA-SEC-003: Security headers configured
- CRA-SEC-004: Encryption in transit enforced
- CRA-SEC-005: Authentication mechanisms present

**Vulnerability Handling Rules (Article 11):**
- CRA-VULN-001: SECURITY.md file present
- CRA-VULN-002: Vulnerability disclosure process documented
- CRA-VULN-003: Incident response procedures documented
- CRA-VULN-004: Security contact information present

**Documentation Rules (Article 13):**
- CRA-DOC-001: Security documentation present
- CRA-DOC-002: User security guidance provided
- CRA-DOC-003: Update procedures documented
- CRA-DOC-004: Installation instructions include security considerations

**SBOM Rules (Article 10):**
- CRA-SBOM-001: Dependency manifest files present
- CRA-SBOM-002: Complete dependency tree extractable
- CRA-SBOM-003: License information available for all dependencies
- CRA-SBOM-004: SBOM exportable in standard format (SPDX, CycloneDX)

**Lifecycle Management Rules (Article 12):**
- CRA-LIFE-001: Security update procedures documented
- CRA-LIFE-002: End-of-life policy present
- CRA-LIFE-003: Maintenance commitment documented
- CRA-LIFE-004: Versioning strategy documented

### 2.2 EU AI Act

**Technical Requirements:**

#### 2.2.1 AI System Detection Engine

**Framework Detection:**
- Detect AI/ML frameworks in codebase:
  - Python: TensorFlow, PyTorch, scikit-learn, Keras, XGBoost, LightGBM
  - R: caret, randomForest, xgboost
  - JavaScript: TensorFlow.js, Brain.js, ML5.js
  - Java: Deeplearning4j, DL4J
  - C++: TensorFlow C++, PyTorch C++
  - Other: ONNX, CoreML, TensorRT

**Detection Methods:**
- Dependency analysis: Check package.json, requirements.txt, etc. for AI framework packages
- Import analysis: Parse source code for framework imports
- File pattern matching: Detect model files (.h5, .pkl, .onnx, .pb, etc.)
- Configuration analysis: Detect AI-related configuration files

**Implementation:**
```python
class AISystemDetector:
    def detect_frameworks(self, dependencies: List[Dependency]) -> List[str]
    def detect_imports(self, code_files: List[CodeFile]) -> List[str]
    def detect_model_files(self, repo_files: List[File]) -> List[ModelFile]
    def classify_ai_system(self, evidence: Dict) -> AIClassification
```

#### 2.2.2 AI System Classification Engine

**Classification Logic:**
- **Prohibited AI Systems** (Article 5):
  - Social scoring systems
  - Manipulative AI systems
  - Real-time remote biometric identification (with exceptions)
  
- **High-Risk AI Systems** (Article 6, Annex III):
  - Biometric identification and categorization
  - Critical infrastructure management
  - Educational and vocational training
  - Employment, worker management, access to self-employment
  - Access to and enjoyment of essential private services
  - Law enforcement
  - Migration, asylum, and border control
  - Administration of justice and democratic processes

- **Limited-Risk AI Systems** (Article 50):
  - Chatbots and conversational AI
  - Deepfakes and synthetic media
  - Emotion recognition systems

- **Minimal-Risk AI Systems**: All other AI systems

**Classification Algorithm:**
```python
def classify_ai_system(
    ai_frameworks: List[str],
    use_case_indicators: Dict[str, bool],
    code_patterns: List[str]
) -> AIClassification:
    """
    Returns: {
        "risk_level": "prohibited" | "high_risk" | "limited_risk" | "minimal_risk",
        "confidence": float,  # 0.0-1.0
        "reasoning": str,
        "applicable_articles": List[str]
    }
    """
```

#### 2.2.3 AI Act Rule Implementation

**AI System Classification Rules:**
- AI-ACT-CLASS-001: Detect AI/ML frameworks in codebase
- AI-ACT-CLASS-002: Classify AI system risk level (prohibited/high-risk/limited-risk/minimal-risk)
- AI-ACT-CLASS-003: Identify biometric identification systems
- AI-ACT-CLASS-004: Detect social scoring systems
- AI-ACT-CLASS-005: Identify real-time remote biometric identification
- AI-ACT-CLASS-006: Detect emotion recognition systems
- AI-ACT-CLASS-007: Identify deepfake/synthetic media systems

**High-Risk AI System Rules (Article 8-51):**
- AI-ACT-HR-001: Risk management system documentation present
- AI-ACT-HR-002: Data governance documentation present (Article 10)
- AI-ACT-HR-003: Technical documentation completeness (Article 11)
- AI-ACT-HR-004: Record keeping mechanisms implemented (Article 12)
- AI-ACT-HR-005: Transparency requirements met (Article 13)
- AI-ACT-HR-006: Human oversight mechanisms present (Article 14)
- AI-ACT-HR-007: Accuracy and robustness testing documented (Article 15)
- AI-ACT-HR-008: Cybersecurity measures implemented (Article 15)
- AI-ACT-HR-009: Quality management system in place (Article 17)
- AI-ACT-HR-010: Conformity assessment completed (Article 43)

**Limited-Risk AI Rules (Article 50):**
- AI-ACT-LR-001: Chatbot transparency (AI identification to users)
- AI-ACT-LR-002: Deepfake disclosure requirements met
- AI-ACT-LR-003: Emotion recognition disclosure present

**General-Purpose AI Model Rules (Articles 51-65):**
- AI-ACT-GPAI-001: Model card present and complete
- AI-ACT-GPAI-002: Training data documentation available
- AI-ACT-GPAI-003: Capability assessment documented
- AI-ACT-GPAI-004: Systemic risk evaluation completed (for GPAI with systemic risk)

**Model Card Validation:**
```python
class ModelCardValidator:
    def validate_model_card(self, model_card: Dict) -> ValidationResult:
        """
        Validates model card against AI Act requirements:
        - Model architecture description
        - Training data description
        - Performance metrics
        - Limitations and biases
        - Intended use cases
        """
```

---

## 3. Core System Components

### 3.1 Repository Scanning Engine

#### 3.1.1 Multi-Source Repository Support

**GitHub Integration (Current):**
- GitHub App authentication
- Public repository access (with/without token)
- Private repository access (requires installation_id)
- Rate limit handling
- Webhook support for real-time scanning

**GitLab Integration (To Implement):**
```python
class GitLabClient:
    def __init__(self, access_token: str)
    def get_repo(self, project_id: str) -> Repository
    def list_files(self, repo: Repository) -> List[File]
    def get_file_content(self, repo: Repository, path: str) -> str
    def get_commit_hash(self, repo: Repository) -> str
```

**Bitbucket Integration (To Implement):**
```python
class BitbucketClient:
    def __init__(self, username: str, app_password: str)
    def get_repo(self, workspace: str, repo_slug: str) -> Repository
    # Similar methods to GitLabClient
```

**Azure DevOps Integration (To Implement):**
```python
class AzureDevOpsClient:
    def __init__(self, organization: str, personal_access_token: str)
    def get_repo(self, project: str, repo_name: str) -> Repository
    # Similar methods
```

**Generic Git Support:**
```python
class GenericGitClient:
    def __init__(self, repo_url: str, auth: Optional[Auth])
    def clone_repo(self) -> LocalRepository
    def list_files(self) -> List[File]
    # Uses git commands directly
```

#### 3.1.2 File Discovery and Processing

**File Discovery Algorithm:**
```python
class FileDiscoveryService:
    def discover_files(
        self,
        repo: Repository,
        max_files: int = 120,
        skip_dirs: Set[str] = None
    ) -> List[File]:
        """
        Recursively discover files in repository.
        - Respects max_files limit
        - Skips directories in skip_dirs
        - Prioritizes important files (manifests, configs, docs)
        """
    
    def prioritize_files(self, files: List[File]) -> List[File]:
        """
        Prioritize files for scanning:
        1. Manifest files (package.json, requirements.txt, etc.)
        2. Configuration files (.env, config files)
        3. Documentation files (README, SECURITY.md, etc.)
        4. Source code files
        5. Other files
        """
```

**Incremental Scanning:**
```python
class IncrementalScanner:
    def get_changed_files(
        self,
        repo: Repository,
        base_commit: str,
        head_commit: str
    ) -> List[File]:
        """
        Get files changed between two commits.
        Only re-scan changed files and files dependent on them.
        """
    
    def get_dependent_rules(self, file: File) -> List[Rule]:
        """
        Determine which rules need re-evaluation when file changes.
        """
```

**Large Repository Handling:**
- **Streaming Processing**: Process files in batches, don't load all into memory
- **Parallel Processing**: Process multiple files concurrently
- **Caching**: Cache file metadata and content hashes
- **Progressive Scanning**: Scan critical files first, background scan for others

#### 3.1.3 Dependency Extraction

**Manifest Parser Architecture:**
```python
class DependencyExtractor:
    def extract_dependencies(
        self,
        file_path: str,
        content: str
    ) -> List[Dependency]:
        """
        Extract dependencies from manifest file.
        Returns: [
            {
                "name": str,
                "version": str,
                "type": "direct" | "transitive",
                "file_source": str,
                "license": Optional[str],
                "vulnerabilities": List[Vulnerability]
            }
        ]
        """
    
    def resolve_transitive_dependencies(
        self,
        direct_deps: List[Dependency]
    ) -> List[Dependency]:
        """
        Resolve full dependency tree including transitive dependencies.
        """
```

**Supported Package Managers:**

**Python:**
- `requirements.txt`: Regex-based parsing
- `pyproject.toml`: TOML parsing (use `toml` library)
- `Pipfile`: TOML parsing
- `setup.py`: AST parsing for `install_requires`

**Node.js:**
- `package.json`: JSON parsing, extract `dependencies` and `devDependencies`
- `yarn.lock`: YAML parsing
- `pnpm-lock.yaml`: YAML parsing
- `package-lock.json`: JSON parsing

**Java:**
- `pom.xml`: XML parsing, extract `<dependencies>`
- `build.gradle`: Groovy parsing (use regex/parser)
- `build.gradle.kts`: Kotlin parsing

**Go:**
- `go.mod`: Parse module requirements
- `go.sum`: Parse checksums (for verification)

**Rust:**
- `Cargo.toml`: TOML parsing
- `Cargo.lock`: TOML parsing

**Docker:**
- `Dockerfile`: Parse `FROM`, `RUN pip install`, `RUN npm install`, etc.
- `docker-compose.yml`: YAML parsing

**Kubernetes:**
- Helm charts: Parse `Chart.yaml` and `values.yaml`
- K8s manifests: YAML parsing for container images

**Vulnerability Integration:**
```python
class VulnerabilityScanner:
    def __init__(self):
        self.osv_client = OSVClient()
        self.snyk_client = SnykClient()  # Optional
    
    def check_vulnerabilities(
        self,
        dependencies: List[Dependency]
    ) -> Dict[str, List[Vulnerability]]:
        """
        Check dependencies against vulnerability databases.
        Returns mapping of dependency name to vulnerabilities.
        """
```

#### 3.1.4 Code Analysis

**Static Analysis Integration:**
```python
class StaticAnalysisService:
    def run_sast_scan(
        self,
        repo: Repository,
        tool: str = "semgrep"  # or "codeql", "sonarqube"
    ) -> List[Finding]:
        """
        Run SAST tool on repository.
        Returns security findings.
        """
```

**Secret Detection:**
```python
class SecretDetector:
    def detect_secrets(self, file: File) -> List[SecretFinding]:
        """
        Detect secrets in code:
        - API keys (pattern matching)
        - Passwords (pattern matching)
        - Tokens (pattern matching)
        - Use truffleHog or similar library
        """
```

**AI/ML Component Detection:**
```python
class AIDetector:
    def detect_ai_components(self, repo: Repository) -> AIDetectionResult:
        """
        Detect AI/ML components:
        1. Framework imports (TensorFlow, PyTorch, etc.)
        2. Model files (.h5, .pkl, .onnx, etc.)
        3. Training scripts (train.py, training notebooks)
        4. Inference code (predict, classify functions)
        5. Data preprocessing pipelines
        """
    
    def detect_training_data(self, repo: Repository) -> List[DataFile]:
        """
        Detect training data files:
        - Large data files (.csv, .parquet, .h5)
        - Data directories
        - Data loading code
        """
```

**Architecture Analysis:**
```python
class ArchitectureAnalyzer:
    def analyze_architecture(self, repo: Repository) -> ArchitectureReport:
        """
        Analyze software architecture:
        - Microservices vs monolith
        - API patterns (REST, GraphQL, gRPC)
        - Authentication mechanisms
        - Data storage patterns
        - Communication patterns
        """
```

### 3.2 Rule Engine

#### 3.2.1 Rule Architecture

**Rule Schema:**
```json
{
  "rule_id": "CRA-BASE-001",
  "version": "1.0.0",
  "title": "Security Policy Documentation",
  "description_short": "Repository must have SECURITY.md file",
  "description_long": "...",
  "regulation": "CRA",
  "article": "Article 11",
  "severity": "high",
  "is_blocking": true,
  "applicability": {
    "operator": "AND",
    "conditions": [
      {
        "signal": "has_security_policy",
        "operator": "exists"
      }
    ]
  },
  "evaluation_method": "file_presence",
  "evidence_requirements": [
    {
      "type": "file_presence",
      "source": "SECURITY.md",
      "required": false
    }
  ],
  "remediation_guidance": {
    "steps": [
      "Create SECURITY.md file in repository root",
      "Include vulnerability disclosure process",
      "Add security contact information"
    ],
    "examples": ["..."]
  }
}
```

**Rule Storage:**
- **Format**: JSON files in `app/data/rules/`
- **Versioning**: Git-based versioning, semantic versioning for rules
- **Loading**: Lazy loading, cached in memory after first load
- **Updates**: Hot-reload capability for rule updates

**Rule Module System:**
```python
class RuleModule:
    def __init__(self, rule_id: str, rule_definition: Dict):
        self.rule_id = rule_id
        self.definition = rule_definition
        self.evaluator = self._create_evaluator()
    
    def evaluate(
        self,
        signals: Dict[str, Any],
        evidence: Dict[str, Any]
    ) -> RuleResult:
        """
        Evaluate rule against signals and evidence.
        Returns: {
            "status": "PASS" | "FAIL" | "UNKNOWN" | "NOT_APPLICABLE",
            "confidence": float,
            "evidence": Dict,
            "reason": str
        }
        """
```

#### 3.2.2 Rule Evaluation Engine

**Evaluation Pipeline:**
```python
class RuleEvaluationEngine:
    def __init__(self):
        self.rule_loader = RuleLoader()
        self.signal_builder = SignalBuilder()
        self.evidence_collector = EvidenceCollector()
    
    def evaluate_repo(
        self,
        scan_result: ScanResult,
        regulations: List[str] = None
    ) -> ComplianceEvaluation:
        """
        Evaluate repository against all applicable rules.
        
        Steps:
        1. Load rules for specified regulations
        2. Build signals from scan result
        3. Collect evidence for each rule
        4. Evaluate each rule (parallel)
        5. Generate verdict
        6. Build compliance report
        """
    
    def evaluate_rule(
        self,
        rule: Rule,
        signals: Dict[str, Any],
        evidence: Dict[str, Any]
    ) -> RuleResult:
        """
        Evaluate single rule:
        1. Check applicability
        2. Collect rule-specific evidence
        3. Run rule evaluator
        4. Return result with confidence score
        """
```

**Parallel Rule Evaluation:**
```python
async def evaluate_rules_parallel(
    rules: List[Rule],
    signals: Dict[str, Any],
    evidence: Dict[str, Any]
) -> List[RuleResult]:
    """
    Evaluate multiple rules concurrently using asyncio.
    """
    tasks = [
        evaluate_rule_async(rule, signals, evidence)
        for rule in rules
    ]
    return await asyncio.gather(*tasks)
```

**Signal Building:**
```python
class SignalBuilder:
    def build_signals(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Extract signals from scan result:
        - has_security_policy: bool
        - dependency_count: int
        - vulnerable_dependency_count: int
        - has_ai_frameworks: bool
        - ai_system_classification: str
        - documentation_files: List[str]
        - etc.
        """
```

**Evidence Collection:**
```python
class EvidenceCollector:
    def collect_evidence(
        self,
        rule: Rule,
        scan_result: ScanResult
    ) -> Dict[str, Any]:
        """
        Collect evidence required for rule evaluation:
        - File contents
        - Dependency lists
        - Code patterns
        - Configuration values
        """
```

#### 3.2.3 CRA Rule Implementation

**Rule Categories and Implementation:**

**File Presence Rules:**
```python
class FilePresenceRule(Rule):
    def evaluate(self, signals, evidence):
        required_files = self.definition["evidence_requirements"]
        found_files = [
            f for f in required_files
            if evidence.get(f"file_exists_{f['source']}", False)
        ]
        if found_files:
            return RuleResult(status="PASS", evidence={"files": found_files})
        return RuleResult(status="FAIL", evidence={"missing": required_files})
```

**Dependency Rules:**
```python
class DependencyRule(Rule):
    def evaluate(self, signals, evidence):
        dependencies = evidence.get("dependencies", [])
        vulnerable_deps = [
            d for d in dependencies
            if d.get("vulnerabilities", [])
        ]
        if len(vulnerable_deps) == 0:
            return RuleResult(status="PASS")
        return RuleResult(
            status="FAIL",
            evidence={"vulnerable_dependencies": vulnerable_deps}
        )
```

**Documentation Quality Rules:**
```python
class DocumentationQualityRule(Rule):
    def evaluate(self, signals, evidence):
        # Use LLM to evaluate documentation quality
        doc_content = evidence.get("documentation_content", "")
        quality_score = self.llm_evaluate_documentation(doc_content)
        if quality_score > 0.7:
            return RuleResult(status="PASS", confidence=quality_score)
        return RuleResult(status="FAIL", confidence=quality_score)
```

#### 3.2.4 AI Act Rule Implementation

**AI System Classification Rule:**
```python
class AIClassificationRule(Rule):
    def evaluate(self, signals, evidence):
        ai_frameworks = signals.get("ai_frameworks", [])
        use_case_indicators = evidence.get("use_case_indicators", {})
        
        if not ai_frameworks:
            return RuleResult(
                status="NOT_APPLICABLE",
                reason="No AI frameworks detected"
            )
        
        classification = self.classify_ai_system(
            ai_frameworks,
            use_case_indicators
        )
        
        return RuleResult(
            status="PASS",
            evidence={"classification": classification}
        )
```

**High-Risk AI Documentation Rules:**
```python
class HighRiskAIDocumentationRule(Rule):
    def evaluate(self, signals, evidence):
        if signals.get("ai_classification") != "high_risk":
            return RuleResult(status="NOT_APPLICABLE")
        
        required_docs = [
            "risk_management_doc",
            "data_governance_doc",
            "technical_documentation",
            "model_card"
        ]
        
        found_docs = [
            doc for doc in required_docs
            if evidence.get(f"has_{doc}", False)
        ]
        
        if len(found_docs) == len(required_docs):
            return RuleResult(status="PASS", evidence={"docs": found_docs})
        
        return RuleResult(
            status="FAIL",
            evidence={"missing_docs": set(required_docs) - set(found_docs)}
        )
```

### 3.3 Compliance Evaluation Engine

#### 3.3.1 Verdict Generation

**Verdict Logic:**
```python
class VerdictGenerator:
    def generate_verdict(
        self,
        rule_results: List[RuleResult],
        environment: str = "production"
    ) -> Verdict:
        """
        Generate SHIP_ALLOWED or SHIP_BLOCKED verdict.
        
        Logic:
        - If any CRITICAL severity rule FAILS -> SHIP_BLOCKED
        - If any HIGH severity rule FAILS and environment == "production" -> SHIP_BLOCKED
        - If any HIGH severity rule FAILS and environment != "production" -> SHIP_ALLOWED (with warning)
        - Otherwise -> SHIP_ALLOWED
        """
        blocking_rules = [
            r for r in rule_results
            if r.status == "FAIL"
            and r.severity in ["critical", "high"]
            and (r.severity == "critical" or environment == "production")
        ]
        
        if blocking_rules:
            return Verdict(
                verdict="SHIP_BLOCKED",
                blocking_rules=[r.rule_id for r in blocking_rules]
            )
        
        return Verdict(verdict="SHIP_ALLOWED")
```

**Multi-Regulation Verdict:**
```python
def generate_multi_regulation_verdict(
    cra_results: List[RuleResult],
    ai_act_results: List[RuleResult]
) -> MultiRegulationVerdict:
    """
    Generate combined verdict across regulations.
    """
    cra_verdict = generate_verdict(cra_results)
    ai_act_verdict = generate_verdict(ai_act_results)
    
    return MultiRegulationVerdict(
        overall_verdict="SHIP_BLOCKED" if (
            cra_verdict.verdict == "SHIP_BLOCKED" or
            ai_act_verdict.verdict == "SHIP_BLOCKED"
        ) else "SHIP_ALLOWED",
        regulations={
            "CRA": cra_verdict,
            "AI_ACT": ai_act_verdict
        }
    )
```

#### 3.3.2 Compliance Scoring

**Scoring Algorithm:**
```python
class ComplianceScorer:
    def calculate_score(
        self,
        rule_results: List[RuleResult]
    ) -> ComplianceScore:
        """
        Calculate compliance score:
        - Weight rules by severity
        - Count PASS/FAIL/UNKNOWN/NOT_APPLICABLE
        - Score = (passed_rules * weight) / (total_applicable_rules * weight)
        """
        weights = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0
        }
        
        total_weight = sum(
            weights.get(r.severity, 1.0)
            for r in rule_results
            if r.status != "NOT_APPLICABLE"
        )
        
        passed_weight = sum(
            weights.get(r.severity, 1.0)
            for r in rule_results
            if r.status == "PASS"
        )
        
        score = (passed_weight / total_weight) * 100 if total_weight > 0 else 0
        
        return ComplianceScore(
            score=score,
            passed=len([r for r in rule_results if r.status == "PASS"]),
            failed=len([r for r in rule_results if r.status == "FAIL"]),
            unknown=len([r for r in rule_results if r.status == "UNKNOWN"]),
            not_applicable=len([r for r in rule_results if r.status == "NOT_APPLICABLE"])
        )
```

### 3.4 Data Persistence

#### 3.4.1 Database Schema

**Core Tables:**

```sql
-- Organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Projects
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_scan_at TIMESTAMP WITH TIME ZONE
);

-- Repositories
CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id),
    provider VARCHAR(50) NOT NULL,  -- 'github', 'gitlab', 'bitbucket'
    owner VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    default_branch VARCHAR(255) DEFAULT 'main',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider, owner, name)
);

-- Scans
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id),
    repository_id UUID REFERENCES repositories(id),
    status VARCHAR(50) NOT NULL,  -- 'queued', 'processing', 'completed', 'failed'
    repo_name VARCHAR(255) NOT NULL,
    commit_hash VARCHAR(40),
    installation_id BIGINT,
    total_files INTEGER,
    analyzed_files INTEGER,
    duration_ms INTEGER,
    error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Rules
CREATE TABLE rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(50) UNIQUE NOT NULL,  -- e.g., 'CRA-BASE-001'
    version VARCHAR(20) NOT NULL,
    regulation VARCHAR(50) NOT NULL,  -- 'CRA', 'AI_ACT'
    title VARCHAR(255) NOT NULL,
    description_short TEXT,
    description_long TEXT,
    severity VARCHAR(20) NOT NULL,  -- 'critical', 'high', 'medium', 'low'
    is_blocking BOOLEAN DEFAULT false,
    rule_definition JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rule Results
CREATE TABLE rule_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    rule_id VARCHAR(50) REFERENCES rules(rule_id),
    status VARCHAR(20) NOT NULL,  -- 'PASS', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE'
    confidence DECIMAL(3,2),  -- 0.00-1.00
    reason TEXT,
    evidence JSONB,
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Dependencies
CREATE TABLE scan_dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    project_id UUID REFERENCES projects(id),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    type VARCHAR(50),  -- 'python', 'node', 'java', etc.
    file_source VARCHAR(255),
    license VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Findings
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    project_id UUID REFERENCES projects(id),
    severity VARCHAR(20) NOT NULL,  -- 'critical', 'high', 'medium', 'low', 'info'
    category VARCHAR(50) NOT NULL,  -- 'security', 'compliance', 'ai_act', 'cra'
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    details TEXT,
    file_path VARCHAR(500),
    line_number INTEGER,
    code_snippet TEXT,
    recommendation TEXT,
    confidence DECIMAL(3,2),
    fingerprint VARCHAR(64) UNIQUE,  -- SHA256 for deduplication
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compliance Reports
CREATE TABLE compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    project_id UUID REFERENCES projects(id),
    regulation VARCHAR(50) NOT NULL,  -- 'CRA', 'AI_ACT', 'COMBINED'
    verdict VARCHAR(20) NOT NULL,  -- 'SHIP_ALLOWED', 'SHIP_BLOCKED'
    score DECIMAL(5,2),  -- 0.00-100.00
    total_rules INTEGER,
    passed INTEGER,
    failed INTEGER,
    unknown INTEGER,
    not_applicable INTEGER,
    evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compliance Details (rule-level results in report)
CREATE TABLE compliance_details (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID REFERENCES compliance_reports(id),
    scan_id UUID REFERENCES scans(id),
    rule_id VARCHAR(50) REFERENCES rules(rule_id),
    status VARCHAR(20) NOT NULL,
    confidence DECIMAL(3,2),
    reason TEXT,
    evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- AI Systems (AI Act specific)
CREATE TABLE ai_systems (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    repository_id UUID REFERENCES repositories(id),
    name VARCHAR(255),
    classification VARCHAR(50),  -- 'prohibited', 'high_risk', 'limited_risk', 'minimal_risk'
    frameworks TEXT[],  -- Array of framework names
    use_case TEXT,
    confidence DECIMAL(3,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Model Cards (AI Act specific)
CREATE TABLE model_cards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_system_id UUID REFERENCES ai_systems(id),
    file_path VARCHAR(500),
    content JSONB,
    validation_status VARCHAR(20),  -- 'valid', 'invalid', 'incomplete'
    validation_errors TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### 3.4.2 Data Access Layer

**Repository Pattern:**
```python
class ScanRepository:
    def create_scan(self, scan_data: Dict) -> Scan:
    def get_scan(self, scan_id: UUID) -> Scan:
    def update_scan_status(self, scan_id: UUID, status: str) -> None:
    def get_scans_by_project(self, project_id: UUID) -> List[Scan]:
    
class RuleRepository:
    def get_rule(self, rule_id: str) -> Rule:
    def get_rules_by_regulation(self, regulation: str) -> List[Rule]:
    def get_all_rules(self) -> List[Rule]:
    
class ComplianceReportRepository:
    def create_report(self, report_data: Dict) -> ComplianceReport:
    def get_report(self, report_id: UUID) -> ComplianceReport:
    def get_reports_by_project(self, project_id: UUID) -> List[ComplianceReport]:
```

### 3.5 API Specification

#### 3.5.1 REST API Endpoints

**Scan Management:**
```
POST   /api/v1/scans/run
GET    /api/v1/scans/{scan_id}
GET    /api/v1/scans?project_id={project_id}&status={status}
DELETE /api/v1/scans/{scan_id}
```

**Project Management:**
```
POST   /api/v1/projects
GET    /api/v1/projects/{project_id}
GET    /api/v1/projects
PUT    /api/v1/projects/{project_id}
DELETE /api/v1/projects/{project_id}
```

**Repository Management:**
```
POST   /api/v1/repositories
GET    /api/v1/repositories/{repository_id}
GET    /api/v1/repositories?project_id={project_id}
PUT    /api/v1/repositories/{repository_id}
DELETE /api/v1/repositories/{repository_id}
```

**Rule Management:**
```
GET    /api/v1/rules
GET    /api/v1/rules/{rule_id}
GET    /api/v1/rules?regulation={regulation}
GET    /api/v1/rules/{rule_id}/versions  # ⚠️ NOT IMPLEMENTED: Rule versioning system not yet built
```

**Compliance Reports:**
```
GET    /api/v1/reports/{report_id}
GET    /api/v1/reports?project_id={project_id}&regulation={regulation}
POST   /api/v1/reports/generate  # ⚠️ PLACEHOLDER: Reports auto-generated during scan execution
GET    /api/v1/reports/{report_id}/export?format={pdf|json|excel}  # ⚠️ PARTIAL: JSON only, PDF/Excel require additional libraries (ReportLab/openpyxl)
```

**Webhooks:**
```
POST   /api/v1/webhooks  # ⚠️ NOT IMPLEMENTED: Deferred to Phase 3 (Months 7-9) - requires webhook registration system, event generation, delivery with retry logic, and security
GET    /api/v1/webhooks  # ⚠️ NOT IMPLEMENTED: Deferred to Phase 3
DELETE /api/v1/webhooks/{webhook_id}  # ⚠️ NOT IMPLEMENTED: Deferred to Phase 3
POST   /api/v1/webhooks/{webhook_id}/test  # ⚠️ NOT IMPLEMENTED: Deferred to Phase 3
```

#### 3.5.2 API Request/Response Models

**Scan Run Request:**
```python
class ScanRunRequestV1(BaseModel):
    repo_url: str
    environment: Literal["dev", "staging", "production", "eu-production"]
    installation_id: Optional[int] = None
    project_id: Optional[UUID] = None
    regulations: List[str] = ["CRA", "AI_ACT"]  # Which regulations to evaluate
    max_files: Optional[int] = None
    skip_llm_analysis: bool = False
```

**Scan Result Response:**
```python
class ScanResultV1(BaseModel):
    scan_id: UUID
    project_id: Optional[UUID]
    repo_url: str
    commit_sha: str
    environment: str
    evaluated_at: datetime
    verdict: Literal["SHIP_ALLOWED", "SHIP_BLOCKED"]
    blocking_rules: List[str]
    rule_results: List[RuleResultV1]
    evidence_refs: EvidenceRefsV1
    advisory_findings: List[AdvisoryFindingV1]
    compliance_scores: Dict[str, ComplianceScore]  # Per-regulation scores
```

**Rule Result:**
```python
class RuleResultV1(BaseModel):
    rule_id: str
    title: str
    description: str
    regulation: str
    article: Optional[str]
    status: Literal["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]
    severity: str
    is_blocking: bool
    confidence: float
    evidence: Dict[str, Any]
    remediation_guidance: Optional[RemediationGuidance]
```

#### 3.5.3 GraphQL API Schema

⚠️ **NOT IMPLEMENTED**: GraphQL API deferred to Phase 3 (Months 7-9) per PRD roadmap. Requires Strawberry GraphQL setup, schema definitions, resolvers, and subscriptions.

```graphql
type Query {
    scan(id: ID!): Scan
    scans(filter: ScanFilter): [Scan!]!
    project(id: ID!): Project
    projects: [Project!]!
    rule(id: ID!): Rule
    rules(filter: RuleFilter): [Rule!]!
    complianceReport(id: ID!): ComplianceReport
    complianceReports(filter: ReportFilter): [ComplianceReport!]!
}

type Mutation {
    runScan(input: ScanRunInput!): ScanResult!
    createProject(input: ProjectInput!): Project!
    createRepository(input: RepositoryInput!): Repository!
}

type Subscription {
    scanStatusChanged(scanId: ID!): ScanStatusUpdate!
    complianceStatusChanged(projectId: ID!): ComplianceStatusUpdate!
}

type Scan {
    id: ID!
    status: ScanStatus!
    repoUrl: String!
    commitSha: String
    ruleResults: [RuleResult!]!
    complianceReports: [ComplianceReport!]!
    createdAt: DateTime!
    completedAt: DateTime
}

type RuleResult {
    rule: Rule!
    status: RuleStatus!
    confidence: Float!
    evidence: JSON!
    remediationGuidance: RemediationGuidance
}
```

### 3.6 CI/CD Integration

#### 3.6.1 GitHub Actions Integration

**Action Definition:**
```yaml
# .github/actions/eura-compliance/action.yml
name: 'EURA Compliance Check'
description: 'Check repository compliance with EU regulations'
inputs:
  api_url:
    description: 'EURA API URL'
    required: false
    default: 'https://api.eura.com'
  api_key:
    description: 'EURA API key'
    required: true
  environment:
    description: 'Deployment environment'
    required: false
    default: 'production'
  regulations:
    description: 'Comma-separated list of regulations'
    required: false
    default: 'CRA,AI_ACT'
runs:
  using: 'composite'
  steps:
    - name: Run EURA Compliance Scan
      run: |
        response=$(curl -X POST "${{ inputs.api_url }}/api/v1/scans/run" \
          -H "Authorization: Bearer ${{ inputs.api_key }}" \
          -H "Content-Type: application/json" \
          -d '{
            "repo_url": "${{ github.repository }}",
            "environment": "${{ inputs.environment }}",
            "regulations": ["${{ inputs.regulations }}"]
          }')
        
        verdict=$(echo $response | jq -r '.verdict')
        if [ "$verdict" = "SHIP_BLOCKED" ]; then
          echo "::error::Compliance check failed. Deployment blocked."
          exit 1
        fi
```

#### 3.6.2 GitLab CI Integration

**GitLab CI Template:**
```yaml
# .gitlab-ci.yml
include:
  - template: EURA Compliance

eura_compliance:
  variables:
    EURA_API_URL: "https://api.eura.com"
    EURA_ENVIRONMENT: "production"
  script:
    - python scripts/ci_gatekeeper.py
      --repo_url "$CI_PROJECT_PATH"
      --environment "$EURA_ENVIRONMENT"
      --api_url "$EURA_API_URL"
```

#### 3.6.3 Generic CI/CD Integration

**CI Gatekeeper Script:**
```python
# scripts/ci_gatekeeper.py
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo_url", required=True)
    parser.add_argument("--environment", default="production")
    parser.add_argument("--api_url", default="https://api.eura.com")
    parser.add_argument("--api_key", default=os.getenv("EURA_API_KEY"))
    
    args = parser.parse_args()
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{args.api_url}/api/v1/scans/run",
            headers={"Authorization": f"Bearer {args.api_key}"},
            json={
                "repo_url": args.repo_url,
                "environment": args.environment
            }
        )
        response.raise_for_status()
        result = response.json()
        
        if result["verdict"] == "SHIP_BLOCKED":
            print(f"❌ Compliance check failed. Blocking rules: {result['blocking_rules']}")
            sys.exit(1)
        else:
            print("✅ Compliance check passed")
            sys.exit(0)
```

### 3.7 Performance Requirements

#### 3.7.1 Performance Targets

**Scan Performance:**
- Small repository (<100 files): <10 seconds
- Medium repository (100-1000 files): <30 seconds
- Large repository (1000-10000 files): <2 minutes
- Very large repository (>10000 files): <5 minutes

**API Performance:**
- Scan initiation: <1 second
- Scan status check: <100ms
- Report generation: <2 seconds
- Rule query: <50ms

**Throughput:**
- 1000+ scans per hour
- 100+ concurrent scans
- 10,000+ API requests per minute

#### 3.7.2 Optimization Strategies

**Caching:**
- Cache rule definitions (Redis, in-memory)
- Cache repository metadata (commit hashes, file lists)
- Cache dependency vulnerability data (TTL: 1 hour)
- Cache LLM responses for documentation evaluation

**Parallel Processing:**
- Parallel file processing (async I/O)
- Parallel rule evaluation (asyncio)
- Parallel dependency resolution
- Background job processing (Celery/RQ)

**Database Optimization:**
- Indexes on frequently queried columns
- Partitioning for large tables (scans, findings)
- Connection pooling
- Read replicas for reporting queries

**Incremental Processing:**
- Only scan changed files
- Only re-evaluate affected rules
- Incremental dependency updates
- Delta compliance reports

### 3.8 Compliance Artifact Exports

EURA must generate machine-readable compliance artifacts required for EU regulatory audits. These exports enable automated market surveillance and provide the evidentiary basis for conformity assessments.

#### 3.8.1 CRA Mandatory Artifacts

**Software Bill of Materials (SBOM):**
```
POST /api/v1/exports/sbom
```
- **Formats**: CycloneDX 1.5, SPDX 2.3 (JSON)
- **Status**: ✅ Implemented
- **Content**: Component inventory with name, version, PURL, supplier, license, dependencies
- **CRA Reference**: Annex I - Software supply chain transparency

**Vulnerability Exploitability eXchange (VEX):**
```
POST /api/v1/exports/vex
```
- **Format**: CycloneDX VEX or OpenVEX (JSON)
- **Status**: 🔲 To Implement
- **Content**: CVE analysis showing whether vulnerabilities actually affect the product
- **Fields**: `vulnerability_id`, `status` (not_affected/affected/fixed/under_investigation), `justification`, `action_statement`
- **CRA Reference**: Annex I, II - Vulnerability handling

**Common Security Advisory Framework (CSAF):**
```
POST /api/v1/exports/csaf
```
- **Format**: CSAF 2.0 (JSON)
- **Status**: 🔲 To Implement
- **Content**: Machine-readable security advisories for automated consumption
- **CRA Reference**: Annex I - Incident reporting

**Static Analysis Results (SARIF):**
```
POST /api/v1/exports/sarif
```
- **Format**: SARIF 2.1.0 (JSON)
- **Status**: 🔲 To Implement
- **Content**: Security scan results from SAST/SCA/secret detection
- **CRA Reference**: Essential Requirements - Security by Design

#### 3.8.2 AI Act Mandatory Artifacts

**Model Card:**
```
POST /api/v1/exports/model-card
```
- **Format**: JSON or Markdown
- **Status**: 🔲 To Implement
- **Content**: AI system "nutrition label" including:
  - Model architecture and type
  - Intended use and limitations
  - Performance metrics (accuracy, robustness, fairness)
  - Training data summary
  - Ethical considerations and known risks
- **AI Act Reference**: Article 13 (Transparency), Annex IV

**Data Card (Datasheet for Datasets):**
```
POST /api/v1/exports/data-card
```
- **Format**: JSON or Markdown
- **Status**: 🔲 To Implement (Template Only - requires user input)
- **Content**: Training data documentation including:
  - Data provenance and collection methods
  - Dataset composition and scope
  - Labelling procedures
  - Bias mitigation steps
- **AI Act Reference**: Article 10 (Data Governance)

**Risk Register:**
```
POST /api/v1/exports/risk-register
```
- **Format**: JSON or CSV
- **Status**: 🔲 To Implement
- **Content**: Compliance risk assessment including:
  - Rule failures mapped to regulatory articles
  - Severity and impact assessment
  - Remediation status and timeline
  - Residual risk documentation
- **AI Act Reference**: Article 9 (Risk Management)

**Technical File (Annex IV Template):**
```
POST /api/v1/exports/technical-file
```
- **Format**: Structured Markdown or PDF
- **Status**: 🔲 To Implement
- **Content**: Complete audit dossier structure:
  1. System Overview (description, versioning, architecture)
  2. Data & Model Documentation (model cards, data cards)
  3. Risk & Control Register (Art 9 assessments)
  4. Operational Controls (human oversight, monitoring)
  5. Technical Evidence (logs, security scans)
  6. Conformity Records (compliance mapping)
- **AI Act Reference**: Article 11, Annex IV

**Compliance Mapping Table:**
```
POST /api/v1/exports/compliance-map
```
- **Format**: JSON or CSV
- **Status**: 🔲 To Implement
- **Content**: Maps every regulatory requirement to specific evidence
- **Columns**: `regulation`, `article`, `requirement`, `rule_id`, `status`, `evidence_location`

#### 3.8.3 Artifacts EURA Cannot Generate

The following artifacts require runtime data or human expertise that EURA cannot automatically produce:

| Artifact | Reason | User Action Required |
|----------|--------|---------------------|
| **Art 12 Activity Logs** | Requires actual system operation logs | User must provide runtime logs |
| **Human Oversight Logs** | Requires intervention records from production | User must implement logging |
| **Training Data Provenance** | Requires actual dataset metadata | User must document datasets |
| **EU Declaration of Conformity** | Legal document requiring authorized signature | User/legal team signs |
| **Bias Testing Results** | Requires actual ML model evaluation | User must run fairness tests |
| **Threat Models** | Requires architectural security expertise | Security team creates |

#### 3.8.4 Export API Specification

**Request Format:**
```python
class ExportRequest(BaseModel):
    scan_id: Optional[UUID] = None  # Use latest scan if not provided
    project_id: Optional[UUID] = None
    format: Literal["json", "markdown", "csv", "pdf"]
    include_evidence: bool = True
    regulation: Optional[Literal["CRA", "AI_ACT", "ALL"]] = "ALL"
```

**Response Format:**
```python
class ExportResponse(BaseModel):
    export_id: UUID
    artifact_type: str
    format: str
    generated_at: datetime
    content: Union[dict, str]  # JSON object or string content
    download_url: Optional[str]  # For large files
    metadata: Dict[str, Any]
```

---

## 4. Technical Architecture

### 4.1 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Web Frontend │  │ CI/CD Plugins │  │ API Clients  │     │
│  │  (React)     │  │ (GitHub, etc) │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└──────────────────────┬──────────────────────────────────────┘
                        │ HTTPS
┌──────────────────────▼──────────────────────────────────────┐
│                    API Gateway Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ REST API     │  │ GraphQL API  │  │ Webhooks     │     │
│  │ (FastAPI)    │  │ (Strawberry)  │  │ Handler      │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐                        │
│  │ Auth         │  │ Rate Limiting│                        │
│  │ (OAuth/JWT)  │  │ (Redis)      │                        │
│  └──────────────┘  └──────────────┘                        │
└──────────────────────┬──────────────────────────────────────┘
                        │
┌──────────────────────▼──────────────────────────────────────┐
│                 Application Service Layer                    │
│  ┌────────────────────────────────────────────────────┐    │
│  │              Scan Orchestration Service            │    │
│  │  - Repository fetching                             │    │
│  │  - File discovery                                   │    │
│  │  - Dependency extraction                            │    │
│  │  - Code analysis coordination                       │    │
│  └────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────┐    │
│  │              Rule Evaluation Service                │    │
│  │  - Rule loading and caching                         │    │
│  │  - Signal building                                  │    │
│  │  - Evidence collection                              │    │
│  │  - Parallel rule evaluation                        │    │
│  └────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────┐    │
│  │           Compliance Evaluation Service            │    │
│  │  - Verdict generation                              │    │
│  │  - Compliance scoring                              │    │
│  │  - Report generation                                │    │
│  └────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────┐    │
│  │              AI Detection Service                   │    │
│  │  - Framework detection                             │    │
│  │  - AI system classification                         │    │
│  │  - Model card validation                            │    │
│  └────────────────────────────────────────────────────┘    │
└──────────────────────┬──────────────────────────────────────┘
                        │
┌──────────────────────▼──────────────────────────────────────┐
│                    Data Access Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Scan Repo    │  │ Rule Repo   │  │ Report Repo  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐                        │
│  │ Dependency   │  │ Finding Repo │                        │
│  │ Repo         │  │              │                        │
│  └──────────────┘  └──────────────┘                        │
└──────────────────────┬──────────────────────────────────────┘
                        │
┌──────────────────────▼──────────────────────────────────────┐
│                      Data Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ PostgreSQL   │  │ Redis Cache  │  │ Object Store │     │
│  │ (Supabase)   │  │              │  │ (S3/GCS)     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                        │
┌──────────────────────▼──────────────────────────────────────┐
│              Background Job Queue                           │
│  ┌──────────────┐  ┌──────────────┐                        │
│  │ Celery       │  │ Task Queue   │                        │
│  │ Workers      │  │ (RabbitMQ)   │                        │
│  └──────────────┘  └──────────────┘                        │
└─────────────────────────────────────────────────────────────┘
                        │
┌──────────────────────▼──────────────────────────────────────┐
│                  External Services                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ GitHub API   │  │ OpenAI API   │  │ Vuln DBs     │     │
│  │ GitLab API   │  │ (LLM)        │  │ (OSV, Snyk)  │     │
│  │ Bitbucket API│  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Technology Stack

**Backend:**
- **Language**: Python 3.11+
- **Framework**: FastAPI 0.104+
- **Async Runtime**: Uvicorn with uvloop (Linux) or asyncio (Windows)
- **Database**: PostgreSQL 14+ (via Supabase)
- **ORM**: SQLAlchemy 2.0+ (async)
- **Cache**: Redis 7+
- **Object Storage**: AWS S3 or Google Cloud Storage
- **Message Queue**: RabbitMQ or AWS SQS
- **Task Queue**: Celery 5.3+ or RQ
- **GraphQL**: Strawberry GraphQL

**Frontend:**
- **Framework**: React 18+
- **TypeScript**: Yes
- **State Management**: Zustand or React Query
- **UI Library**: Material-UI (MUI) or Tailwind CSS + Headless UI
- **Charts**: Recharts
- **API Client**: React Query (TanStack Query)
- **Build Tool**: Vite

**Infrastructure:**
- **Hosting**: Railway, AWS (ECS/EKS), or Google Cloud Platform (Cloud Run/GKE)
- **Containerization**: Docker
- **Orchestration**: Kubernetes (for production scale)
- **Monitoring**: Prometheus + Grafana
- **Logging**: Structured logging (JSON) → ELK Stack or CloudWatch
- **Error Tracking**: Sentry
- **APM**: Datadog or New Relic

### 4.3 Data Model (Detailed Schema)

See Section 3.4.1 for complete database schema.

**Key Relationships:**
- Organization → Projects (1:N)
- Project → Repositories (1:N)
- Repository → Scans (1:N)
- Scan → RuleResults (1:N)
- Scan → Findings (1:N)
- Scan → Dependencies (1:N)
- Scan → ComplianceReports (1:N)
- ComplianceReport → ComplianceDetails (1:N)
- Scan → AISystems (1:N, AI Act)
- AISystem → ModelCards (1:N)

**Indexes:**
```sql
-- Performance indexes
CREATE INDEX idx_scans_project_id ON scans(project_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_rule_results_scan_id ON rule_results(scan_id);
CREATE INDEX idx_rule_results_rule_id ON rule_results(rule_id);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_compliance_reports_project_id ON compliance_reports(project_id);
CREATE INDEX idx_compliance_reports_evaluated_at ON compliance_reports(evaluated_at DESC);

-- Unique constraints
CREATE UNIQUE INDEX idx_rules_rule_id_version ON rules(rule_id, version);
CREATE UNIQUE INDEX idx_findings_fingerprint ON findings(fingerprint);
```

### 4.4 Security Architecture

**Authentication:**
- OAuth 2.0 / OIDC for user authentication
- GitHub App for repository access
- API keys for programmatic access
- JWT tokens for session management

**Authorization:**
- Role-based access control (RBAC):
  - Admin: Full access
  - Developer: Read scans, create scans
  - Viewer: Read-only access
- Resource-level permissions (project/repository level)

**Data Security:**
- TLS 1.3 for all communications
- Encryption at rest for sensitive data
- Secrets management: AWS Secrets Manager / HashiCorp Vault
- API key rotation policies
- Audit logging for all sensitive operations

**Input Validation:**
- Request validation using Pydantic models
- SQL injection prevention (parameterized queries)
- XSS prevention (input sanitization)
- Rate limiting per API key/user

---

## 5. Implementation Roadmap

### Phase 1: Foundation & CRA Expansion (Months 1-3)

**Technical Deliverables:**

1. **CRA Rule Expansion**
   - Implement 50+ CRA rules covering all articles
   - Rule versioning system
   - Rule testing framework
   - Rule documentation generator

2. **Enhanced Dependency Parsing**
   - Support all major package managers (Java, Go, Rust, Ruby, PHP, .NET)
   - Transitive dependency resolution
   - Vulnerability database integration (OSV API)
   - License detection and compliance checking

3. **Performance Optimization**
   - Parallel rule evaluation (asyncio)
   - Caching layer (Redis)
   - Database query optimization
   - Incremental scanning support

4. **API Enhancements**
   - Complete REST API documentation (OpenAPI/Swagger)
   - API versioning strategy
   - Error handling standardization
   - Request/response validation

5. **Basic Web Dashboard**
   - Repository scan interface
   - Compliance report viewer
   - Rule explorer
   - Basic analytics

**Technical Tasks:**
- [ ] Implement dependency parsers for Java, Go, Rust, Ruby, PHP, .NET
- [ ] Integrate OSV API for vulnerability scanning
- [ ] Build rule versioning system
- [ ] Implement parallel rule evaluation
- [ ] Add Redis caching layer
- [ ] Create rule testing framework
- [ ] Build OpenAPI documentation generator
- [ ] Implement incremental scanning algorithm
- [ ] Create React dashboard components
- [ ] Set up monitoring and logging infrastructure

### Phase 2: AI Act Support (Months 4-6)

**Technical Deliverables:**

1. **AI Detection Engine**
   - Framework detection (TensorFlow, PyTorch, etc.)
   - Model file detection
   - Training code detection
   - Inference code detection

2. **AI System Classification**
   - Risk classification algorithm
   - Use case detection
   - Prohibited AI practice detection
   - High-risk AI system identification

3. **AI Act Rules**
   - 30+ AI Act rules
   - Model card validation
   - Training data documentation checks
   - Transparency requirement checks

4. **AI-Specific Data Model**
   - AISystem table
   - ModelCard table
   - TrainingData table
   - RiskAssessment table

**Technical Tasks:**
- [ ] Build AI framework detection service
- [ ] Implement AI system classification algorithm
- [ ] Create model card validator
- [ ] Implement AI Act rule set (30+ rules)
- [ ] Build training data detection
- [ ] Create AI system database schema
- [ ] Implement AI Act compliance scoring
- [ ] Build AI Act-specific reports

### Phase 3: Platform Expansion (Months 7-9)

**Technical Deliverables:**

1. **Multi-Repository Support**
   - GitLab API client
   - Bitbucket API client
   - Azure DevOps API client
   - Generic Git client

2. **CI/CD Integrations**
   - GitHub Actions action
   - GitLab CI template
   - Jenkins plugin
   - CircleCI orb
   - Azure Pipelines task

3. **GraphQL API**
   - GraphQL schema definition
   - Query resolvers
   - Mutation resolvers
   - Subscription support

4. **Webhook System**
   - Webhook registration API
   - Event delivery system
   - Retry logic
   - Webhook testing

5. **Enhanced Reporting**
   - PDF report generation
   - Excel export
   - Historical trend analysis
   - Comparative reports

**Technical Tasks:**
- [ ] Implement GitLab API client
- [ ] Implement Bitbucket API client
- [ ] Implement Azure DevOps API client
- [ ] Build generic Git client
- [ ] Create GitHub Actions action
- [ ] Build GitLab CI template
- [ ] Create Jenkins plugin
- [ ] Implement GraphQL API (Strawberry)
- [ ] Build webhook delivery system
- [ ] Implement PDF report generation
- [ ] Add Excel export functionality

### Phase 4: Enterprise Features (Months 10-12)

**Technical Deliverables:**

1. **Multi-Tenancy**
   - Organization management
   - Resource isolation
   - Billing integration

2. **Advanced Analytics**
   - Compliance trend analysis
   - Benchmarking engine
   - Predictive analytics
   - Custom dashboards

3. **Custom Rule Builder**
   - Visual rule editor
   - Rule testing interface
   - Rule marketplace

4. **Third-Party Integrations**
   - Jira integration
   - Slack/Teams integration
   - ServiceNow integration
   - Splunk integration

5. **Enterprise Security**
   - SSO (SAML, OIDC)
   - Advanced RBAC
   - Audit logging
   - Compliance certifications

**Technical Tasks:**
- [ ] Implement multi-tenancy architecture
- [ ] Build organization management APIs
- [ ] Create analytics engine
- [ ] Implement benchmarking system
- [ ] Build custom rule builder UI
- [ ] Create rule marketplace
- [ ] Implement Jira integration
- [ ] Build Slack/Teams integration
- [ ] Implement SSO (SAML/OIDC)
- [ ] Add advanced RBAC
- [ ] Set up audit logging system

### Phase 5: Additional Regulations (Months 13-15)

**Technical Deliverables:**

1. **GDPR Support**
   - Data privacy rule set
   - Consent management checks
   - Data retention checks
   - Right to erasure checks

2. **NIS2 Support**
   - Network security rules
   - Incident reporting checks
   - Security measures verification

3. **DSA Support**
   - Platform obligation checks
   - Content moderation checks
   - Transparency requirements

4. **Cross-Regulation Analysis**
   - Conflict detection
   - Synergy identification
   - Unified compliance scoring

**Technical Tasks:**
- [ ] Research GDPR technical requirements
- [ ] Implement GDPR rule set
- [ ] Research NIS2 technical requirements
- [ ] Implement NIS2 rule set
- [ ] Research DSA technical requirements
- [ ] Implement DSA rule set
- [ ] Build cross-regulation analysis engine

---

## 6. Technical Metrics and Monitoring

### 6.1 Performance Metrics

**Scan Performance:**
- P50 scan duration: <15 seconds
- P95 scan duration: <45 seconds
- P99 scan duration: <2 minutes
- Scan success rate: >99%

**API Performance:**
- P50 API response time: <100ms
- P95 API response time: <500ms
- P99 API response time: <1 second
- API error rate: <0.1%

**Database Performance:**
- P95 query time: <100ms
- Connection pool utilization: <80%
- Slow query count: <10 per hour

**System Resources:**
- CPU utilization: <70% average
- Memory utilization: <80% average
- Disk I/O: <80% capacity
- Network bandwidth: <70% capacity

### 6.2 Reliability Metrics

- **Uptime**: >99.9% (less than 8.76 hours downtime per year)
- **MTTR** (Mean Time To Recovery): <15 minutes
- **MTBF** (Mean Time Between Failures): >720 hours
- **Error Rate**: <0.1% of all operations

### 6.3 Monitoring and Alerting

**Key Metrics to Monitor:**
- Scan queue depth
- Scan failure rate
- API error rate
- Database connection pool
- Cache hit rate
- External API response times
- Background job queue depth

**Alerting Thresholds:**
- Scan failure rate >5%: Alert
- API error rate >1%: Alert
- Database connection pool >90%: Alert
- Scan queue depth >100: Alert
- External API timeout: Alert

**Monitoring Tools:**
- Prometheus for metrics collection
- Grafana for visualization
- Sentry for error tracking
- ELK Stack for log aggregation
- Datadog/New Relic for APM

---

## 7. Testing Requirements

### 7.1 Unit Testing

**Coverage Requirements:**
- Minimum 80% code coverage
- 100% coverage for critical paths (rule evaluation, verdict generation)
- All business logic must have unit tests

**Test Framework:**
- pytest for Python
- Jest for JavaScript/TypeScript
- Mock external dependencies

### 7.2 Integration Testing

**Test Categories:**
- API endpoint tests
- Database integration tests
- External service integration tests (GitHub API, OpenAI API)
- End-to-end scan workflow tests

**Test Framework:**
- pytest with pytest-asyncio
- Testcontainers for database testing
- Mock external APIs

### 7.3 Performance Testing

**Load Testing:**
- Simulate 1000+ concurrent scans
- Test API under load (10,000+ requests/minute)
- Database performance under load
- Cache performance under load

**Tools:**
- Locust for load testing
- k6 for API load testing
- pgbench for database benchmarking

### 7.4 Security Testing

**Test Areas:**
- Authentication and authorization
- Input validation
- SQL injection prevention
- XSS prevention
- API security
- Secrets management

**Tools:**
- OWASP ZAP for security scanning
- Bandit for Python security linting
- Snyk for dependency vulnerability scanning

---

## 8. Deployment and Operations

### 8.1 Deployment Strategy

**Environments:**
- **Development**: Local development with Docker Compose
- **Staging**: Staging environment for testing
- **Production**: Production environment with high availability

**Deployment Process:**
- Git-based deployment (GitHub Actions / GitLab CI)
- Automated testing before deployment
- Blue-green deployment for zero downtime
- Database migrations with rollback capability

### 8.2 Infrastructure as Code

**Tools:**
- Terraform for infrastructure provisioning
- Ansible for configuration management
- Kubernetes manifests for container orchestration

### 8.3 Backup and Disaster Recovery

**Backup Strategy:**
- Database backups: Daily full backups, hourly incremental backups
- Object storage backups: Daily snapshots
- Backup retention: 30 days

**Disaster Recovery:**
- RTO (Recovery Time Objective): <4 hours
- RPO (Recovery Point Objective): <1 hour
- Multi-region deployment for high availability

### 8.4 Scaling Strategy

**Horizontal Scaling:**
- Stateless API servers (scale based on CPU/memory)
- Background workers (scale based on queue depth)
- Database read replicas for reporting queries

**Vertical Scaling:**
- Database instance scaling for write-heavy workloads
- Cache cluster scaling for high read loads

**Auto-Scaling:**
- Kubernetes HPA (Horizontal Pod Autoscaler)
- Cloud provider auto-scaling groups
- Scale based on CPU, memory, and queue metrics

---

## 9. Technical Risks and Mitigation

### 9.1 Technical Risks

**Risk: Rule Evaluation Accuracy**
- **Impact**: High - Incorrect compliance verdicts
- **Probability**: Medium
- **Mitigation**:
  - Extensive unit and integration testing
  - Human review of rule implementations
  - Confidence scoring for uncertain evaluations
  - Regular rule accuracy audits

**Risk: Performance at Scale**
- **Impact**: High - Slow scans, poor user experience
- **Probability**: Medium
- **Mitigation**:
  - Performance testing and optimization
  - Caching strategies
  - Parallel processing
  - Incremental scanning
  - Load testing before releases

**Risk: External API Dependencies**
- **Impact**: Medium - Service degradation if external APIs fail
- **Probability**: High
- **Mitigation**:
  - Circuit breakers for external API calls
  - Retry logic with exponential backoff
  - Fallback mechanisms
  - Rate limit handling
  - Monitoring and alerting

**Risk: Database Performance**
- **Impact**: High - Slow queries, system degradation
- **Probability**: Medium
- **Mitigation**:
  - Proper indexing strategy
  - Query optimization
  - Connection pooling
  - Read replicas for reporting
  - Database monitoring

**Risk: False Positives Blocking Deployments**
- **Impact**: High - Blocking legitimate deployments
- **Probability**: Medium
- **Mitigation**:
  - Severity-based blocking (only Critical/High)
  - Exception workflow
  - Human review option
  - Confidence thresholds
  - Rule tuning based on feedback

### 9.2 Regulatory Risks

**Risk: Regulation Interpretation Changes**
- **Impact**: High - Rules become incorrect
- **Probability**: Low
- **Mitigation**:
  - Rule versioning system
  - Expert review process
  - Regulatory monitoring
  - Rule update process

**Risk: Incomplete Regulation Coverage**
- **Impact**: Medium - Missing compliance requirements
- **Probability**: Medium
- **Mitigation**:
  - Phased rollout
  - Expert consultation
  - Continuous rule expansion
  - User feedback integration

---

## 10. Appendices

### 10.1 Glossary

- **CRA**: EU Cyber Resilience Act
- **AI Act**: EU Artificial Intelligence Act
- **SBOM**: Software Bill of Materials
- **SAST**: Static Application Security Testing
- **GPAI**: General-Purpose AI Model
- **HR AI**: High-Risk AI System
- **LLM**: Large Language Model
- **API**: Application Programming Interface
- **CI/CD**: Continuous Integration/Continuous Deployment
- **RBAC**: Role-Based Access Control
- **SSO**: Single Sign-On
- **OIDC**: OpenID Connect
- **SAML**: Security Assertion Markup Language

### 10.2 Technical References

- EU Cyber Resilience Act: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2065
- EU AI Act: https://artificialintelligenceact.eu/
- CRA Rule Pack v0.1: `eura_knowledge/cra_rule_pack_v0.1.txt`
- EURA Architecture: `docs/WORKFLOW_AND_ARCHITECTURE.md`
- FastAPI Documentation: https://fastapi.tiangolo.com/
- PostgreSQL Documentation: https://www.postgresql.org/docs/
- Redis Documentation: https://redis.io/docs/

### 10.3 Code Examples

**Rule Evaluation Example:**
```python
# Example rule evaluation
rule = RuleLoader().load_rule("CRA-BASE-001")
signals = SignalBuilder().build_signals(scan_result)
evidence = EvidenceCollector().collect_evidence(rule, scan_result)
result = rule.evaluate(signals, evidence)
# Returns: RuleResult(status="FAIL", confidence=0.9, evidence={...})
```

**Scan Execution Example:**
```python
# Example scan execution
scan_executor = ScanExecutor()
result = await scan_executor.execute_scan(
    repo_name="owner/repo",
    installation_id=12345,
    regulations=["CRA", "AI_ACT"]
)
# Returns: ScanResultV1(verdict="SHIP_ALLOWED", rule_results=[...])
```

---

**Document Owner**: Engineering Team  
**Last Updated**: January 2026  
**Next Review**: April 2026

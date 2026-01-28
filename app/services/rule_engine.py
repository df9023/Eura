"""Rule Engine - Core rule evaluation architecture for Section 3.2."""
import asyncio
from typing import List, Dict, Optional, Any, Literal
from datetime import datetime
from dataclasses import dataclass
from app.core.logger import logger
from app.models.domain import Finding
from app.schemas.requests import Dependency

# Rule status types
RuleStatus = Literal["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]


@dataclass
class RuleResult:
    """Result of rule evaluation."""
    rule_id: str
    status: RuleStatus
    confidence: float
    reason: str
    evidence: Dict[str, Any]
    evaluated_at: str


class RuleModule:
    """Base class for rule modules - encapsulates rule definition and evaluation logic."""
    
    def __init__(self, rule_id: str, rule_definition: Dict[str, Any]):
        """
        Initialize rule module.
        
        Args:
            rule_id: Unique rule identifier
            rule_definition: Rule definition dictionary from rules_db.json
        """
        self.rule_id = rule_id
        self.definition = rule_definition
        self.evaluation_method = rule_definition.get("evaluation_method") or rule_definition.get("check_method", "unknown")
    
    def check_applicability(self, signals: Dict[str, Any]) -> bool:
        """Check if rule is applicable based on signals."""
        from app.services.compliance import check_applicability
        return check_applicability(self.definition, signals)
    
    def evaluate(
        self,
        signals: Dict[str, Any],
        evidence: Dict[str, Any]
    ) -> RuleResult:
        """
        Evaluate rule against signals and evidence.
        
        Args:
            signals: Signal dictionary from scan results
            evidence: Evidence dictionary with rule-specific data
        
        Returns:
            RuleResult with status, confidence, reason, and evidence
        """
        # Check applicability first
        if not self.check_applicability(signals):
            return RuleResult(
                rule_id=self.rule_id,
                status="NOT_APPLICABLE",
                confidence=1.0,
                reason="Rule not applicable based on repository characteristics",
                evidence={},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
        
        # Route to specific evaluator based on evaluation_method
        if self.evaluation_method == "file_presence":
            return self._evaluate_file_presence(evidence)
        elif self.evaluation_method == "dependency_analysis":
            return self._evaluate_dependency(evidence)
        elif self.evaluation_method == "content_analysis":
            return self._evaluate_content(evidence)
        elif self.evaluation_method == "documentation_quality":
            return self._evaluate_documentation_quality(evidence)
        else:
            return RuleResult(
                rule_id=self.rule_id,
                status="UNKNOWN",
                confidence=0.2,
                reason=f"Evaluation method '{self.evaluation_method}' not implemented",
                evidence={},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
    
    def _evaluate_file_presence(self, evidence: Dict[str, Any]) -> RuleResult:
        """Evaluate file presence rule."""
        required_evidence = self.definition.get("required_evidence", [])
        found_files = []
        
        for ev_spec in required_evidence:
            source = ev_spec.get("source", "")
            if evidence.get(f"file_exists_{source}", False) or source in evidence.get("repo_files", []):
                found_files.append(source)
        
        if found_files:
            return RuleResult(
                rule_id=self.rule_id,
                status="PASS",
                confidence=0.8,
                reason=f"Required files found: {', '.join(found_files[:3])}",
                evidence={"found_files": found_files},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
        else:
            return RuleResult(
                rule_id=self.rule_id,
                status="FAIL",
                confidence=0.7,
                reason="Required files not found",
                evidence={"required_files": [ev.get("source") for ev in required_evidence]},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
    
    def _evaluate_dependency(self, evidence: Dict[str, Any]) -> RuleResult:
        """Evaluate dependency rule."""
        dependencies = evidence.get("dependencies", [])
        
        if self.rule_id == "CRA-BASE-002":
            if not dependencies:
                return RuleResult(
                    rule_id=self.rule_id,
                    status="UNKNOWN",
                    confidence=0.5,
                    reason="No dependencies found - rule may not be applicable",
                    evidence={},
                    evaluated_at=datetime.utcnow().isoformat() + "Z"
                )
            return RuleResult(
                rule_id=self.rule_id,
                status="PASS",
                confidence=0.9,
                reason=f"Found {len(dependencies)} dependencies in manifest files",
                evidence={"dependency_count": len(dependencies)},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
        
        # Default dependency rule evaluation
        return RuleResult(
            rule_id=self.rule_id,
            status="UNKNOWN",
            confidence=0.3,
            reason="Dependency rule evaluation not fully implemented",
            evidence={},
            evaluated_at=datetime.utcnow().isoformat() + "Z"
        )
    
    def _evaluate_content(self, evidence: Dict[str, Any]) -> RuleResult:
        """Evaluate content-based rule (e.g., secrets detection)."""
        findings = evidence.get("findings", [])
        
        if self.rule_id == "CRA-BASE-008":
            secret_findings = [f for f in findings if getattr(f, "category", None) == "secrets"]
            if secret_findings:
                return RuleResult(
                    rule_id=self.rule_id,
                    status="FAIL",
                    confidence=0.9,
                    reason=f"Found {len(secret_findings)} potential hardcoded secret(s)",
                    evidence={"secret_count": len(secret_findings)},
                    evaluated_at=datetime.utcnow().isoformat() + "Z"
                )
            return RuleResult(
                rule_id=self.rule_id,
                status="PASS",
                confidence=0.8,
                reason="No hardcoded secrets detected",
                evidence={},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
        
        return RuleResult(
            rule_id=self.rule_id,
            status="UNKNOWN",
            confidence=0.2,
            reason="Content rule evaluation not implemented",
            evidence={},
            evaluated_at=datetime.utcnow().isoformat() + "Z"
        )
    
    def _evaluate_documentation_quality(self, evidence: Dict[str, Any]) -> RuleResult:
        """Evaluate documentation quality rule (requires async LLM call)."""
        # This will be handled by async evaluation
        return RuleResult(
            rule_id=self.rule_id,
            status="UNKNOWN",
            confidence=0.5,
            reason="Documentation quality evaluation requires async LLM call",
            evidence={},
            evaluated_at=datetime.utcnow().isoformat() + "Z"
        )


class SignalBuilder:
    """Builds signals from scan results for rule evaluation."""
    
    @staticmethod
    def build_signals(
        findings: List[Finding],
        dependencies: List[Dependency],
        repo_files: List[str],
        ai_components: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Extract signals from scan results.
        
        Args:
            findings: List of security findings
            dependencies: List of dependencies
            repo_files: List of file paths
            ai_components: Optional AI detection results
        
        Returns:
            Dictionary of signals for rule evaluation
        """
        signals = {
            "has_security_policy": any(
                "security" in f.lower() and f.endswith(".md") for f in repo_files
            ),
            "dependency_count": len(dependencies),
            "has_lockfile": any(
                f.endswith((".lock", "package-lock.json", "yarn.lock", "Pipfile.lock", "poetry.lock"))
                for f in repo_files
            ),
            "has_dockerfile": any("dockerfile" in f.lower() for f in repo_files),
            "has_cicd_config": any(
                f.endswith((".yml", ".yaml")) and
                ("workflow" in f.lower() or "ci" in f.lower() or ".github" in f)
                for f in repo_files
            ),
            "has_changelog": any(
                "changelog" in f.lower() or "release" in f.lower() for f in repo_files
            ),
            "has_hardcoded_secrets": any(
                getattr(f, "category", None) == "secrets" for f in findings
            ),
            "vulnerable_dependency_count": 0,  # Would need vulnerability DB integration
            "has_security_testing": False,  # Would need CI/CD config parsing
            "release_tag_count": 0,  # Would need git API
            "days_since_last_update": 0,  # Would need git API
        }
        
        # Add AI-related signals if available
        if ai_components:
            signals.update({
                "has_ai_frameworks": len(ai_components.get("frameworks", [])) > 0,
                "ai_framework_count": len(ai_components.get("frameworks", [])),
                "has_model_files": len(ai_components.get("model_files", [])) > 0,
                "has_training_code": len(ai_components.get("training_files", [])) > 0,
                "has_inference_code": len(ai_components.get("inference_files", [])) > 0,
            })
        
        return signals


class EvidenceCollector:
    """Collects evidence required for rule evaluation."""
    
    def __init__(self, repo_files: List[str], findings: List[Finding], dependencies: List[Dependency]):
        """
        Initialize evidence collector.
        
        Args:
            repo_files: List of file paths in repository
            findings: List of security findings
            dependencies: List of dependencies
        """
        self.repo_files = repo_files
        self.findings = findings
        self.dependencies = dependencies
    
    def collect_evidence(self, rule: RuleModule) -> Dict[str, Any]:
        """
        Collect evidence required for rule evaluation.
        
        Args:
            rule: Rule module to collect evidence for
        
        Returns:
            Dictionary with evidence data
        """
        evidence = {
            "repo_files": self.repo_files,
            "findings": self.findings,
            "dependencies": self.dependencies,
        }
        
        # Add file existence evidence
        for ev_spec in rule.definition.get("required_evidence", []):
            source = ev_spec.get("source", "")
            evidence[f"file_exists_{source}"] = source in self.repo_files
        
        return evidence


class RuleLoader:
    """Loads and caches rules from rules database."""
    
    def __init__(self):
        """Initialize rule loader."""
        self._rules_cache: Optional[Dict[str, RuleModule]] = None
        self._rules_db: Optional[Dict[str, Any]] = None
    
    def load_rules_db(self) -> Dict[str, Any]:
        """Load rules database (cached)."""
        if self._rules_db is not None:
            return self._rules_db
        
        from app.services.compliance import load_rules_db
        self._rules_db = load_rules_db()
        return self._rules_db
    
    def load_rules(self, regulations: Optional[List[str]] = None) -> List[RuleModule]:
        """
        Load rules as RuleModule objects.
        
        Args:
            regulations: Optional list of regulations to filter by (e.g., ["CRA"])
        
        Returns:
            List of RuleModule objects
        """
        rules_db = self.load_rules_db()
        rules = rules_db.get("rules", [])
        
        if regulations:
            rules = [r for r in rules if r.get("regulation") in regulations]
        
        return [RuleModule(rule["rule_id"], rule) for rule in rules]
    
    def get_rule(self, rule_id: str) -> Optional[RuleModule]:
        """Get a specific rule by ID."""
        rules_db = self.load_rules_db()
        rules = rules_db.get("rules", [])
        
        for rule_def in rules:
            if rule_def.get("rule_id") == rule_id:
                return RuleModule(rule_id, rule_def)
        
        return None


class RuleEvaluationEngine:
    """Main rule evaluation engine with parallel evaluation support."""
    
    def __init__(self):
        """Initialize rule evaluation engine."""
        self.rule_loader = RuleLoader()
        self.signal_builder = SignalBuilder()
    
    async def evaluate_repo(
        self,
        findings: List[Finding],
        dependencies: List[Dependency],
        repo_files: List[str],
        regulations: Optional[List[str]] = None,
        ai_components: Optional[Dict[str, Any]] = None,
        repo: Optional[Any] = None,
        read_file_func: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Evaluate repository against all applicable rules.
        
        Args:
            findings: List of security findings
            dependencies: List of dependencies
            repo_files: List of file paths
            regulations: Optional list of regulations to evaluate
            ai_components: Optional AI detection results
            repo: Optional GitHub repo object
            read_file_func: Optional function to read file content
        
        Returns:
            Dictionary with compliance report containing rule_results
        """
        # Load rules
        rules = self.rule_loader.load_rules(regulations)
        
        if not rules:
            logger.warning("No rules loaded, returning empty compliance report")
            return {
                "rule_results": [],
                "evaluated_at": datetime.utcnow().isoformat() + "Z",
                "total_rules": 0,
                "passed": 0,
                "failed": 0,
                "unknown": 0,
                "not_applicable": 0
            }
        
        # Build signals
        signals = self.signal_builder.build_signals(findings, dependencies, repo_files, ai_components)
        
        # Collect base evidence
        evidence_collector = EvidenceCollector(repo_files, findings, dependencies)
        
        # Evaluate rules in parallel (except documentation rules that need async LLM)
        rule_results = await self._evaluate_rules_parallel(
            rules, signals, evidence_collector, repo, read_file_func
        )
        
        # Calculate summary statistics
        status_counts = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0}
        for result in rule_results:
            status = result.get("status", "UNKNOWN")
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "rule_results": rule_results,
            "evaluated_at": datetime.utcnow().isoformat() + "Z",
            "total_rules": len(rule_results),
            "passed": status_counts["PASS"],
            "failed": status_counts["FAIL"],
            "unknown": status_counts["UNKNOWN"],
            "not_applicable": status_counts["NOT_APPLICABLE"]
        }
    
    async def _evaluate_rules_parallel(
        self,
        rules: List[RuleModule],
        signals: Dict[str, Any],
        evidence_collector: EvidenceCollector,
        repo: Optional[Any],
        read_file_func: Optional[Any]
    ) -> List[Dict[str, Any]]:
        """Evaluate multiple rules concurrently."""
        tasks = []
        
        for rule in rules:
            # Documentation rules need async LLM evaluation
            if rule.evaluation_method == "documentation_quality" or rule.rule_id in ["CRA-BASE-001", "CRA-BASE-007"]:
                tasks.append(
                    self._evaluate_rule_async(rule, signals, evidence_collector, repo, read_file_func)
                )
            else:
                # Synchronous rules can be evaluated directly
                tasks.append(
                    self._evaluate_rule_sync(rule, signals, evidence_collector)
                )
        
        results = await asyncio.gather(*tasks)
        return results
    
    async def _evaluate_rule_sync(
        self,
        rule: RuleModule,
        signals: Dict[str, Any],
        evidence_collector: EvidenceCollector
    ) -> Dict[str, Any]:
        """Evaluate a synchronous rule."""
        try:
            evidence = evidence_collector.collect_evidence(rule)
            result = rule.evaluate(signals, evidence)
            
            return {
                "rule_id": result.rule_id,
                "status": result.status,
                "confidence": result.confidence,
                "reason": result.reason,
                "evaluated_at": result.evaluated_at
            }
        except Exception as e:
            logger.error("Error evaluating rule %s: %s", rule.rule_id, str(e)[:200])
            return {
                "rule_id": rule.rule_id,
                "status": "UNKNOWN",
                "confidence": 0.1,
                "reason": f"Evaluation error: {str(e)[:100]}",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            }
    
    async def _evaluate_rule_async(
        self,
        rule: RuleModule,
        signals: Dict[str, Any],
        evidence_collector: EvidenceCollector,
        repo: Optional[Any],
        read_file_func: Optional[Any]
    ) -> Dict[str, Any]:
        """Evaluate an async rule (documentation quality with LLM)."""
        try:
            # Use existing LLM evaluation for documentation rules
            from app.services.compliance import evaluate_documentation_rule_with_llm
            
            evidence = evidence_collector.collect_evidence(rule)
            result_dict = await evaluate_documentation_rule_with_llm(
                rule.definition,
                evidence_collector.repo_files,
                repo,
                read_file_func
            )
            
            return result_dict
        except Exception as e:
            logger.error("Error evaluating async rule %s: %s", rule.rule_id, str(e)[:200])
            return {
                "rule_id": rule.rule_id,
                "status": "UNKNOWN",
                "confidence": 0.1,
                "reason": f"Async evaluation error: {str(e)[:100]}",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            }

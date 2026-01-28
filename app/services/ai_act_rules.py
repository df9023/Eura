"""AI Act Rule Implementation (Section 3.2.4)."""
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.services.rule_engine import RuleModule, RuleResult
from app.core.logger import logger


class AIClassificationRule(RuleModule):
    """Rule for AI system classification."""
    
    def evaluate(
        self,
        signals: Dict[str, Any],
        evidence: Dict[str, Any]
    ) -> RuleResult:
        """
        Evaluate AI system classification rule.
        
        Checks if AI frameworks are detected and classifies the AI system.
        """
        # Check applicability
        if not self.check_applicability(signals):
            return RuleResult(
                rule_id=self.rule_id,
                status="NOT_APPLICABLE",
                confidence=1.0,
                reason="Rule not applicable - no AI frameworks detected",
                evidence={},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
        
        ai_frameworks = signals.get("ai_frameworks", [])
        use_case_indicators = evidence.get("use_case_indicators", {})
        
        if not ai_frameworks:
            return RuleResult(
                rule_id=self.rule_id,
                status="NOT_APPLICABLE",
                confidence=1.0,
                reason="No AI frameworks detected",
                evidence={},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
        
        # Classify AI system based on frameworks and use cases
        classification = self._classify_ai_system(ai_frameworks, use_case_indicators, signals)
        
        return RuleResult(
            rule_id=self.rule_id,
            status="PASS",
            confidence=0.8,
            reason=f"AI system classified as: {classification}",
            evidence={"classification": classification, "frameworks": ai_frameworks},
            evaluated_at=datetime.utcnow().isoformat() + "Z"
        )
    
    def _classify_ai_system(
        self,
        frameworks: List[str],
        use_case_indicators: Dict[str, Any],
        signals: Dict[str, Any]
    ) -> str:
        """
        Classify AI system based on frameworks and use cases.
        
        Returns: "high_risk", "limited_risk", "minimal_risk", or "unknown"
        """
        # High-risk indicators
        high_risk_frameworks = {"transformers", "langchain", "llama-index", "anthropic", "openai"}
        has_high_risk_framework = any(fw in high_risk_frameworks for fw in frameworks)
        
        # Check for high-risk use cases
        has_model_files = signals.get("has_model_files", False)
        has_training_code = signals.get("has_training_code", False)
        
        # Simple classification logic
        if has_high_risk_framework and (has_model_files or has_training_code):
            return "high_risk"
        elif has_model_files or has_training_code:
            return "limited_risk"
        elif frameworks:
            return "minimal_risk"
        else:
            return "unknown"


class HighRiskAIDocumentationRule(RuleModule):
    """Rule for high-risk AI system documentation requirements."""
    
    def evaluate(
        self,
        signals: Dict[str, Any],
        evidence: Dict[str, Any]
    ) -> RuleResult:
        """
        Evaluate high-risk AI documentation requirements.
        
        Checks if required documentation exists for high-risk AI systems.
        """
        # Check if this is a high-risk AI system
        ai_classification = signals.get("ai_classification", "unknown")
        
        if ai_classification != "high_risk":
            return RuleResult(
                rule_id=self.rule_id,
                status="NOT_APPLICABLE",
                confidence=1.0,
                reason=f"AI system classification is '{ai_classification}', not high-risk",
                evidence={"classification": ai_classification},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
        
        # Required documentation for high-risk AI systems
        required_docs = [
            "risk_management_doc",
            "data_governance_doc",
            "technical_documentation",
            "model_card"
        ]
        
        # Check for documentation files
        repo_files = evidence.get("repo_files", [])
        found_docs = []
        
        # Check for model card
        if any("model" in f.lower() and "card" in f.lower() for f in repo_files):
            found_docs.append("model_card")
        
        # Check for risk management documentation
        if any("risk" in f.lower() and f.endswith(".md") for f in repo_files):
            found_docs.append("risk_management_doc")
        
        # Check for data governance documentation
        if any("data" in f.lower() and ("governance" in f.lower() or "policy" in f.lower()) for f in repo_files):
            found_docs.append("data_governance_doc")
        
        # Check for technical documentation
        if any(f.lower().endswith("readme.md") or "docs" in f.lower() for f in repo_files):
            found_docs.append("technical_documentation")
        
        missing_docs = set(required_docs) - set(found_docs)
        
        if len(found_docs) == len(required_docs):
            return RuleResult(
                rule_id=self.rule_id,
                status="PASS",
                confidence=0.9,
                reason="All required documentation found for high-risk AI system",
                evidence={"found_docs": found_docs},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )
        else:
            return RuleResult(
                rule_id=self.rule_id,
                status="FAIL",
                confidence=0.8,
                reason=f"Missing required documentation: {', '.join(missing_docs)}",
                evidence={"found_docs": found_docs, "missing_docs": list(missing_docs)},
                evaluated_at=datetime.utcnow().isoformat() + "Z"
            )


def create_ai_act_rule_module(rule_id: str, rule_definition: Dict[str, Any]) -> Optional[RuleModule]:
    """
    Factory function to create AI Act rule modules.
    
    Args:
        rule_id: Rule identifier
        rule_definition: Rule definition dictionary
    
    Returns:
        Appropriate AI Act rule module or None
    """
    # Map rule IDs to rule classes
    ai_act_rule_classes = {
        "AI-ACT-CLASS-001": AIClassificationRule,
        "AI-ACT-DOC-001": HighRiskAIDocumentationRule,
    }
    
    rule_class = ai_act_rule_classes.get(rule_id)
    if rule_class:
        return rule_class(rule_id, rule_definition)
    
    return None

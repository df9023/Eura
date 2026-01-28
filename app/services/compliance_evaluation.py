"""Compliance Evaluation Engine (Section 3.3) - Verdict generation and scoring."""
from typing import List, Dict, Any, Literal, Optional
from dataclasses import dataclass
from app.core.logger import logger


@dataclass
class Verdict:
    """Verdict result from compliance evaluation."""
    verdict: Literal["SHIP_ALLOWED", "SHIP_BLOCKED"]
    blocking_rules: List[str]
    reason: Optional[str] = None


@dataclass
class ComplianceScore:
    """Compliance score result."""
    score: float  # 0-100
    passed: int
    failed: int
    unknown: int
    not_applicable: int
    total_applicable: int


class VerdictGenerator:
    """Generates SHIP_ALLOWED or SHIP_BLOCKED verdicts based on rule results."""
    
    def generate_verdict(
        self,
        rule_results: List[Dict[str, Any]],
        environment: str = "production",
        rules_db: Optional[Dict[str, Any]] = None
    ) -> Verdict:
        """
        Generate SHIP_ALLOWED or SHIP_BLOCKED verdict.
        
        Logic:
        - If any CRITICAL severity rule FAILS -> SHIP_BLOCKED
        - If any HIGH severity rule FAILS and environment == "production" -> SHIP_BLOCKED
        - If any HIGH severity rule FAILS and environment != "production" -> SHIP_ALLOWED (with warning)
        - Otherwise -> SHIP_ALLOWED
        
        Args:
            rule_results: List of rule result dictionaries
            environment: Deployment environment (dev, staging, production, eu-production)
            rules_db: Optional rules database to get rule severity
        
        Returns:
            Verdict object with verdict and blocking rules
        """
        blocking_rules: List[str] = []
        
        # Load rules DB if not provided (for severity lookup)
        if rules_db is None:
            from app.services.compliance import load_rules_db
            rules_db = load_rules_db()
        
        rules_by_id = {
            rule.get("rule_id"): rule
            for rule in rules_db.get("rules", [])
        }
        
        for result in rule_results:
            if result.get("status") != "FAIL":
                continue
            
            rule_id = result.get("rule_id", "UNKNOWN")
            rule_metadata = rules_by_id.get(rule_id, {})
            
            # Get severity from rule metadata
            severity_dict = rule_metadata.get("severity", {})
            severity = severity_dict.get("overall", "medium") if isinstance(severity_dict, dict) else "medium"
            
            # Check if this rule should block shipping
            is_blocking = False
            
            if severity == "critical":
                # Critical rules always block
                is_blocking = True
            elif severity == "high":
                # High severity rules block in production
                if environment == "production" or environment == "eu-production":
                    is_blocking = True
            
            if is_blocking:
                blocking_rules.append(rule_id)
        
        if blocking_rules:
            reason = f"Blocked by {len(blocking_rules)} rule(s): {', '.join(blocking_rules[:3])}"
            if len(blocking_rules) > 3:
                reason += f" and {len(blocking_rules) - 3} more"
            
            return Verdict(
                verdict="SHIP_BLOCKED",
                blocking_rules=blocking_rules,
                reason=reason
            )
        
        return Verdict(
            verdict="SHIP_ALLOWED",
            blocking_rules=[],
            reason="All applicable rules passed"
        )


def generate_multi_regulation_verdict(
    cra_results: List[Dict[str, Any]],
    ai_act_results: List[Dict[str, Any]],
    environment: str = "production",
    rules_db: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate combined verdict across regulations.
    
    Args:
        cra_results: CRA rule results
        ai_act_results: AI Act rule results
        environment: Deployment environment
        rules_db: Optional rules database
    
    Returns:
        Dictionary with overall verdict and per-regulation verdicts
    """
    generator = VerdictGenerator()
    
    cra_verdict = generator.generate_verdict(cra_results, environment, rules_db)
    ai_act_verdict = generator.generate_verdict(ai_act_results, environment, rules_db)
    
    overall_verdict = "SHIP_BLOCKED" if (
        cra_verdict.verdict == "SHIP_BLOCKED" or
        ai_act_verdict.verdict == "SHIP_BLOCKED"
    ) else "SHIP_ALLOWED"
    
    return {
        "overall_verdict": overall_verdict,
        "regulations": {
            "CRA": {
                "verdict": cra_verdict.verdict,
                "blocking_rules": cra_verdict.blocking_rules,
                "reason": cra_verdict.reason
            },
            "AI_ACT": {
                "verdict": ai_act_verdict.verdict,
                "blocking_rules": ai_act_verdict.blocking_rules,
                "reason": ai_act_verdict.reason
            }
        },
        "blocking_rules": list(set(cra_verdict.blocking_rules + ai_act_verdict.blocking_rules))
    }


class ComplianceScorer:
    """Calculates compliance scores from rule results."""
    
    def __init__(self):
        """Initialize compliance scorer with severity weights."""
        self.weights = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0
        }
    
    def calculate_score(
        self,
        rule_results: List[Dict[str, Any]],
        rules_db: Optional[Dict[str, Any]] = None
    ) -> ComplianceScore:
        """
        Calculate compliance score.
        
        Score = (passed_rules * weight) / (total_applicable_rules * weight) * 100
        
        Args:
            rule_results: List of rule result dictionaries
            rules_db: Optional rules database to get rule severity
        
        Returns:
            ComplianceScore object with score and counts
        """
        # Load rules DB if not provided
        if rules_db is None:
            from app.services.compliance import load_rules_db
            rules_db = load_rules_db()
        
        rules_by_id = {
            rule.get("rule_id"): rule
            for rule in rules_db.get("rules", [])
        }
        
        total_weight = 0.0
        passed_weight = 0.0
        failed_weight = 0.0
        
        passed_count = 0
        failed_count = 0
        unknown_count = 0
        not_applicable_count = 0
        
        for result in rule_results:
            status = result.get("status", "UNKNOWN")
            rule_id = result.get("rule_id", "UNKNOWN")
            
            # Count by status
            if status == "PASS":
                passed_count += 1
            elif status == "FAIL":
                failed_count += 1
            elif status == "UNKNOWN":
                unknown_count += 1
            elif status == "NOT_APPLICABLE":
                not_applicable_count += 1
            
            # Skip NOT_APPLICABLE rules from scoring
            if status == "NOT_APPLICABLE":
                continue
            
            # Get severity for weighting
            rule_metadata = rules_by_id.get(rule_id, {})
            severity_dict = rule_metadata.get("severity", {})
            severity = severity_dict.get("overall", "medium") if isinstance(severity_dict, dict) else "medium"
            
            weight = self.weights.get(severity, 1.0)
            total_weight += weight
            
            if status == "PASS":
                passed_weight += weight
            elif status == "FAIL":
                failed_weight += weight
        
        # Calculate score
        score = (passed_weight / total_weight * 100) if total_weight > 0 else 0.0
        
        total_applicable = passed_count + failed_count + unknown_count
        
        return ComplianceScore(
            score=round(score, 2),
            passed=passed_count,
            failed=failed_count,
            unknown=unknown_count,
            not_applicable=not_applicable_count,
            total_applicable=total_applicable
        )
    
    def calculate_per_regulation_scores(
        self,
        rule_results: List[Dict[str, Any]],
        rules_db: Optional[Dict[str, Any]] = None
    ) -> Dict[str, ComplianceScore]:
        """
        Calculate compliance scores per regulation.
        
        Args:
            rule_results: List of rule result dictionaries
            rules_db: Optional rules database
        
        Returns:
            Dictionary mapping regulation -> ComplianceScore
        """
        # Load rules DB if not provided
        if rules_db is None:
            from app.services.compliance import load_rules_db
            rules_db = load_rules_db()
        
        rules_by_id = {
            rule.get("rule_id"): rule
            for rule in rules_db.get("rules", [])
        }
        
        # Group results by regulation
        results_by_regulation: Dict[str, List[Dict[str, Any]]] = {}
        
        for result in rule_results:
            rule_id = result.get("rule_id", "UNKNOWN")
            rule_metadata = rules_by_id.get(rule_id, {})
            regulation = rule_metadata.get("regulation", "UNKNOWN")
            
            if regulation not in results_by_regulation:
                results_by_regulation[regulation] = []
            
            results_by_regulation[regulation].append(result)
        
        # Calculate score for each regulation
        scores = {}
        for regulation, reg_results in results_by_regulation.items():
            scores[regulation] = self.calculate_score(reg_results, rules_db)
        
        return scores

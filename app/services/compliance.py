"""Compliance rule evaluation service."""
import json
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Any, Literal
from datetime import datetime
from app.core.logger import logger
from app.models.domain import Finding
from app.schemas.requests import Dependency
from app.core.config import openai_client

# Rule status types
RuleStatus = Literal["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]

# In-memory cache for rules
_rules_db: Optional[Dict[str, Any]] = None


def load_rules_db() -> Dict[str, Any]:
    """Load rules database from JSON file (cached after first load)."""
    global _rules_db
    
    if _rules_db is not None:
        return _rules_db
    
    # Find rules_db.json relative to project root
    script_dir = Path(__file__).parent.parent.parent
    rules_path = script_dir / "app" / "data" / "rules_db.json"
    
    if not rules_path.exists():
        logger.warning("rules_db.json not found at %s, compliance evaluation will be limited", rules_path)
        _rules_db = {"rules": [], "remediation_catalog": {}}
        return _rules_db
    
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            _rules_db = json.load(f)
        logger.info("Loaded %d compliance rules from rules_db.json", len(_rules_db.get("rules", [])))
        return _rules_db
    except Exception as e:
        logger.error("Failed to load rules_db.json: %s", e)
        _rules_db = {"rules": [], "remediation_catalog": {}}
        return _rules_db


def check_applicability(rule: Dict[str, Any], signals: Dict[str, Any]) -> bool:
    """Check if a rule is applicable based on its applicability conditions and current signals."""
    applicability = rule.get("applicability", {})
    if not applicability:
        return True  # Default to applicable if no conditions
    
    operator = applicability.get("operator", "AND")
    conditions = applicability.get("conditions", [])
    
    if not conditions:
        return True
    
    def evaluate_condition(condition: Dict[str, Any]) -> bool:
        """Recursively evaluate a condition."""
        if "operator" in condition:
            # Nested condition
            nested_op = condition.get("operator", "AND")
            nested_conds = condition.get("conditions", [])
            results = [evaluate_condition(c) for c in nested_conds]
            if nested_op == "AND":
                return all(results)
            elif nested_op == "OR":
                return any(results)
            elif nested_op == "NOT":
                return not any(results)
            return True
        else:
            # Signal condition
            signal_name = condition.get("signal")
            if not signal_name:
                return True
            
            signal_value = signals.get(signal_name)
            cond_operator = condition.get("operator")
            cond_value = condition.get("value")
            
            if cond_operator == "exists":
                return signal_value is not None and signal_value is not False
            elif cond_operator == "not_exists":
                return signal_value is None or signal_value is False
            elif cond_operator == "equals":
                return signal_value == cond_value
            elif cond_operator == "contains":
                if isinstance(signal_value, str) and isinstance(cond_value, str):
                    return cond_value in signal_value
                return False
            elif cond_operator == "greater_than":
                return isinstance(signal_value, (int, float)) and signal_value > cond_value
            elif cond_operator == "less_than":
                return isinstance(signal_value, (int, float)) and signal_value < cond_value
            
            return True
    
    results = [evaluate_condition(c) for c in conditions]
    
    if operator == "AND":
        return all(results)
    elif operator == "OR":
        return any(results)
    elif operator == "NOT":
        return not any(results)
    
    return True


def evaluate_dependency_rule(rule: Dict[str, Any], dependencies: List[Dependency]) -> Dict[str, Any]:
    """Evaluate a rule that checks dependencies."""
    rule_id = rule.get("rule_id", "UNKNOWN")
    
    # CRA-BASE-002: Dependency Inventory (SBOM)
    if rule_id == "CRA-BASE-002":
        if not dependencies:
            return {
                "rule_id": rule_id,
                "status": "UNKNOWN",
                "confidence": 0.5,
                "reason": "No dependencies found - rule may not be applicable if repository has no dependencies",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            }
        return {
            "rule_id": rule_id,
            "status": "PASS",
            "confidence": 0.9,
            "reason": f"Found {len(dependencies)} dependencies in manifest files",
            "evaluated_at": datetime.utcnow().isoformat() + "Z"
        }
    
    # CRA-BASE-003: Dependency Vulnerability Management
    if rule_id == "CRA-BASE-003":
        if not dependencies:
            return {
                "rule_id": rule_id,
                "status": "NOT_APPLICABLE",
                "confidence": 1.0,
                "reason": "No dependencies to check",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            }
        # Note: Actual vulnerability checking would require integration with vulnerability DB
        # For now, we assume PASS if dependencies exist (vulnerability scanning is separate)
        return {
            "rule_id": rule_id,
            "status": "UNKNOWN",
            "confidence": 0.3,
            "reason": "Dependencies found but vulnerability status not checked (requires vulnerability DB integration)",
            "evaluated_at": datetime.utcnow().isoformat() + "Z"
        }
    
    # CRA-BASE-009: Dependency Pinning
    if rule_id == "CRA-BASE-009":
        if not dependencies:
            return {
                "rule_id": rule_id,
                "status": "NOT_APPLICABLE",
                "confidence": 1.0,
                "reason": "No dependencies to check",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            }
        # Check if versions are pinned (this is a simplified check)
        # In reality, we'd need to parse manifest files to check for version ranges
        return {
            "rule_id": rule_id,
            "status": "UNKNOWN",
            "confidence": 0.4,
            "reason": "Dependency pinning check requires manifest file analysis (not yet implemented)",
            "evaluated_at": datetime.utcnow().isoformat() + "Z"
        }
    
    # Default for unknown dependency rules
    return {
        "rule_id": rule_id,
        "status": "UNKNOWN",
        "confidence": 0.2,
        "reason": "Dependency rule evaluation not implemented for this rule",
        "evaluated_at": datetime.utcnow().isoformat() + "Z"
    }


def evaluate_finding_rule(rule: Dict[str, Any], findings: List[Finding]) -> Dict[str, Any]:
    """Evaluate a rule that checks findings."""
    rule_id = rule.get("rule_id", "UNKNOWN")
    
    # CRA-BASE-008: No Hardcoded Secrets
    if rule_id == "CRA-BASE-008":
        secret_findings = [f for f in findings if f.category == "secrets"]
        if secret_findings:
            return {
                "rule_id": rule_id,
                "status": "FAIL",
                "confidence": 0.9,
                "reason": f"Found {len(secret_findings)} potential hardcoded secret(s)",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            }
        return {
            "rule_id": rule_id,
            "status": "PASS",
            "confidence": 0.8,
            "reason": "No hardcoded secrets detected in scan",
            "evaluated_at": datetime.utcnow().isoformat() + "Z"
        }
    
    # Default for unknown finding rules
    return {
        "rule_id": rule_id,
        "status": "UNKNOWN",
        "confidence": 0.2,
        "reason": "Finding rule evaluation not implemented for this rule",
        "evaluated_at": datetime.utcnow().isoformat() + "Z"
    }


async def evaluate_documentation_rule_with_llm(
    rule: Dict[str, Any],
    repo_files: List[str],
    repo: Any,
    read_file_func: Any
) -> Dict[str, Any]:
    """Use LLM to evaluate documentation rules by checking file presence and content."""
    rule_id = rule.get("rule_id", "UNKNOWN")
    required_evidence = rule.get("required_evidence", [])
    
    # Check for required files
    found_files = []
    for evidence_spec in required_evidence:
        source = evidence_spec.get("source", "")
        if source in repo_files:
            found_files.append(source)
    
    # CRA-BASE-001: Security Policy Documentation
    if rule_id == "CRA-BASE-001":
        security_files = [f for f in repo_files if "security" in f.lower() and f.lower().endswith(".md")]
        if not security_files:
            return {
                "rule_id": rule_id,
                "status": "FAIL",
                "confidence": 0.9,
                "reason": "No SECURITY.md or security policy file found",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            }
        
        # Check content quality with LLM
        try:
            if read_file_func:
                content = read_file_func(repo, security_files[0])
            else:
                content = None
            if content:
                prompt = f"""Check if this security policy file is adequate for CRA compliance.
                
File: {security_files[0]}
Content:
{content[:2000]}

Does this file:
1. Explain how to report security vulnerabilities?
2. Provide contact information?
3. Define scope of what should be reported?

Respond with JSON: {{"adequate": true/false, "reason": "brief explanation"}}"""
                
                response = await openai_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a compliance auditor. Return only valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_tokens=200
                )
                
                result_text = response.choices[0].message.content.strip()
                if result_text.startswith("```"):
                    result_text = result_text.split("```")[1].replace("json", "").strip()
                
                result = json.loads(result_text)
                if result.get("adequate", False):
                    return {
                        "rule_id": rule_id,
                        "status": "PASS",
                        "confidence": 0.85,
                        "reason": f"Security policy file found and appears adequate: {security_files[0]}",
                        "evaluated_at": datetime.utcnow().isoformat() + "Z"
                    }
                else:
                    return {
                        "rule_id": rule_id,
                        "status": "FAIL",
                        "confidence": 0.7,
                        "reason": f"Security policy file exists but may be inadequate: {result.get('reason', 'Missing required elements')}",
                        "evaluated_at": datetime.utcnow().isoformat() + "Z"
                    }
        except Exception as e:
            logger.warning("LLM evaluation failed for %s: %s", rule_id, str(e)[:200])
            return {
                "rule_id": rule_id,
                "status": "UNKNOWN",
                "confidence": 0.5,
                "reason": f"File found but content evaluation failed: {str(e)[:100]}",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            }
    
    # CRA-BASE-007: Documentation of Security Features
    if rule_id == "CRA-BASE-007":
        readme_files = [f for f in repo_files if "readme" in f.lower() and f.lower().endswith(".md")]
        if not readme_files:
            return {
                "rule_id": rule_id,
                "status": "FAIL",
                "confidence": 0.8,
                "reason": "No README.md file found",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            }
        
        # Simplified check - in production, would use LLM to verify security section exists
        return {
            "rule_id": rule_id,
            "status": "UNKNOWN",
            "confidence": 0.5,
            "reason": "README found but security documentation quality not verified",
            "evaluated_at": datetime.utcnow().isoformat() + "Z"
        }
    
    # Default for unknown documentation rules
    return {
        "rule_id": rule_id,
        "status": "UNKNOWN",
        "confidence": 0.2,
        "reason": "Documentation rule evaluation not fully implemented for this rule",
        "evaluated_at": datetime.utcnow().isoformat() + "Z"
    }


def build_signals_from_scan(
    findings: List[Finding],
    dependencies: List[Dependency],
    repo_files: List[str]
) -> Dict[str, Any]:
    """Build signal dictionary from scan results."""
    signals = {
        "has_security_policy": any("security" in f.lower() and f.endswith(".md") for f in repo_files),
        "dependency_count": len(dependencies),
        "has_lockfile": any(f.endswith((".lock", "package-lock.json", "yarn.lock", "Pipfile.lock", "poetry.lock")) for f in repo_files),
        "has_dockerfile": any("dockerfile" in f.lower() for f in repo_files),
        "has_cicd_config": any(f.endswith((".yml", ".yaml")) and ("workflow" in f.lower() or "ci" in f.lower() or ".github" in f) for f in repo_files),
        "has_changelog": any("changelog" in f.lower() or "release" in f.lower() for f in repo_files),
        "has_hardcoded_secrets": any(f.category == "secrets" for f in findings),
        "vulnerable_dependency_count": 0,  # Would need vulnerability DB integration
        "has_security_testing": False,  # Would need CI/CD config parsing
        "release_tag_count": 0,  # Would need git API
        "days_since_last_update": 0,  # Would need git API
    }
    return signals


async def evaluate_repo(
    findings: List[Finding],
    dependencies: List[Dependency],
    repo_files: List[str],
    repo: Optional[Any] = None,
    read_file_func: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Evaluate all CRA compliance rules against scan results.
    
    Args:
        findings: List of security findings from scan
        dependencies: List of dependencies extracted from manifest files
        repo_files: List of file paths in the repository
        repo: Optional GitHub repo object for reading files
        read_file_func: Optional function to read file content (repo, path) -> content
    
    Returns:
        Dictionary with compliance_report containing rule_results
    """
    rules_db = load_rules_db()
    rules = rules_db.get("rules", [])
    
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
    
    # Build signals from scan results
    signals = build_signals_from_scan(findings, dependencies, repo_files)
    
    rule_results = []
    
    for rule in rules:
        rule_id = rule.get("rule_id", "UNKNOWN")
        check_method = rule.get("check_method", "repo_scan_static")
        
        # Check applicability
        if not check_applicability(rule, signals):
            rule_results.append({
                "rule_id": rule_id,
                "status": "NOT_APPLICABLE",
                "confidence": 1.0,
                "reason": "Rule not applicable based on repository characteristics",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            })
            continue
        
        # Evaluate based on check_method
        try:
            if check_method == "dependency_analysis":
                result = evaluate_dependency_rule(rule, dependencies)
            elif check_method == "content_analysis" and rule_id == "CRA-BASE-008":
                # Hardcoded secrets check
                result = evaluate_finding_rule(rule, findings)
            elif check_method in ["file_presence", "repo_scan_static"]:
                # Documentation and file-based rules
                # Check if this is a documentation rule that needs LLM evaluation
                rule_id_lower = rule_id.lower()
                if rule_id in ["CRA-BASE-001", "CRA-BASE-007"] and repo and read_file_func:
                    result = await evaluate_documentation_rule_with_llm(rule, repo_files, repo, read_file_func)
                else:
                    # Fallback: simple file presence check
                    required_evidence = rule.get("required_evidence", [])
                    found_files = [ev.get("source") for ev in required_evidence if ev.get("source") in repo_files]
                    if found_files:
                        result = {
                            "rule_id": rule_id,
                            "status": "PASS",
                            "confidence": 0.6,
                            "reason": f"Required files found: {', '.join(found_files)}",
                            "evaluated_at": datetime.utcnow().isoformat() + "Z"
                        }
                    else:
                        result = {
                            "rule_id": rule_id,
                            "status": "FAIL",
                            "confidence": 0.7,
                            "reason": "Required files not found",
                            "evaluated_at": datetime.utcnow().isoformat() + "Z"
                        }
            else:
                # Unknown check method
                result = {
                    "rule_id": rule_id,
                    "status": "UNKNOWN",
                    "confidence": 0.2,
                    "reason": f"Check method '{check_method}' not implemented",
                    "evaluated_at": datetime.utcnow().isoformat() + "Z"
                }
            
            rule_results.append(result)
            
        except Exception as e:
            logger.error("Error evaluating rule %s: %s", rule_id, str(e)[:200])
            rule_results.append({
                "rule_id": rule_id,
                "status": "UNKNOWN",
                "confidence": 0.1,
                "reason": f"Evaluation error: {str(e)[:100]}",
                "evaluated_at": datetime.utcnow().isoformat() + "Z"
            })
    
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


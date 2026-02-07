"""SARIF 2.1.0 report generation for EURA compliance scan results.

Generates Static Analysis Results Interchange Format (SARIF) v2.1.0 JSON
from EURA scan data — rule results, security findings, and vulnerability
reports. Compatible with GitHub Code Scanning, VS Code SARIF Viewer, and
other SARIF-consuming tools.

PRD Reference: Section 3.8.1 — CRA Mandatory Artifacts (SARIF export).
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from app.core.logger import logger

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "EURA"
TOOL_VERSION = "2.0"
TOOL_URI = "https://github.com/eura-compliance/eura"

# Severity → SARIF level mapping
_SEVERITY_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Rule status → whether to include in SARIF results
_INCLUDE_STATUSES = {"FAIL", "UNKNOWN"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_to_level(severity: str) -> str:
    """Map EURA severity string to SARIF level."""
    return _SEVERITY_TO_LEVEL.get(severity.lower(), "warning")


def _rule_overall_severity(rule_def: Dict[str, Any]) -> str:
    """Extract overall severity from a rule definition dict."""
    sev = rule_def.get("severity", {})
    if isinstance(sev, dict):
        return sev.get("overall", "medium")
    return str(sev) if sev else "medium"


def _make_sarif_rule(rule_def: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an EURA rule definition to a SARIF reportingDescriptor."""
    rule_id = rule_def.get("rule_id", "UNKNOWN")
    severity = _rule_overall_severity(rule_def)
    refs = rule_def.get("references", {})

    descriptor: Dict[str, Any] = {
        "id": rule_id,
        "name": rule_id.replace("-", ""),
        "shortDescription": {"text": rule_def.get("description_short", rule_def.get("title", ""))},
        "fullDescription": {"text": rule_def.get("description_long", "")},
        "defaultConfiguration": {"level": _severity_to_level(severity)},
        "properties": {
            "tags": [
                rule_def.get("regulation", "CRA"),
                severity,
            ],
        },
    }

    # Add help URI from article reference
    article = refs.get("article", "")
    if article:
        descriptor["helpUri"] = f"https://eur-lex.europa.eu/eli/reg/2024/2847/oj#{article.replace(' ', '-').lower()}"
        descriptor["help"] = {
            "text": f"{article}: {refs.get('note', '')}".strip(": "),
            "markdown": f"**{article}** — {refs.get('note', '')}".strip("— "),
        }

    return descriptor


def _make_sarif_result(
    rule_result: Dict[str, Any],
    rule_index: int,
    rule_defs_map: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Convert an EURA rule evaluation result to a SARIF result object."""
    rule_id = rule_result.get("rule_id", "UNKNOWN")
    status = rule_result.get("status", "UNKNOWN")
    reason = rule_result.get("reason", "")
    confidence = rule_result.get("confidence", 0.5)

    # Determine SARIF level from rule definition severity
    rule_def = rule_defs_map.get(rule_id, {})
    severity = _rule_overall_severity(rule_def)
    level = _severity_to_level(severity)

    # UNKNOWN status gets downgraded to "note"
    if status == "UNKNOWN":
        level = "note"

    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": reason},
        "properties": {
            "eura:status": status,
            "eura:confidence": confidence,
        },
    }

    # Add evidence as properties if available
    evidence = rule_result.get("evidence", {})
    if evidence:
        result["properties"]["eura:evidence"] = evidence

    return result


def _make_finding_result(
    finding: Dict[str, Any],
    rule_index: int,
) -> Dict[str, Any]:
    """Convert an EURA security finding to a SARIF result object."""
    finding_id = finding.get("id", f"finding-{uuid.uuid4().hex[:8]}")
    title = finding.get("title", "Security Finding")
    severity = finding.get("severity", "medium")
    summary = finding.get("summary", "")
    details = finding.get("details", "")
    category = finding.get("category", "security")

    result: Dict[str, Any] = {
        "ruleId": f"EURA-FINDING-{category.upper()}",
        "ruleIndex": rule_index,
        "level": _severity_to_level(severity),
        "message": {"text": f"{title}: {summary}" if summary else title},
        "properties": {
            "eura:finding_id": finding_id,
            "eura:category": category,
            "eura:severity": severity,
        },
    }

    # Add locations from evidence
    locations = []
    for ev in finding.get("evidence", []):
        loc: Dict[str, Any] = {}
        file_path = ev.get("file", "")
        if file_path:
            artifact_loc: Dict[str, Any] = {"uri": file_path}
            region: Dict[str, Any] = {}

            lines = ev.get("lines", "")
            if lines and "-" in str(lines):
                parts = str(lines).split("-")
                try:
                    region["startLine"] = int(parts[0])
                    region["endLine"] = int(parts[1])
                except (ValueError, IndexError):
                    pass
            elif lines:
                try:
                    region["startLine"] = int(lines)
                except (ValueError, TypeError):
                    pass

            snippet = ev.get("snippet", "")
            if snippet:
                region["snippet"] = {"text": snippet}

            loc["physicalLocation"] = {"artifactLocation": artifact_loc}
            if region:
                loc["physicalLocation"]["region"] = region

        if loc:
            locations.append(loc)

    if locations:
        result["locations"] = locations

    if details:
        result["properties"]["eura:details"] = details

    return result


def _make_vuln_result(
    vuln: Dict[str, Any],
    rule_index: int,
) -> Dict[str, Any]:
    """Convert an OSV vulnerability entry to a SARIF result object."""
    vuln_id = vuln.get("vuln_id", vuln.get("id", "UNKNOWN"))
    severity = vuln.get("severity", "UNKNOWN").lower()
    package = vuln.get("affected_package", "unknown")
    version = vuln.get("affected_version", "")
    fixed = vuln.get("fixed_version", "")
    summary = vuln.get("summary", "")

    level = _severity_to_level(severity) if severity != "unknown" else "warning"

    message_parts = [f"Vulnerability {vuln_id} in {package}"]
    if version:
        message_parts[0] += f"@{version}"
    if summary:
        message_parts.append(summary)
    if fixed:
        message_parts.append(f"Fix: upgrade to {fixed}")

    result: Dict[str, Any] = {
        "ruleId": "EURA-VULN-OSV",
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": ". ".join(message_parts)},
        "properties": {
            "eura:vuln_id": vuln_id,
            "eura:package": package,
            "eura:version": version,
            "eura:severity": severity,
        },
    }

    if fixed:
        result["properties"]["eura:fixed_version"] = fixed

    # Add references as related locations or properties
    refs = vuln.get("references", [])
    if refs:
        result["properties"]["eura:references"] = refs[:5]

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_sarif(
    rule_results: List[Dict[str, Any]],
    *,
    rule_definitions: Optional[List[Dict[str, Any]]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    vulnerability_report: Optional[Dict[str, Any]] = None,
    repo_name: Optional[str] = None,
    commit_sha: Optional[str] = None,
    scan_id: Optional[str] = None,
    tool_name: str = TOOL_NAME,
    tool_version: str = TOOL_VERSION,
) -> Dict[str, Any]:
    """Generate a SARIF 2.1.0 JSON document from EURA scan results.

    Args:
        rule_results: List of rule evaluation result dicts, each containing
            at minimum ``rule_id``, ``status``, ``reason``, ``confidence``.
        rule_definitions: Optional list of full rule definition dicts from
            rules_db.json.  Used to populate SARIF rule descriptors and
            severity levels.  When omitted, rules_db.json is loaded
            automatically.
        findings: Optional list of security finding dicts (secret detection,
            code analysis).
        vulnerability_report: Optional OSV vulnerability report dict with a
            ``vulnerabilities`` list.
        repo_name: Repository identifier (e.g. "owner/repo").
        commit_sha: Git commit hash.
        scan_id: EURA scan UUID.
        tool_name: Name used in the SARIF ``tool.driver`` block.
        tool_version: Version used in the SARIF ``tool.driver`` block.

    Returns:
        SARIF 2.1.0 document as a Python dict (JSON-serializable).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ------------------------------------------------------------------
    # Load rule definitions if not provided
    # ------------------------------------------------------------------
    if rule_definitions is None:
        try:
            from app.services.compliance import load_rules_db
            db = load_rules_db()
            rule_definitions = db.get("rules", [])
        except Exception:
            rule_definitions = []

    rule_defs_map: Dict[str, Dict[str, Any]] = {
        r["rule_id"]: r for r in rule_definitions
    }

    # ------------------------------------------------------------------
    # Build SARIF rule descriptors (tool.driver.rules)
    # ------------------------------------------------------------------
    sarif_rules: List[Dict[str, Any]] = []
    rule_index_map: Dict[str, int] = {}

    # Add descriptors for every rule that has results
    for rr in rule_results:
        rid = rr.get("rule_id", "")
        if rid and rid not in rule_index_map:
            rule_index_map[rid] = len(sarif_rules)
            rule_def = rule_defs_map.get(rid, {"rule_id": rid, "title": rid})
            sarif_rules.append(_make_sarif_rule(rule_def))

    # Add synthetic rules for findings & vulns
    finding_categories_seen: set = set()
    if findings:
        for f in findings:
            cat = f.get("category", "security")
            synth_id = f"EURA-FINDING-{cat.upper()}"
            if synth_id not in rule_index_map:
                rule_index_map[synth_id] = len(sarif_rules)
                sarif_rules.append({
                    "id": synth_id,
                    "name": synth_id.replace("-", ""),
                    "shortDescription": {"text": f"Security finding ({cat})"},
                    "defaultConfiguration": {"level": "warning"},
                    "properties": {"tags": ["security", cat]},
                })
                finding_categories_seen.add(cat)

    vuln_rule_id = "EURA-VULN-OSV"
    if vulnerability_report and vulnerability_report.get("vulnerabilities"):
        if vuln_rule_id not in rule_index_map:
            rule_index_map[vuln_rule_id] = len(sarif_rules)
            sarif_rules.append({
                "id": vuln_rule_id,
                "name": "EURAVulnOSV",
                "shortDescription": {"text": "Known vulnerability from OSV database"},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["vulnerability", "SCA", "OSV"]},
            })

    # ------------------------------------------------------------------
    # Build SARIF results
    # ------------------------------------------------------------------
    sarif_results: List[Dict[str, Any]] = []

    # 1. Rule evaluation results (only FAIL and UNKNOWN)
    for rr in rule_results:
        status = rr.get("status", "UNKNOWN")
        if status not in _INCLUDE_STATUSES:
            continue
        rid = rr.get("rule_id", "")
        idx = rule_index_map.get(rid, 0)
        sarif_results.append(_make_sarif_result(rr, idx, rule_defs_map))

    # 2. Security findings
    if findings:
        for f in findings:
            cat = f.get("category", "security")
            synth_id = f"EURA-FINDING-{cat.upper()}"
            idx = rule_index_map.get(synth_id, 0)
            sarif_results.append(_make_finding_result(f, idx))

    # 3. Vulnerability results
    if vulnerability_report:
        vulns = vulnerability_report.get("vulnerabilities", [])
        idx = rule_index_map.get(vuln_rule_id, 0)
        for v in vulns:
            sarif_results.append(_make_vuln_result(v, idx))

    # ------------------------------------------------------------------
    # Build invocation
    # ------------------------------------------------------------------
    invocation: Dict[str, Any] = {
        "executionSuccessful": True,
        "endTimeUtc": now,
    }
    if scan_id:
        invocation["properties"] = {"eura:scan_id": scan_id}

    # ------------------------------------------------------------------
    # Build run
    # ------------------------------------------------------------------
    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": TOOL_URI,
                "rules": sarif_rules,
            },
        },
        "results": sarif_results,
        "invocations": [invocation],
    }

    # Add artifacts for repository info
    if repo_name or commit_sha:
        run["properties"] = {}
        if repo_name:
            run["properties"]["eura:repo"] = repo_name
        if commit_sha:
            run["properties"]["eura:commit"] = commit_sha

    # ------------------------------------------------------------------
    # Assemble SARIF document
    # ------------------------------------------------------------------
    sarif: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }

    result_count = len(sarif_results)
    rule_count = len(sarif_rules)
    logger.debug(
        "Generated SARIF document: %d results from %d rules",
        result_count, rule_count,
    )

    return sarif

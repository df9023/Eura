"""Tests for SARIF 2.1.0 report generation (app/services/sarif.py).

Covers:
 - SARIF document structure compliance (schema, version, runs)
 - Rule result → SARIF result mapping (FAIL/UNKNOWN only)
 - Severity → SARIF level mapping
 - Security finding → SARIF result with locations
 - Vulnerability → SARIF result mapping
 - Full integration with rule_definitions from rules_db.json
 - Edge cases (empty inputs, missing fields)
"""
import json
import pytest
from typing import Any, Dict, List

from app.services.sarif import (
    generate_sarif,
    _severity_to_level,
    _rule_overall_severity,
    _make_sarif_rule,
    _make_sarif_result,
    _make_finding_result,
    _make_vuln_result,
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    TOOL_VERSION,
)


# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------

def _sample_rule_results() -> List[Dict[str, Any]]:
    """Minimal set of rule results spanning all statuses."""
    return [
        {"rule_id": "CRA-BASE-001", "status": "PASS", "reason": "SECURITY.md found", "confidence": 0.9},
        {"rule_id": "CRA-BASE-003", "status": "FAIL", "reason": "2 critical vulns", "confidence": 0.95,
         "evidence": {"vulnerability_count": 2, "critical_count": 2}},
        {"rule_id": "CRA-SEC-001", "status": "FAIL", "reason": "No validation config", "confidence": 0.7},
        {"rule_id": "CRA-DOC-002", "status": "UNKNOWN", "reason": "Could not determine", "confidence": 0.3},
        {"rule_id": "CRA-LIFE-001", "status": "NOT_APPLICABLE", "reason": "Not applicable", "confidence": 1.0},
    ]


def _sample_findings() -> List[Dict[str, Any]]:
    return [
        {
            "id": "finding-001",
            "title": "Hardcoded API key",
            "severity": "high",
            "summary": "AWS API key in source",
            "details": "Found AKIA... pattern in config.py",
            "category": "secrets",
            "evidence": [
                {"file": "config.py", "lines": "12-14", "snippet": "aws_key = 'AKIA...'"},
            ],
        },
        {
            "id": "finding-002",
            "title": "Debug mode enabled",
            "severity": "medium",
            "summary": "DEBUG=True in production config",
            "details": "",
            "category": "config",
            "evidence": [
                {"file": "settings.py", "lines": "5", "snippet": "DEBUG = True"},
            ],
        },
    ]


def _sample_vuln_report() -> Dict[str, Any]:
    return {
        "vulnerability_count": 2,
        "vulnerable_count": 2,
        "total_dependencies": 10,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
        "vulnerabilities": [
            {
                "vuln_id": "GHSA-1234-abcd",
                "summary": "SQL injection in parser",
                "severity": "CRITICAL",
                "affected_package": "sqlparse",
                "affected_version": "0.4.2",
                "fixed_version": "0.4.4",
                "references": ["https://github.com/advisories/GHSA-1234-abcd"],
            },
            {
                "vuln_id": "CVE-2024-9999",
                "summary": "XSS in template engine",
                "severity": "HIGH",
                "affected_package": "jinja2",
                "affected_version": "3.1.0",
                "fixed_version": "3.1.3",
                "references": [],
            },
        ],
    }


# ===========================================================================
# 1. Helpers
# ===========================================================================

class TestSeverityToLevel:
    def test_critical(self):
        assert _severity_to_level("critical") == "error"

    def test_high(self):
        assert _severity_to_level("high") == "error"

    def test_medium(self):
        assert _severity_to_level("medium") == "warning"

    def test_low(self):
        assert _severity_to_level("low") == "note"

    def test_info(self):
        assert _severity_to_level("info") == "note"

    def test_unknown_defaults_to_warning(self):
        assert _severity_to_level("banana") == "warning"

    def test_case_insensitive(self):
        assert _severity_to_level("HIGH") == "error"
        assert _severity_to_level("Critical") == "error"


class TestRuleOverallSeverity:
    def test_dict_severity(self):
        assert _rule_overall_severity({"severity": {"overall": "critical"}}) == "critical"

    def test_missing_overall(self):
        assert _rule_overall_severity({"severity": {"impact": "high"}}) == "medium"

    def test_string_severity(self):
        assert _rule_overall_severity({"severity": "high"}) == "high"

    def test_empty(self):
        assert _rule_overall_severity({}) == "medium"


# ===========================================================================
# 2. SARIF Rule Descriptor
# ===========================================================================

class TestMakeSarifRule:
    def test_basic_fields(self):
        rule_def = {
            "rule_id": "CRA-BASE-001",
            "title": "Security Policy Documentation",
            "description_short": "Repo must have SECURITY.md",
            "description_long": "Full description here",
            "regulation": "CRA",
            "severity": {"impact": "medium", "likelihood": "medium", "overall": "medium"},
            "references": {"article": "Article 10(1)", "note": "Security requirements"},
        }
        descriptor = _make_sarif_rule(rule_def)

        assert descriptor["id"] == "CRA-BASE-001"
        assert descriptor["name"] == "CRABASE001"
        assert descriptor["shortDescription"]["text"] == "Repo must have SECURITY.md"
        assert descriptor["fullDescription"]["text"] == "Full description here"
        assert descriptor["defaultConfiguration"]["level"] == "warning"
        assert "CRA" in descriptor["properties"]["tags"]

    def test_help_uri_from_article(self):
        rule_def = {
            "rule_id": "CRA-SEC-001",
            "description_short": "test",
            "description_long": "",
            "severity": {"overall": "high"},
            "references": {"article": "Article 10(1)", "note": "Security by design"},
        }
        descriptor = _make_sarif_rule(rule_def)
        assert "helpUri" in descriptor
        assert "article-10(1)" in descriptor["helpUri"]

    def test_no_references(self):
        rule_def = {
            "rule_id": "TEST-001",
            "description_short": "test",
            "description_long": "",
            "severity": {"overall": "low"},
            "references": {},
        }
        descriptor = _make_sarif_rule(rule_def)
        assert "helpUri" not in descriptor


# ===========================================================================
# 3. Rule Result → SARIF Result
# ===========================================================================

class TestMakeSarifResult:
    def test_fail_result(self):
        rr = {"rule_id": "CRA-BASE-003", "status": "FAIL", "reason": "Vulns found", "confidence": 0.95}
        rule_defs = {"CRA-BASE-003": {"rule_id": "CRA-BASE-003", "severity": {"overall": "high"}}}
        result = _make_sarif_result(rr, 0, rule_defs)

        assert result["ruleId"] == "CRA-BASE-003"
        assert result["ruleIndex"] == 0
        assert result["level"] == "error"
        assert "Vulns found" in result["message"]["text"]
        assert result["properties"]["eura:status"] == "FAIL"

    def test_unknown_downgrades_to_note(self):
        rr = {"rule_id": "CRA-DOC-002", "status": "UNKNOWN", "reason": "Cannot determine", "confidence": 0.3}
        rule_defs = {"CRA-DOC-002": {"rule_id": "CRA-DOC-002", "severity": {"overall": "medium"}}}
        result = _make_sarif_result(rr, 1, rule_defs)
        assert result["level"] == "note"

    def test_evidence_included(self):
        rr = {
            "rule_id": "CRA-BASE-008",
            "status": "FAIL",
            "reason": "Secrets found",
            "confidence": 0.9,
            "evidence": {"secret_count": 3},
        }
        result = _make_sarif_result(rr, 0, {})
        assert result["properties"]["eura:evidence"] == {"secret_count": 3}


# ===========================================================================
# 4. Finding → SARIF Result
# ===========================================================================

class TestMakeFindingResult:
    def test_basic_finding(self):
        finding = {
            "id": "f-001",
            "title": "API Key Leak",
            "severity": "high",
            "summary": "AWS key in code",
            "details": "Full details...",
            "category": "secrets",
            "evidence": [{"file": "config.py", "lines": "10-12", "snippet": "key='AKIA...'"}],
        }
        result = _make_finding_result(finding, 5)

        assert result["ruleId"] == "EURA-FINDING-SECRETS"
        assert result["ruleIndex"] == 5
        assert result["level"] == "error"
        assert "API Key Leak" in result["message"]["text"]
        assert len(result["locations"]) == 1

        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "config.py"
        assert loc["region"]["startLine"] == 10
        assert loc["region"]["endLine"] == 12
        assert "AKIA" in loc["region"]["snippet"]["text"]

    def test_finding_single_line(self):
        finding = {
            "id": "f-002",
            "title": "Debug flag",
            "severity": "medium",
            "category": "config",
            "evidence": [{"file": "app.py", "lines": "5"}],
        }
        result = _make_finding_result(finding, 0)
        loc = result["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 5

    def test_finding_no_evidence(self):
        finding = {"id": "f-003", "title": "Generic issue", "severity": "low", "category": "security"}
        result = _make_finding_result(finding, 0)
        assert "locations" not in result


# ===========================================================================
# 5. Vulnerability → SARIF Result
# ===========================================================================

class TestMakeVulnResult:
    def test_critical_vuln(self):
        vuln = {
            "vuln_id": "GHSA-1234",
            "summary": "SQL injection",
            "severity": "CRITICAL",
            "affected_package": "sqlparse",
            "affected_version": "0.4.2",
            "fixed_version": "0.4.4",
            "references": ["https://example.com/advisory"],
        }
        result = _make_vuln_result(vuln, 3)

        assert result["ruleId"] == "EURA-VULN-OSV"
        assert result["ruleIndex"] == 3
        assert result["level"] == "error"
        assert "GHSA-1234" in result["message"]["text"]
        assert "sqlparse@0.4.2" in result["message"]["text"]
        assert "upgrade to 0.4.4" in result["message"]["text"]
        assert result["properties"]["eura:fixed_version"] == "0.4.4"

    def test_vuln_unknown_severity(self):
        vuln = {"vuln_id": "CVE-9999", "severity": "UNKNOWN", "affected_package": "foo"}
        result = _make_vuln_result(vuln, 0)
        assert result["level"] == "warning"

    def test_vuln_no_fix(self):
        vuln = {
            "vuln_id": "CVE-1111",
            "severity": "HIGH",
            "affected_package": "bar",
            "affected_version": "1.0",
            "fixed_version": "",
        }
        result = _make_vuln_result(vuln, 0)
        assert "eura:fixed_version" not in result["properties"]


# ===========================================================================
# 6. Full SARIF Document Generation
# ===========================================================================

class TestGenerateSarif:
    """Tests for the top-level generate_sarif function."""

    def test_minimal_sarif(self):
        """Generates valid SARIF with just rule results."""
        sarif = generate_sarif(rule_results=_sample_rule_results())

        assert sarif["$schema"] == SARIF_SCHEMA
        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == TOOL_NAME
        assert run["tool"]["driver"]["version"] == TOOL_VERSION
        assert "rules" in run["tool"]["driver"]
        assert "results" in run
        assert "invocations" in run

    def test_only_fail_and_unknown_included(self):
        """PASS and NOT_APPLICABLE results should be excluded."""
        sarif = generate_sarif(rule_results=_sample_rule_results())
        results = sarif["runs"][0]["results"]

        rule_ids = [r["ruleId"] for r in results]
        # FAIL results
        assert "CRA-BASE-003" in rule_ids
        assert "CRA-SEC-001" in rule_ids
        # UNKNOWN result
        assert "CRA-DOC-002" in rule_ids
        # PASS and NOT_APPLICABLE should NOT be present
        assert "CRA-BASE-001" not in rule_ids
        assert "CRA-LIFE-001" not in rule_ids

    def test_result_count(self):
        """3 results: 2 FAIL + 1 UNKNOWN."""
        sarif = generate_sarif(rule_results=_sample_rule_results())
        assert len(sarif["runs"][0]["results"]) == 3

    def test_with_findings(self):
        """Findings create additional SARIF results and rule descriptors."""
        sarif = generate_sarif(
            rule_results=[{"rule_id": "CRA-BASE-001", "status": "PASS", "reason": "ok", "confidence": 0.9}],
            findings=_sample_findings(),
        )
        run = sarif["runs"][0]
        results = run["results"]

        # 0 rule results (only PASS) + 2 findings
        assert len(results) == 2

        # Finding rules should be in driver.rules
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        assert "EURA-FINDING-SECRETS" in rule_ids
        assert "EURA-FINDING-CONFIG" in rule_ids

    def test_with_vulnerabilities(self):
        """Vulnerability report creates SARIF results."""
        sarif = generate_sarif(
            rule_results=[{"rule_id": "CRA-BASE-003", "status": "FAIL", "reason": "vulns", "confidence": 0.9}],
            vulnerability_report=_sample_vuln_report(),
        )
        run = sarif["runs"][0]
        results = run["results"]

        # 1 rule FAIL + 2 vuln results
        assert len(results) == 3

        vuln_results = [r for r in results if r["ruleId"] == "EURA-VULN-OSV"]
        assert len(vuln_results) == 2
        assert "GHSA-1234-abcd" in vuln_results[0]["message"]["text"]

    def test_combined_all_sources(self):
        """Full SARIF with rule results + findings + vulnerabilities."""
        sarif = generate_sarif(
            rule_results=_sample_rule_results(),
            findings=_sample_findings(),
            vulnerability_report=_sample_vuln_report(),
            repo_name="owner/repo",
            commit_sha="abc123",
            scan_id="scan-uuid-001",
        )
        run = sarif["runs"][0]

        # 3 rule FAILs/UNKNOWNs + 2 findings + 2 vulns = 7
        assert len(run["results"]) == 7

        # Metadata
        assert run["properties"]["eura:repo"] == "owner/repo"
        assert run["properties"]["eura:commit"] == "abc123"
        assert run["invocations"][0]["properties"]["eura:scan_id"] == "scan-uuid-001"

    def test_empty_rule_results(self):
        """Empty inputs should produce valid SARIF with zero results."""
        sarif = generate_sarif(rule_results=[])
        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"][0]["results"]) == 0
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0

    def test_sarif_json_serializable(self):
        """SARIF output must be JSON-serializable."""
        sarif = generate_sarif(
            rule_results=_sample_rule_results(),
            findings=_sample_findings(),
            vulnerability_report=_sample_vuln_report(),
        )
        output = json.dumps(sarif, indent=2)
        assert len(output) > 100
        reparsed = json.loads(output)
        assert reparsed["version"] == SARIF_VERSION

    def test_rule_descriptors_from_db(self):
        """When rule_definitions is None, rules_db.json is loaded automatically."""
        sarif = generate_sarif(
            rule_results=[
                {"rule_id": "CRA-SEC-001", "status": "FAIL", "reason": "Missing", "confidence": 0.7},
            ],
        )
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        # Should have real description from rules_db.json
        sec001 = rules[0]
        assert sec001["id"] == "CRA-SEC-001"
        assert "validate and sanitize" in sec001["shortDescription"]["text"]

    def test_explicit_rule_definitions(self):
        """Providing rule_definitions overrides auto-load."""
        custom_defs = [
            {
                "rule_id": "CUSTOM-001",
                "title": "Custom Rule",
                "description_short": "A custom rule",
                "description_long": "Detailed custom rule",
                "regulation": "CRA",
                "severity": {"overall": "critical"},
                "references": {},
            }
        ]
        sarif = generate_sarif(
            rule_results=[{"rule_id": "CUSTOM-001", "status": "FAIL", "reason": "failed", "confidence": 0.8}],
            rule_definitions=custom_defs,
        )
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["id"] == "CUSTOM-001"
        assert rules[0]["defaultConfiguration"]["level"] == "error"

    def test_invocation_success(self):
        sarif = generate_sarif(rule_results=[])
        inv = sarif["runs"][0]["invocations"][0]
        assert inv["executionSuccessful"] is True
        assert "endTimeUtc" in inv

    def test_no_repo_metadata(self):
        """Without repo_name/commit_sha, no properties on run."""
        sarif = generate_sarif(rule_results=[])
        run = sarif["runs"][0]
        assert "properties" not in run


# ===========================================================================
# 7. SARIF Structure Validation
# ===========================================================================

class TestSarifStructure:
    """Validate SARIF structure requirements."""

    def test_has_schema(self):
        sarif = generate_sarif(rule_results=_sample_rule_results())
        assert "$schema" in sarif

    def test_version_is_2_1_0(self):
        sarif = generate_sarif(rule_results=[])
        assert sarif["version"] == "2.1.0"

    def test_runs_is_array(self):
        sarif = generate_sarif(rule_results=[])
        assert isinstance(sarif["runs"], list)

    def test_single_run(self):
        sarif = generate_sarif(rule_results=_sample_rule_results())
        assert len(sarif["runs"]) == 1

    def test_tool_driver_has_required_fields(self):
        sarif = generate_sarif(rule_results=_sample_rule_results())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert "name" in driver
        assert "version" in driver
        assert "rules" in driver

    def test_each_result_has_rule_id_and_level(self):
        sarif = generate_sarif(
            rule_results=_sample_rule_results(),
            findings=_sample_findings(),
            vulnerability_report=_sample_vuln_report(),
        )
        for result in sarif["runs"][0]["results"]:
            assert "ruleId" in result
            assert "level" in result
            assert result["level"] in ("error", "warning", "note", "none")
            assert "message" in result
            assert "text" in result["message"]

    def test_rule_index_references_valid(self):
        """Every result.ruleIndex should point to a valid rule in driver.rules."""
        sarif = generate_sarif(
            rule_results=_sample_rule_results(),
            findings=_sample_findings(),
            vulnerability_report=_sample_vuln_report(),
        )
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for result in sarif["runs"][0]["results"]:
            idx = result["ruleIndex"]
            assert 0 <= idx < len(rules), f"ruleIndex {idx} out of range for {result['ruleId']}"

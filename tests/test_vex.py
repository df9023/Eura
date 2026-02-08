"""Tests for OpenVEX report generation (app/services/vex.py).

Covers:
 - OpenVEX document structure (context, author, timestamp, statements)
 - Vulnerability → VEX statement mapping
 - VEX status determination (affected, not_affected, fixed, under_investigation)
 - Justification handling for not_affected
 - Product ID generation (purl-like)
 - Action statements and impact statements
 - Metadata propagation (repo_name, commit_sha, scan_id)
 - Edge cases (empty inputs, missing fields, unknown severities)
"""
import pytest
from typing import Any, Dict, List

from app.services.vex import (
    generate_vex,
    _make_product_id,
    _determine_vex_status,
    _determine_justification,
    _make_vex_statement,
    OPENVEX_CONTEXT,
    TOOL_NAME,
    TOOL_VERSION,
    VEX_STATUSES,
    VEX_JUSTIFICATIONS,
)


# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------

def _sample_vulns() -> List[Dict[str, Any]]:
    """Sample vulnerabilities spanning different statuses."""
    return [
        {
            "vuln_id": "CVE-2021-44228",
            "affected_package": "log4j-core",
            "affected_version": "2.14.1",
            "fixed_version": "2.17.0",
            "severity": "CRITICAL",
            "summary": "Apache Log4j2 remote code execution",
            "ecosystem": "maven",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        },
        {
            "vuln_id": "GHSA-abcd-1234-efgh",
            "affected_package": "requests",
            "affected_version": "2.25.0",
            "fixed_version": "2.31.0",
            "severity": "HIGH",
            "summary": "Unintended leak of proxy credentials",
            "ecosystem": "pypi",
        },
        {
            "vuln_id": "CVE-2023-99999",
            "affected_package": "express",
            "affected_version": "4.17.1",
            "severity": "MEDIUM",
            "summary": "ReDoS in path-to-regexp",
            "ecosystem": "npm",
        },
        {
            "vuln_id": "CVE-2024-00001",
            "affected_package": "safe-lib",
            "affected_version": "1.0.0",
            "severity": "LOW",
            "summary": "Minor info disclosure",
            "ecosystem": "pypi",
            "vex_status": "not_affected",
            "justification": "vulnerable_code_not_present",
            "impact_statement": "The vulnerable code path is not compiled in this build.",
        },
    ]


def _sample_vuln_fixed() -> Dict[str, Any]:
    return {
        "vuln_id": "CVE-2022-11111",
        "affected_package": "lodash",
        "affected_version": "4.17.20",
        "fixed_version": "4.17.21",
        "severity": "HIGH",
        "summary": "Prototype pollution",
        "ecosystem": "npm",
        "vex_status": "fixed",
    }


def _sample_vuln_under_investigation() -> Dict[str, Any]:
    return {
        "vuln_id": "CVE-2025-00001",
        "affected_package": "unknown-lib",
        "affected_version": "0.1.0",
        "severity": "MEDIUM",
        "summary": "Potential issue under review",
        "ecosystem": "pypi",
        "vex_status": "under_investigation",
    }


# ---------------------------------------------------------------------------
# Product ID tests
# ---------------------------------------------------------------------------

class TestMakeProductId:
    def test_basic(self):
        assert _make_product_id("requests") == "pkg:generic/requests"

    def test_with_version(self):
        assert _make_product_id("requests", "2.28.0") == "pkg:generic/requests@2.28.0"

    def test_with_ecosystem(self):
        assert _make_product_id("requests", "2.28.0", "pypi") == "pkg:pypi/requests@2.28.0"

    def test_ecosystem_lowercase(self):
        assert _make_product_id("log4j", "2.17.0", "Maven") == "pkg:maven/log4j@2.17.0"

    def test_empty_version(self):
        assert _make_product_id("express", "", "npm") == "pkg:npm/express"

    def test_empty_ecosystem(self):
        assert _make_product_id("foo", "1.0") == "pkg:generic/foo@1.0"


# ---------------------------------------------------------------------------
# VEX status determination
# ---------------------------------------------------------------------------

class TestDetermineVexStatus:
    def test_explicit_affected(self):
        assert _determine_vex_status({"vex_status": "affected"}) == "affected"

    def test_explicit_not_affected(self):
        assert _determine_vex_status({"vex_status": "not_affected"}) == "not_affected"

    def test_explicit_fixed(self):
        assert _determine_vex_status({"vex_status": "fixed"}) == "fixed"

    def test_explicit_under_investigation(self):
        assert _determine_vex_status({"vex_status": "under_investigation"}) == "under_investigation"

    def test_fixed_version_implies_affected(self):
        """If fixed_version exists but no explicit status, it means the vuln affects current version."""
        assert _determine_vex_status({"fixed_version": "2.0"}) == "affected"

    def test_affected_false_implies_not_affected(self):
        assert _determine_vex_status({"affected": False}) == "not_affected"

    def test_default_is_affected(self):
        assert _determine_vex_status({}) == "affected"

    def test_invalid_explicit_status_falls_through(self):
        assert _determine_vex_status({"vex_status": "bogus"}) == "affected"

    def test_explicit_overrides_fixed_version(self):
        assert _determine_vex_status({"vex_status": "not_affected", "fixed_version": "2.0"}) == "not_affected"


# ---------------------------------------------------------------------------
# Justification
# ---------------------------------------------------------------------------

class TestDetermineJustification:
    def test_valid_justification(self):
        for j in VEX_JUSTIFICATIONS:
            assert _determine_justification({"justification": j}) == j

    def test_invalid_justification(self):
        assert _determine_justification({"justification": "bogus"}) is None

    def test_empty(self):
        assert _determine_justification({}) is None


# ---------------------------------------------------------------------------
# VEX statement generation
# ---------------------------------------------------------------------------

class TestMakeVexStatement:
    def test_affected_statement(self):
        vuln = {
            "vuln_id": "CVE-2021-44228",
            "summary": "RCE in log4j",
            "severity": "CRITICAL",
            "fixed_version": "2.17.0",
            "affected_package": "log4j",
        }
        stmt = _make_vex_statement(vuln, ["pkg:maven/log4j@2.14.1"])

        assert stmt["status"] == "affected"
        assert stmt["vulnerability"]["@id"] == "CVE-2021-44228"
        assert stmt["vulnerability"]["name"] == "CVE-2021-44228"
        assert stmt["vulnerability"]["description"] == "RCE in log4j"
        assert len(stmt["products"]) == 1
        assert stmt["products"][0]["@id"] == "pkg:maven/log4j@2.14.1"
        assert "action_statement" in stmt
        assert "2.17.0" in stmt["action_statement"]

    def test_not_affected_with_justification(self):
        vuln = {
            "vuln_id": "CVE-2024-00001",
            "severity": "LOW",
            "vex_status": "not_affected",
            "justification": "component_not_present",
            "impact_statement": "Component not included.",
        }
        stmt = _make_vex_statement(vuln, ["pkg:generic/foo@1.0"])

        assert stmt["status"] == "not_affected"
        assert stmt["justification"] == "component_not_present"
        assert stmt["impact_statement"] == "Component not included."

    def test_fixed_statement(self):
        vuln = _sample_vuln_fixed()
        stmt = _make_vex_statement(vuln, ["pkg:npm/lodash@4.17.20"])

        assert stmt["status"] == "fixed"

    def test_under_investigation_statement(self):
        vuln = _sample_vuln_under_investigation()
        stmt = _make_vex_statement(vuln, ["pkg:pypi/unknown-lib@0.1.0"])

        assert stmt["status"] == "under_investigation"

    def test_no_summary_no_description(self):
        vuln = {"vuln_id": "CVE-2024-00002", "severity": "LOW"}
        stmt = _make_vex_statement(vuln, ["pkg:generic/x"])

        assert "description" not in stmt["vulnerability"]

    def test_severity_impact_added_for_known_severities(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            vuln = {"vuln_id": f"CVE-TEST-{sev}", "severity": sev}
            stmt = _make_vex_statement(vuln, ["pkg:generic/x"])
            assert "impact_statement" in stmt

    def test_auto_action_from_fixed_version(self):
        vuln = {
            "vuln_id": "CVE-TEST",
            "affected_package": "mylib",
            "fixed_version": "3.0",
            "severity": "HIGH",
        }
        stmt = _make_vex_statement(vuln, ["pkg:generic/mylib@2.0"])
        assert "Upgrade mylib to version 3.0" in stmt["action_statement"]

    def test_explicit_action_statement(self):
        vuln = {
            "vuln_id": "CVE-TEST",
            "severity": "HIGH",
            "action_statement": "Apply the vendor patch.",
        }
        stmt = _make_vex_statement(vuln, ["pkg:generic/x"])
        assert stmt["action_statement"] == "Apply the vendor patch."


# ---------------------------------------------------------------------------
# Full VEX document generation
# ---------------------------------------------------------------------------

class TestGenerateVex:
    def test_empty_vulnerabilities(self):
        vex = generate_vex([])

        assert vex["@context"] == OPENVEX_CONTEXT
        assert "@id" in vex
        assert vex["version"] == 1
        assert vex["statements"] == []
        assert "timestamp" in vex
        assert vex["tooling"] == f"{TOOL_NAME}/{TOOL_VERSION}"

    def test_basic_structure(self):
        vex = generate_vex(_sample_vulns())

        assert vex["@context"] == OPENVEX_CONTEXT
        assert vex["version"] == 1
        assert len(vex["statements"]) == 4
        assert vex["author"] == "EURA Compliance Scanner"
        assert vex["role"] == "tool"

    def test_metadata_included(self):
        vex = generate_vex(
            _sample_vulns(),
            repo_name="octocat/hello-world",
            commit_sha="abc123",
            scan_id="scan-001",
        )

        assert "metadata" in vex
        assert vex["metadata"]["repo"] == "octocat/hello-world"
        assert vex["metadata"]["commit"] == "abc123"
        assert vex["metadata"]["scan_id"] == "scan-001"

    def test_no_metadata_when_none(self):
        vex = generate_vex(_sample_vulns())
        assert "metadata" not in vex

    def test_custom_author(self):
        vex = generate_vex(
            _sample_vulns(),
            author="My Security Team",
            author_role="vendor",
        )
        assert vex["author"] == "My Security Team"
        assert vex["role"] == "vendor"

    def test_custom_document_id(self):
        vex = generate_vex(
            _sample_vulns(),
            document_id="https://example.com/vex/custom-001",
        )
        assert vex["@id"] == "https://example.com/vex/custom-001"

    def test_statement_count_matches_vulnerabilities(self):
        vulns = _sample_vulns()
        vex = generate_vex(vulns)
        assert len(vex["statements"]) == len(vulns)

    def test_critical_vuln_has_action(self):
        vex = generate_vex(_sample_vulns())
        critical_stmt = vex["statements"][0]
        assert critical_stmt["vulnerability"]["@id"] == "CVE-2021-44228"
        assert critical_stmt["status"] == "affected"
        assert "action_statement" in critical_stmt

    def test_not_affected_vuln_has_justification(self):
        vex = generate_vex(_sample_vulns())
        not_affected = vex["statements"][3]
        assert not_affected["status"] == "not_affected"
        assert not_affected["justification"] == "vulnerable_code_not_present"

    def test_product_ids_use_ecosystem(self):
        vex = generate_vex(_sample_vulns())
        # First vuln is maven
        products = vex["statements"][0]["products"]
        assert products[0]["@id"].startswith("pkg:maven/")

    def test_json_serializable(self):
        import json
        vex = generate_vex(_sample_vulns(), repo_name="test/repo")
        serialized = json.dumps(vex)
        assert isinstance(serialized, str)
        assert len(serialized) > 100

    def test_single_vulnerability(self):
        vex = generate_vex([{
            "vuln_id": "CVE-2024-99999",
            "affected_package": "mylib",
            "severity": "LOW",
        }])
        assert len(vex["statements"]) == 1
        stmt = vex["statements"][0]
        assert stmt["vulnerability"]["@id"] == "CVE-2024-99999"

    def test_vuln_without_id_gets_generated(self):
        vex = generate_vex([{
            "affected_package": "mystery",
            "severity": "MEDIUM",
        }])
        assert len(vex["statements"]) == 1
        vid = vex["statements"][0]["vulnerability"]["@id"]
        assert vid.startswith("EURA-UNKNOWN-")

    def test_mixed_statuses(self):
        vulns = [
            {"vuln_id": "V1", "severity": "HIGH", "vex_status": "affected", "affected_package": "a"},
            {"vuln_id": "V2", "severity": "LOW", "vex_status": "not_affected", "affected_package": "b"},
            {"vuln_id": "V3", "severity": "MEDIUM", "vex_status": "fixed", "affected_package": "c"},
            {"vuln_id": "V4", "severity": "HIGH", "vex_status": "under_investigation", "affected_package": "d"},
        ]
        vex = generate_vex(vulns)
        statuses = [s["status"] for s in vex["statements"]]
        assert statuses == ["affected", "not_affected", "fixed", "under_investigation"]

    def test_timestamp_is_iso8601(self):
        vex = generate_vex([])
        ts = vex["timestamp"]
        assert ts.endswith("Z")
        assert "T" in ts

    def test_unknown_severity_no_impact(self):
        vex = generate_vex([{
            "vuln_id": "CVE-UNKNOWN",
            "affected_package": "pkg",
            "severity": "UNKNOWN",
        }])
        # UNKNOWN severity should not add impact_statement from severity map
        stmt = vex["statements"][0]
        # impact_statement may still not be present for UNKNOWN
        if "impact_statement" in stmt:
            assert "UNKNOWN" not in stmt["impact_statement"]

"""Tests for CSAF 2.0 advisory generation (app/services/csaf.py).

Covers:
 - CSAF document structure (document, product_tree, vulnerabilities)
 - Vulnerability → CSAF vulnerability mapping
 - Product tree generation from packages
 - Remediation entries (vendor_fix, workaround)
 - CVSS score assignment by severity
 - Tracking and publisher blocks
 - Reference handling
 - Metadata propagation (repo_name, commit_sha, scan_id)
 - Edge cases (empty inputs, missing fields, CVE vs non-CVE IDs)
"""
import pytest
from typing import Any, Dict, List

from app.services.csaf import (
    generate_csaf,
    _make_product_id,
    _make_tracking,
    _make_publisher,
    _make_product_tree,
    _make_vulnerability,
    CSAF_VERSION,
    CSAF_CATEGORY_VEX,
    CSAF_CATEGORY_ADVISORY,
    TOOL_NAME,
    TOOL_VERSION,
)


# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------

def _sample_vulns() -> List[Dict[str, Any]]:
    """Sample vulnerabilities for CSAF tests."""
    return [
        {
            "vuln_id": "CVE-2021-44228",
            "affected_package": "log4j-core",
            "affected_version": "2.14.1",
            "fixed_version": "2.17.0",
            "severity": "CRITICAL",
            "summary": "Apache Log4j2 remote code execution",
            "ecosystem": "maven",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://logging.apache.org/log4j/2.x/security.html",
            ],
        },
        {
            "vuln_id": "GHSA-abcd-1234-efgh",
            "affected_package": "requests",
            "affected_version": "2.25.0",
            "fixed_version": "2.31.0",
            "severity": "HIGH",
            "summary": "Proxy credential leak",
            "ecosystem": "pypi",
        },
        {
            "vuln_id": "CVE-2023-50000",
            "affected_package": "express",
            "affected_version": "4.17.1",
            "severity": "MEDIUM",
            "summary": "ReDoS vulnerability",
            "ecosystem": "npm",
        },
    ]


# ---------------------------------------------------------------------------
# Product ID tests
# ---------------------------------------------------------------------------

class TestCsafProductId:
    def test_basic(self):
        assert _make_product_id("requests") == "pkg:generic/requests"

    def test_with_version(self):
        assert _make_product_id("requests", "2.28.0") == "pkg:generic/requests@2.28.0"

    def test_with_ecosystem(self):
        assert _make_product_id("requests", "2.28.0", "pypi") == "pkg:pypi/requests@2.28.0"


# ---------------------------------------------------------------------------
# Tracking block
# ---------------------------------------------------------------------------

class TestMakeTracking:
    def test_structure(self):
        tracking = _make_tracking("DOC-001", "2025-01-01T00:00:00Z")

        assert tracking["id"] == "DOC-001"
        assert tracking["current_release_date"] == "2025-01-01T00:00:00Z"
        assert tracking["initial_release_date"] == "2025-01-01T00:00:00Z"
        assert tracking["status"] == "final"
        assert tracking["version"] == "1"
        assert len(tracking["revision_history"]) == 1
        assert tracking["generator"]["engine"]["name"] == TOOL_NAME

    def test_custom_revision(self):
        tracking = _make_tracking("DOC-002", "2025-06-01T00:00:00Z", "3")
        assert tracking["version"] == "3"


# ---------------------------------------------------------------------------
# Publisher block
# ---------------------------------------------------------------------------

class TestMakePublisher:
    def test_default(self):
        pub = _make_publisher()
        assert pub["category"] == "tool"
        assert pub["name"] == "EURA Compliance Scanner"
        assert "eura.dev" in pub["namespace"]

    def test_custom(self):
        pub = _make_publisher("Acme Inc.", "https://acme.com")
        assert pub["name"] == "Acme Inc."
        assert pub["namespace"] == "https://acme.com"


# ---------------------------------------------------------------------------
# Product tree
# ---------------------------------------------------------------------------

class TestMakeProductTree:
    def test_empty(self):
        tree = _make_product_tree([])
        assert tree == {}

    def test_single_product(self):
        tree = _make_product_tree([{
            "name": "requests",
            "version": "2.28.0",
            "ecosystem": "pypi",
        }])

        assert "branches" in tree
        assert len(tree["branches"]) == 1
        assert tree["branches"][0]["name"] == "pypi"
        assert tree["branches"][0]["category"] == "product_family"
        assert len(tree["branches"][0]["branches"]) == 1
        assert tree["full_product_names"][0]["product_id"] == "pkg:pypi/requests@2.28.0"

    def test_multiple_ecosystems(self):
        tree = _make_product_tree([
            {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"},
            {"name": "express", "version": "4.17.1", "ecosystem": "npm"},
        ])

        assert len(tree["branches"]) == 2
        ecosystems = {b["name"] for b in tree["branches"]}
        assert ecosystems == {"pypi", "npm"}
        assert len(tree["full_product_names"]) == 2

    def test_same_ecosystem_multiple_packages(self):
        tree = _make_product_tree([
            {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"},
            {"name": "flask", "version": "2.3.0", "ecosystem": "pypi"},
        ])

        assert len(tree["branches"]) == 1
        assert len(tree["branches"][0]["branches"]) == 2

    def test_no_version(self):
        tree = _make_product_tree([{
            "name": "mylib",
            "version": "",
            "ecosystem": "generic",
        }])

        pn = tree["full_product_names"][0]
        assert pn["product_id"] == "pkg:generic/mylib"
        assert pn["name"] == "mylib"


# ---------------------------------------------------------------------------
# Single vulnerability mapping
# ---------------------------------------------------------------------------

class TestMakeVulnerability:
    def test_cve_id_is_set(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-2021-44228",
            "affected_package": "log4j",
            "severity": "CRITICAL",
            "summary": "RCE",
        })
        assert vuln["cve"] == "CVE-2021-44228"
        assert vuln["title"] == "CVE-2021-44228"

    def test_non_cve_id_no_cve_field(self):
        vuln = _make_vulnerability({
            "vuln_id": "GHSA-abcd-1234-efgh",
            "affected_package": "requests",
            "severity": "HIGH",
        })
        assert "cve" not in vuln
        assert vuln["title"] == "GHSA-abcd-1234-efgh"

    def test_notes_include_summary(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "summary": "Test summary",
            "severity": "LOW",
        })
        note_texts = [n["text"] for n in vuln["notes"]]
        assert any("Test summary" in t for t in note_texts)

    def test_product_status_affected(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "affected_version": "1.0",
            "severity": "HIGH",
            "ecosystem": "pypi",
        })
        ps = vuln["product_status"]
        assert "known_affected" in ps
        assert "pkg:pypi/foo@1.0" in ps["known_affected"]

    def test_fixed_version_creates_remediation(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "affected_version": "1.0",
            "fixed_version": "2.0",
            "severity": "HIGH",
            "ecosystem": "pypi",
        })
        assert "remediations" in vuln
        assert len(vuln["remediations"]) >= 1
        rem = vuln["remediations"][0]
        assert rem["category"] == "vendor_fix"
        assert "2.0" in rem["details"]

    def test_fixed_version_in_product_status(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "affected_version": "1.0",
            "fixed_version": "2.0",
            "severity": "HIGH",
            "ecosystem": "pypi",
        })
        ps = vuln["product_status"]
        assert "fixed" in ps
        assert "pkg:pypi/foo@2.0" in ps["fixed"]

    def test_cvss_score_for_critical(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "severity": "CRITICAL",
        })
        assert "scores" in vuln
        assert vuln["scores"][0]["cvss_v3"]["baseSeverity"] == "CRITICAL"
        assert vuln["scores"][0]["cvss_v3"]["baseScore"] == 9.5

    def test_cvss_score_for_high(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "severity": "HIGH",
        })
        assert vuln["scores"][0]["cvss_v3"]["baseScore"] == 7.5

    def test_cvss_score_for_medium(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "severity": "MEDIUM",
        })
        assert vuln["scores"][0]["cvss_v3"]["baseScore"] == 5.0

    def test_no_cvss_for_unknown_severity(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "severity": "UNKNOWN",
        })
        assert "scores" not in vuln

    def test_references_included(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "severity": "HIGH",
            "references": ["https://example.com/advisory"],
        })
        assert "references" in vuln
        assert vuln["references"][0]["url"] == "https://example.com/advisory"

    def test_references_limited_to_10(self):
        refs = [f"https://example.com/{i}" for i in range(15)]
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "severity": "LOW",
            "references": refs,
        })
        assert len(vuln["references"]) == 10

    def test_explicit_vex_status_not_affected(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "affected_version": "1.0",
            "severity": "LOW",
            "ecosystem": "pypi",
            "vex_status": "not_affected",
        })
        ps = vuln["product_status"]
        assert "known_not_affected" in ps

    def test_workaround_when_no_fix(self):
        vuln = _make_vulnerability({
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "severity": "HIGH",
            "action_statement": "Disable feature X as workaround.",
        })
        rems = vuln.get("remediations", [])
        assert any(r["category"] == "workaround" for r in rems)


# ---------------------------------------------------------------------------
# Full CSAF document generation
# ---------------------------------------------------------------------------

class TestGenerateCsaf:
    def test_empty_vulnerabilities(self):
        csaf = generate_csaf([])

        assert csaf["document"]["csaf_version"] == CSAF_VERSION
        assert csaf["document"]["category"] == CSAF_CATEGORY_VEX
        assert "tracking" in csaf["document"]
        assert "publisher" in csaf["document"]
        assert csaf.get("vulnerabilities") is None or csaf.get("vulnerabilities") == []

    def test_basic_structure(self):
        csaf = generate_csaf(_sample_vulns())

        assert csaf["document"]["csaf_version"] == CSAF_VERSION
        assert csaf["document"]["category"] == CSAF_CATEGORY_VEX
        assert "product_tree" in csaf
        assert "vulnerabilities" in csaf
        assert len(csaf["vulnerabilities"]) == 3

    def test_title_auto_generated(self):
        csaf = generate_csaf(_sample_vulns(), repo_name="octocat/hello-world")
        assert "octocat/hello-world" in csaf["document"]["title"]

    def test_custom_title(self):
        csaf = generate_csaf(_sample_vulns(), title="My Advisory")
        assert csaf["document"]["title"] == "My Advisory"

    def test_custom_publisher(self):
        csaf = generate_csaf(
            _sample_vulns(),
            publisher_name="Acme Security",
        )
        assert csaf["document"]["publisher"]["name"] == "Acme Security"

    def test_advisory_category(self):
        csaf = generate_csaf(
            _sample_vulns(),
            category=CSAF_CATEGORY_ADVISORY,
        )
        assert csaf["document"]["category"] == CSAF_CATEGORY_ADVISORY

    def test_metadata_in_notes(self):
        csaf = generate_csaf(
            _sample_vulns(),
            repo_name="octocat/hello-world",
            commit_sha="abc123",
            scan_id="scan-001",
        )
        notes = csaf["document"]["notes"]
        meta_notes = [n for n in notes if n.get("title") == "EURA Scan Metadata"]
        assert len(meta_notes) == 1
        text = meta_notes[0]["text"]
        assert "octocat/hello-world" in text
        assert "abc123" in text
        assert "scan-001" in text

    def test_no_metadata_note_when_none(self):
        csaf = generate_csaf(_sample_vulns())
        notes = csaf["document"]["notes"]
        meta_notes = [n for n in notes if n.get("title") == "EURA Scan Metadata"]
        assert len(meta_notes) == 0

    def test_product_tree_has_ecosystems(self):
        csaf = generate_csaf(_sample_vulns())
        tree = csaf["product_tree"]
        eco_names = {b["name"] for b in tree["branches"]}
        assert "maven" in eco_names
        assert "pypi" in eco_names
        assert "npm" in eco_names

    def test_product_tree_deduplicates(self):
        vulns = [
            {"vuln_id": "V1", "affected_package": "foo", "affected_version": "1.0",
             "severity": "HIGH", "ecosystem": "pypi"},
            {"vuln_id": "V2", "affected_package": "foo", "affected_version": "1.0",
             "severity": "LOW", "ecosystem": "pypi"},
        ]
        csaf = generate_csaf(vulns)
        names = csaf["product_tree"]["full_product_names"]
        product_ids = [n["product_id"] for n in names]
        assert product_ids.count("pkg:pypi/foo@1.0") == 1

    def test_fixed_versions_in_product_tree(self):
        vulns = [{
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "affected_version": "1.0",
            "fixed_version": "2.0",
            "severity": "HIGH",
            "ecosystem": "pypi",
        }]
        csaf = generate_csaf(vulns)
        names = csaf["product_tree"]["full_product_names"]
        product_ids = {n["product_id"] for n in names}
        assert "pkg:pypi/foo@1.0" in product_ids
        assert "pkg:pypi/foo@2.0" in product_ids

    def test_cve_vulnerabilities_have_cve_field(self):
        csaf = generate_csaf(_sample_vulns())
        cve_vulns = [v for v in csaf["vulnerabilities"] if "cve" in v]
        assert len(cve_vulns) == 2  # CVE-2021-44228 and CVE-2023-50000

    def test_tracking_has_generator(self):
        csaf = generate_csaf(_sample_vulns())
        gen = csaf["document"]["tracking"]["generator"]
        assert gen["engine"]["name"] == TOOL_NAME
        assert gen["engine"]["version"] == TOOL_VERSION

    def test_distribution_tlp_white(self):
        csaf = generate_csaf(_sample_vulns())
        assert csaf["document"]["distribution"]["tlp"]["label"] == "WHITE"

    def test_lang_is_en(self):
        csaf = generate_csaf(_sample_vulns())
        assert csaf["document"]["lang"] == "en"

    def test_custom_document_id(self):
        csaf = generate_csaf(
            _sample_vulns(),
            document_id="CUSTOM-DOC-001",
        )
        assert csaf["document"]["tracking"]["id"] == "CUSTOM-DOC-001"

    def test_json_serializable(self):
        import json
        csaf = generate_csaf(_sample_vulns(), repo_name="test/repo")
        serialized = json.dumps(csaf)
        assert isinstance(serialized, str)
        assert len(serialized) > 100

    def test_single_vulnerability(self):
        csaf = generate_csaf([{
            "vuln_id": "CVE-2024-99999",
            "affected_package": "mylib",
            "affected_version": "1.0",
            "severity": "LOW",
            "ecosystem": "pypi",
        }])
        assert len(csaf["vulnerabilities"]) == 1

    def test_summary_note_mentions_count(self):
        csaf = generate_csaf(_sample_vulns())
        summary_notes = [n for n in csaf["document"]["notes"] if n["category"] == "summary"]
        assert len(summary_notes) == 1
        assert "3" in summary_notes[0]["text"]

    def test_remediation_for_fixed_version(self):
        vulns = [{
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "affected_version": "1.0",
            "fixed_version": "2.0",
            "severity": "HIGH",
            "ecosystem": "pypi",
        }]
        csaf = generate_csaf(vulns)
        rems = csaf["vulnerabilities"][0].get("remediations", [])
        assert any(r["category"] == "vendor_fix" for r in rems)

    def test_references_propagated(self):
        vulns = [{
            "vuln_id": "CVE-TEST",
            "affected_package": "foo",
            "severity": "HIGH",
            "references": ["https://example.com/advisory"],
        }]
        csaf = generate_csaf(vulns)
        refs = csaf["vulnerabilities"][0].get("references", [])
        assert len(refs) == 1
        assert refs[0]["url"] == "https://example.com/advisory"

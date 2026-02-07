"""Tests for OSV vulnerability scanning service (app/services/osv.py)."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from app.services.osv import (
    _normalize_version,
    _map_ecosystem,
    _extract_severity,
    _extract_fixed_version,
    _extract_references,
    _severity_from_cvss_score,
    Vulnerability,
    VulnerabilityReport,
    query_single,
    query_batch,
    scan_dependencies,
    ECOSYSTEM_MAP,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestNormalizeVersion:
    """Tests for _normalize_version."""

    def test_exact_version(self):
        assert _normalize_version("1.2.3") == "1.2.3"

    def test_caret(self):
        assert _normalize_version("^1.2.3") == "1.2.3"

    def test_tilde(self):
        assert _normalize_version("~1.2.3") == "1.2.3"

    def test_gte(self):
        assert _normalize_version(">=2.0.0") == "2.0.0"

    def test_empty(self):
        assert _normalize_version("") == ""

    def test_spaces(self):
        assert _normalize_version("  1.0.0") == "1.0.0"


class TestMapEcosystem:
    """Tests for _map_ecosystem."""

    def test_python(self):
        assert _map_ecosystem("python") == "PyPI"

    def test_poetry(self):
        assert _map_ecosystem("poetry") == "PyPI"

    def test_node(self):
        assert _map_ecosystem("node") == "npm"

    def test_npm(self):
        assert _map_ecosystem("npm") == "npm"

    def test_go(self):
        assert _map_ecosystem("go") == "Go"

    def test_rust(self):
        assert _map_ecosystem("rust") == "crates.io"

    def test_unknown(self):
        assert _map_ecosystem("unknown_ecosystem") is None

    def test_case_insensitive(self):
        assert _map_ecosystem("Python") == "PyPI"
        assert _map_ecosystem("NODE") == "npm"


class TestExtractSeverity:
    """Tests for _extract_severity."""

    def test_database_specific_severity(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        assert _extract_severity(vuln) == "HIGH"

    def test_cvss_v3_score_numeric(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.1"}]}
        assert _extract_severity(vuln) == "CRITICAL"

    def test_cvss_v3_high(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        assert _extract_severity(vuln) == "HIGH"

    def test_cvss_v3_medium(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "5.0"}]}
        assert _extract_severity(vuln) == "MEDIUM"

    def test_cvss_v3_low(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "2.0"}]}
        assert _extract_severity(vuln) == "LOW"

    def test_empty_vuln(self):
        assert _extract_severity({}) == "UNKNOWN"

    def test_affected_database_specific(self):
        vuln = {
            "affected": [
                {"database_specific": {"severity": "MODERATE"}}
            ]
        }
        assert _extract_severity(vuln) == "MODERATE"


class TestSeverityFromCvssScore:
    """Tests for _severity_from_cvss_score."""

    def test_critical(self):
        assert _severity_from_cvss_score(9.8) == "CRITICAL"

    def test_high(self):
        assert _severity_from_cvss_score(7.5) == "HIGH"

    def test_medium(self):
        assert _severity_from_cvss_score(5.0) == "MEDIUM"

    def test_low(self):
        assert _severity_from_cvss_score(2.5) == "LOW"

    def test_zero(self):
        assert _severity_from_cvss_score(0.0) == "UNKNOWN"


class TestExtractFixedVersion:
    """Tests for _extract_fixed_version."""

    def test_found(self):
        vuln = {
            "affected": [{
                "package": {"name": "requests"},
                "ranges": [{
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.31.0"}
                    ]
                }]
            }]
        }
        assert _extract_fixed_version(vuln, "requests") == "2.31.0"

    def test_not_found(self):
        vuln = {"affected": [{"package": {"name": "other"}, "ranges": []}]}
        assert _extract_fixed_version(vuln, "requests") == ""

    def test_empty(self):
        assert _extract_fixed_version({}, "requests") == ""


class TestExtractReferences:
    """Tests for _extract_references."""

    def test_with_refs(self):
        vuln = {
            "references": [
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"},
                {"url": "https://github.com/advisory/GHSA-1234"},
            ]
        }
        refs = _extract_references(vuln)
        assert len(refs) == 2
        assert "nvd.nist.gov" in refs[0]

    def test_empty(self):
        assert _extract_references({}) == []


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class TestVulnerability:
    """Tests for Vulnerability data class."""

    def test_to_dict(self):
        v = Vulnerability(
            vuln_id="GHSA-1234",
            summary="Test vulnerability",
            severity="HIGH",
            aliases=["CVE-2023-1234"],
            affected_package="requests",
            affected_version="2.28.0",
            fixed_version="2.31.0",
            references=["https://example.com"],
        )
        d = v.to_dict()
        assert d["vuln_id"] == "GHSA-1234"
        assert d["severity"] == "HIGH"
        assert d["affected_package"] == "requests"
        assert d["fixed_version"] == "2.31.0"
        assert len(d["aliases"]) == 1

    def test_defaults(self):
        v = Vulnerability(vuln_id="TEST-001")
        d = v.to_dict()
        assert d["summary"] == ""
        assert d["severity"] == "UNKNOWN"
        assert d["aliases"] == []
        assert d["references"] == []


class TestVulnerabilityReport:
    """Tests for VulnerabilityReport."""

    def test_empty_report(self):
        r = VulnerabilityReport()
        d = r.to_dict()
        assert d["total_dependencies"] == 0
        assert d["vulnerable_count"] == 0
        assert d["vulnerability_count"] == 0
        assert d["vulnerabilities"] == []

    def test_report_with_vulns(self):
        r = VulnerabilityReport()
        r.total_dependencies = 10
        r.vulnerable_count = 2
        r.vulnerability_count = 3
        r.critical_count = 1
        r.high_count = 1
        r.medium_count = 1
        r.vulnerabilities.append(Vulnerability(vuln_id="V-1", severity="CRITICAL"))
        
        d = r.to_dict()
        assert d["total_dependencies"] == 10
        assert d["vulnerability_count"] == 3
        assert d["critical_count"] == 1
        assert len(d["vulnerabilities"]) == 1


# ---------------------------------------------------------------------------
# API calls (mocked)
# ---------------------------------------------------------------------------

class TestQuerySingle:
    """Tests for query_single (mocked HTTP)."""

    @pytest.mark.asyncio
    async def test_returns_vulns(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {"id": "GHSA-1234", "summary": "Test vuln"}
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.osv.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await query_single("requests", "2.28.0", "PyPI")
            assert len(result) == 1
            assert result[0]["id"] == "GHSA-1234"

    @pytest.mark.asyncio
    async def test_returns_empty_on_error(self):
        with patch("app.services.osv.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.side_effect = httpx.ConnectError("Connection failed")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await query_single("requests", "2.28.0", "PyPI")
            assert result == []


class TestQueryBatch:
    """Tests for query_batch (mocked HTTP)."""

    @pytest.mark.asyncio
    async def test_batch_query(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"vulns": [{"id": "GHSA-1111", "summary": "Vuln 1"}]},
                {"vulns": []},
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.osv.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            deps = [
                {"name": "requests", "version": "2.28.0", "type": "python"},
                {"name": "flask", "version": "2.0.0", "type": "python"},
            ]
            result = await query_batch(deps)
            # Only the first one has vulnerabilities
            assert "requests@2.28.0" in result
            assert "flask@2.0.0" not in result

    @pytest.mark.asyncio
    async def test_skips_unknown_ecosystem(self):
        deps = [
            {"name": "something", "version": "1.0", "type": "unknown_lang"},
        ]
        result = await query_batch(deps)
        assert result == {}

    @pytest.mark.asyncio
    async def test_empty_deps(self):
        result = await query_batch([])
        assert result == {}


# ---------------------------------------------------------------------------
# High-level scan
# ---------------------------------------------------------------------------

class TestScanDependencies:
    """Tests for scan_dependencies (mocked HTTP)."""

    @pytest.mark.asyncio
    async def test_empty_deps(self):
        report = await scan_dependencies([])
        assert report.total_dependencies == 0
        assert report.vulnerability_count == 0

    @pytest.mark.asyncio
    async def test_scan_with_vulns(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-9999",
                            "summary": "Critical vuln in requests",
                            "database_specific": {"severity": "CRITICAL"},
                            "affected": [{
                                "package": {"name": "requests"},
                                "ranges": [{
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.31.0"}
                                    ]
                                }]
                            }],
                            "aliases": ["CVE-2023-9999"],
                            "references": [{"url": "https://nvd.nist.gov"}],
                        }
                    ]
                },
                {"vulns": []},
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.osv.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            deps = [
                {"name": "requests", "version": "2.28.0", "type": "python", "file_source": "requirements.txt"},
                {"name": "flask", "version": "2.3.0", "type": "python", "file_source": "requirements.txt"},
            ]
            report = await scan_dependencies(deps)

            assert report.total_dependencies == 2
            assert report.vulnerable_count == 1
            assert report.vulnerability_count == 1
            assert report.critical_count == 1
            assert len(report.vulnerabilities) == 1
            assert report.vulnerabilities[0].vuln_id == "GHSA-9999"
            assert report.vulnerabilities[0].fixed_version == "2.31.0"

    @pytest.mark.asyncio
    async def test_scan_no_vulns(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [{"vulns": []}]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.osv.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            deps = [
                {"name": "flask", "version": "3.0.0", "type": "python"},
            ]
            report = await scan_dependencies(deps)

            assert report.total_dependencies == 1
            assert report.vulnerability_count == 0
            assert report.vulnerable_count == 0

    @pytest.mark.asyncio
    async def test_scan_accepts_pydantic_objects(self):
        """scan_dependencies should accept Pydantic Dependency objects too."""
        from app.schemas.requests import Dependency

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": [{"vulns": []}]}
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.osv.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            deps = [
                Dependency(name="requests", version="2.28.0", type="python", file_source="requirements.txt"),
            ]
            report = await scan_dependencies(deps)
            assert report.total_dependencies == 1

    @pytest.mark.asyncio
    async def test_report_to_dict(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": [{
                        "id": "GHSA-ABCD",
                        "summary": "Test",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [{"package": {"name": "pkg"}, "ranges": []}],
                        "references": [],
                    }]
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.osv.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            deps = [{"name": "pkg", "version": "1.0", "type": "python"}]
            report = await scan_dependencies(deps)
            d = report.to_dict()

            assert isinstance(d, dict)
            assert d["vulnerability_count"] == 1
            assert d["high_count"] == 1
            assert len(d["vulnerabilities"]) == 1
            assert d["vulnerabilities"][0]["vuln_id"] == "GHSA-ABCD"


# ---------------------------------------------------------------------------
# Rule engine integration
# ---------------------------------------------------------------------------

class TestCraBase003Integration:
    """Tests for CRA-BASE-003 with OSV vulnerability data."""

    def test_fail_with_critical_vulns(self):
        """CRA-BASE-003 should FAIL when critical vulnerabilities are found."""
        from app.services.rule_engine import RuleModule
        from app.services.compliance import load_rules_db

        rules_db = load_rules_db()
        rule_def = next(
            r for r in rules_db["rules"] if r["rule_id"] == "CRA-BASE-003"
        )
        rule = RuleModule("CRA-BASE-003", rule_def)

        evidence = {
            "dependencies": [{"name": "requests", "version": "2.28.0"}],
            "repo_files": [],
            "vulnerability_report": {
                "total_dependencies": 1,
                "vulnerable_count": 1,
                "vulnerability_count": 1,
                "critical_count": 1,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "vulnerabilities": [
                    {
                        "vuln_id": "GHSA-TEST",
                        "affected_package": "requests",
                        "severity": "CRITICAL",
                        "fixed_version": "2.31.0",
                    }
                ],
            },
        }

        # Need to provide signals that make the rule applicable
        signals = {"dependency_count": 1}
        result = rule.evaluate(signals, evidence)
        assert result.status == "FAIL"
        assert "critical" in result.reason.lower() or "Critical" in result.reason

    def test_pass_with_no_vulns(self):
        """CRA-BASE-003 should PASS when no vulnerabilities are found."""
        from app.services.rule_engine import RuleModule
        from app.services.compliance import load_rules_db

        rules_db = load_rules_db()
        rule_def = next(
            r for r in rules_db["rules"] if r["rule_id"] == "CRA-BASE-003"
        )
        rule = RuleModule("CRA-BASE-003", rule_def)

        evidence = {
            "dependencies": [{"name": "flask", "version": "3.0.0"}],
            "repo_files": [],
            "vulnerability_report": {
                "total_dependencies": 1,
                "vulnerable_count": 0,
                "vulnerability_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "vulnerabilities": [],
            },
        }

        signals = {"dependency_count": 1}
        result = rule.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_pass_with_low_only(self):
        """CRA-BASE-003 should PASS (advisory) when only low/medium vulns exist."""
        from app.services.rule_engine import RuleModule
        from app.services.compliance import load_rules_db

        rules_db = load_rules_db()
        rule_def = next(
            r for r in rules_db["rules"] if r["rule_id"] == "CRA-BASE-003"
        )
        rule = RuleModule("CRA-BASE-003", rule_def)

        evidence = {
            "dependencies": [{"name": "pkg", "version": "1.0"}],
            "repo_files": [],
            "vulnerability_report": {
                "total_dependencies": 1,
                "vulnerable_count": 1,
                "vulnerability_count": 2,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 1,
                "low_count": 1,
                "vulnerabilities": [],
            },
        }

        signals = {"dependency_count": 1}
        result = rule.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_fallback_no_osv_data(self):
        """CRA-BASE-003 falls back to tooling check when no OSV data."""
        from app.services.rule_engine import RuleModule
        from app.services.compliance import load_rules_db

        rules_db = load_rules_db()
        rule_def = next(
            r for r in rules_db["rules"] if r["rule_id"] == "CRA-BASE-003"
        )
        rule = RuleModule("CRA-BASE-003", rule_def)

        evidence = {
            "dependencies": [{"name": "pkg", "version": "1.0"}],
            "repo_files": [".github/dependabot.yml"],
        }

        signals = {"dependency_count": 1}
        result = rule.evaluate(signals, evidence)
        assert result.status == "PASS"
        assert "dependabot" in result.reason.lower()

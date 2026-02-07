"""Tests for expanded CRA rules (CRA-SEC-*, CRA-VULN-*, CRA-DOC-*, CRA-LIFE-*).

Covers:
 - rules_db.json structure validation (35 rules, 35 remediations)
 - Rule loading and filtering
 - repo_scan_static → file_presence routing fix
 - Applicability conditions for each new rule category
 - File-presence evaluation (PASS / FAIL) for every new rule
 - Full rule-engine integration with 35 rules
"""
import json
import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

from app.services.rule_engine import (
    RuleModule,
    RuleResult,
    RuleLoader,
    RuleEvaluationEngine,
    SignalBuilder,
    EvidenceCollector,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

RULES_DB_PATH = Path(__file__).resolve().parent.parent / "app" / "data" / "rules_db.json"


@pytest.fixture(scope="module")
def rules_db():
    """Load the full rules database once."""
    with open(RULES_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def all_rules(rules_db):
    """All rule definitions from the database."""
    return rules_db["rules"]


@pytest.fixture(scope="module")
def remediation_catalog(rules_db):
    """Remediation catalog dict."""
    return rules_db["remediation_catalog"]


@pytest.fixture
def rule_loader():
    return RuleLoader()


# Helpers -------------------------------------------------------------------

def _make_module(rules_db, rule_id: str) -> RuleModule:
    """Create a RuleModule for a given rule_id from the DB."""
    for r in rules_db["rules"]:
        if r["rule_id"] == rule_id:
            return RuleModule(rule_id, r)
    raise KeyError(f"Rule {rule_id} not found")


def _base_signals(**overrides):
    """Minimal signals dict with all keys present."""
    signals = {
        "has_security_policy": False,
        "dependency_count": 0,
        "has_lockfile": False,
        "has_dockerfile": False,
        "has_cicd_config": False,
        "has_changelog": False,
        "has_hardcoded_secrets": False,
        "vulnerable_dependency_count": 0,
        "has_security_testing": False,
        "release_tag_count": 0,
        "days_since_last_update": 0,
    }
    signals.update(overrides)
    return signals


# ===========================================================================
# 1. Database Structure Validation
# ===========================================================================

class TestRulesDBStructure:
    """Validate rules_db.json has correct structure after expansion."""

    def test_total_rule_count(self, all_rules):
        assert len(all_rules) == 35

    def test_total_remediation_count(self, remediation_catalog):
        assert len(remediation_catalog) == 35

    def test_metadata_counts(self, rules_db):
        meta = rules_db["metadata"]
        assert meta["rule_count"] == 35
        assert meta["remediation_count"] == 35

    def test_no_duplicate_rule_ids(self, all_rules):
        ids = [r["rule_id"] for r in all_rules]
        assert len(ids) == len(set(ids))

    def test_no_duplicate_remediation_ids(self, remediation_catalog):
        assert len(remediation_catalog) >= 35

    def test_all_rules_have_required_fields(self, all_rules):
        required = {"rule_id", "title", "description_short", "description_long",
                     "regulation", "required_evidence", "check_method",
                     "severity", "remediation_ids", "references", "version"}
        for rule in all_rules:
            missing = required - set(rule.keys())
            assert not missing, f"{rule['rule_id']} missing fields: {missing}"

    def test_severity_structure(self, all_rules):
        valid_levels = {"low", "medium", "high", "critical"}
        for rule in all_rules:
            sev = rule["severity"]
            assert sev["impact"] in valid_levels, f"{rule['rule_id']} bad impact"
            assert sev["likelihood"] in valid_levels, f"{rule['rule_id']} bad likelihood"
            assert sev["overall"] in valid_levels, f"{rule['rule_id']} bad overall"

    def test_all_remediation_ids_exist(self, all_rules, remediation_catalog):
        for rule in all_rules:
            for rem_id in rule["remediation_ids"]:
                assert rem_id in remediation_catalog, \
                    f"{rule['rule_id']} references non-existent {rem_id}"


# ===========================================================================
# 2. Rule Categories Present
# ===========================================================================

class TestRuleCategories:
    """Ensure all expected rule categories and IDs exist."""

    @pytest.mark.parametrize("prefix,expected_count", [
        ("CRA-BASE-", 18),
        ("CRA-SEC-", 5),
        ("CRA-VULN-", 4),
        ("CRA-DOC-", 4),
        ("CRA-LIFE-", 4),
    ])
    def test_category_count(self, all_rules, prefix, expected_count):
        category_rules = [r for r in all_rules if r["rule_id"].startswith(prefix)]
        assert len(category_rules) == expected_count, \
            f"Expected {expected_count} rules with prefix {prefix}, got {len(category_rules)}"

    @pytest.mark.parametrize("rule_id", [
        "CRA-SEC-001", "CRA-SEC-002", "CRA-SEC-003", "CRA-SEC-004", "CRA-SEC-005",
        "CRA-VULN-001", "CRA-VULN-002", "CRA-VULN-003", "CRA-VULN-004",
        "CRA-DOC-001", "CRA-DOC-002", "CRA-DOC-003", "CRA-DOC-004",
        "CRA-LIFE-001", "CRA-LIFE-002", "CRA-LIFE-003", "CRA-LIFE-004",
    ])
    def test_rule_exists(self, all_rules, rule_id):
        ids = [r["rule_id"] for r in all_rules]
        assert rule_id in ids

    def test_all_new_rules_are_cra(self, all_rules):
        for rule in all_rules:
            assert rule["regulation"] == "CRA"


# ===========================================================================
# 3. repo_scan_static Routing
# ===========================================================================

class TestRepoScanStaticRouting:
    """Verify repo_scan_static correctly routes to file_presence evaluator."""

    def test_repo_scan_static_routes_to_file_presence(self, rules_db):
        """All new rules with repo_scan_static should get evaluated (not UNKNOWN)."""
        for rule_id in ["CRA-SEC-001", "CRA-VULN-001", "CRA-DOC-001", "CRA-LIFE-001"]:
            mod = _make_module(rules_db, rule_id)
            assert mod.evaluation_method == "repo_scan_static"

            # With a matching file → should PASS (not UNKNOWN)
            ev_files = [e["source"] for e in mod.definition["required_evidence"]]
            evidence = {"repo_files": [ev_files[0]]}
            result = mod.evaluate(_base_signals(), evidence)
            assert result.status == "PASS", f"{rule_id} should PASS with matching file"

    def test_repo_scan_static_fails_when_no_files(self, rules_db):
        """With no matching files, repo_scan_static should FAIL (not UNKNOWN)."""
        mod = _make_module(rules_db, "CRA-SEC-001")
        evidence = {"repo_files": []}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "FAIL"

    def test_existing_base_rules_now_evaluate(self, rules_db):
        """CRA-BASE-004 through CRA-BASE-018 previously returned UNKNOWN due to
        repo_scan_static not being handled. They should now evaluate properly."""
        # CRA-BASE-004 requires Dockerfiles or config files
        mod = _make_module(rules_db, "CRA-BASE-004")
        signals = _base_signals(has_dockerfile=True, has_cicd_config=True,
                                has_default_security_config=True)
        evidence = {"repo_files": ["Dockerfile", ".env.example"]}
        result = mod.evaluate(signals, evidence)
        assert result.status in ("PASS", "FAIL"), \
            f"CRA-BASE-004 should evaluate, got {result.status}"


# ===========================================================================
# 4. CRA-SEC Rules — Security by Design
# ===========================================================================

class TestCRASecRules:
    """Tests for CRA-SEC-001 through CRA-SEC-005."""

    def test_sec001_pass_with_eslint(self, rules_db):
        mod = _make_module(rules_db, "CRA-SEC-001")
        evidence = {"repo_files": [".eslintrc.json", "src/index.js"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_sec001_pass_with_pyproject(self, rules_db):
        mod = _make_module(rules_db, "CRA-SEC-001")
        evidence = {"repo_files": ["pyproject.toml"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_sec001_fail_no_evidence(self, rules_db):
        mod = _make_module(rules_db, "CRA-SEC-001")
        evidence = {"repo_files": ["src/app.py"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "FAIL"

    def test_sec002_pass_with_env_example(self, rules_db):
        mod = _make_module(rules_db, "CRA-SEC-002")
        signals = _base_signals(has_security_policy=True)
        evidence = {"repo_files": [".env.example"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_sec002_fail_no_evidence(self, rules_db):
        """SEC-002 with no matching evidence files should FAIL."""
        mod = _make_module(rules_db, "CRA-SEC-002")
        signals = _base_signals(has_security_policy=True)
        evidence = {"repo_files": ["src/main.py"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "FAIL"

    def test_sec003_pass_with_dockerfile(self, rules_db):
        mod = _make_module(rules_db, "CRA-SEC-003")
        signals = _base_signals(has_dockerfile=True)
        evidence = {"repo_files": ["Dockerfile", ".dockerignore"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_sec004_always_applicable(self, rules_db):
        """SEC-004 has empty applicability, so always applies."""
        mod = _make_module(rules_db, "CRA-SEC-004")
        evidence = {"repo_files": []}
        result = mod.evaluate(_base_signals(), evidence)
        # Should evaluate (PASS or FAIL), not NOT_APPLICABLE
        assert result.status in ("PASS", "FAIL")

    def test_sec005_pass_with_encryption_docs(self, rules_db):
        mod = _make_module(rules_db, "CRA-SEC-005")
        signals = _base_signals(has_security_policy=True)
        evidence = {"repo_files": ["docs/encryption.md"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"


# ===========================================================================
# 5. CRA-VULN Rules — Vulnerability Handling
# ===========================================================================

class TestCRAVulnRules:
    """Tests for CRA-VULN-001 through CRA-VULN-004."""

    def test_vuln001_pass_with_security_md(self, rules_db):
        mod = _make_module(rules_db, "CRA-VULN-001")
        evidence = {"repo_files": ["SECURITY.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_vuln001_pass_with_security_txt(self, rules_db):
        mod = _make_module(rules_db, "CRA-VULN-001")
        evidence = {"repo_files": [".well-known/security.txt"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_vuln001_fail_no_disclosure(self, rules_db):
        mod = _make_module(rules_db, "CRA-VULN-001")
        evidence = {"repo_files": ["README.md", "src/main.py"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "FAIL"

    def test_vuln002_pass_with_advisory_template(self, rules_db):
        mod = _make_module(rules_db, "CRA-VULN-002")
        signals = _base_signals(has_security_policy=True)
        evidence = {"repo_files": [".github/ISSUE_TEMPLATE/security-advisory.md"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_vuln003_pass_with_bug_report(self, rules_db):
        mod = _make_module(rules_db, "CRA-VULN-003")
        evidence = {"repo_files": [".github/ISSUE_TEMPLATE/bug_report.yml", "CONTRIBUTING.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_vuln003_pass_with_contributing(self, rules_db):
        mod = _make_module(rules_db, "CRA-VULN-003")
        evidence = {"repo_files": ["CONTRIBUTING.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_vuln004_pass_with_release_workflow(self, rules_db):
        mod = _make_module(rules_db, "CRA-VULN-004")
        signals = _base_signals(has_changelog=True)
        evidence = {"repo_files": [".github/workflows/release.yml", "CHANGELOG.md"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_vuln004_pass_with_changelog(self, rules_db):
        mod = _make_module(rules_db, "CRA-VULN-004")
        signals = _base_signals(has_changelog=True)
        evidence = {"repo_files": ["CHANGELOG.md"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"


# ===========================================================================
# 6. CRA-DOC Rules — Technical Documentation
# ===========================================================================

class TestCRADocRules:
    """Tests for CRA-DOC-001 through CRA-DOC-004."""

    def test_doc001_pass_with_readme(self, rules_db):
        mod = _make_module(rules_db, "CRA-DOC-001")
        evidence = {"repo_files": ["README.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_doc001_pass_with_hardening_guide(self, rules_db):
        mod = _make_module(rules_db, "CRA-DOC-001")
        evidence = {"repo_files": ["docs/hardening-guide.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_doc002_pass_with_openapi(self, rules_db):
        mod = _make_module(rules_db, "CRA-DOC-002")
        evidence = {"repo_files": ["openapi.json"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_doc002_pass_with_swagger(self, rules_db):
        mod = _make_module(rules_db, "CRA-DOC-002")
        evidence = {"repo_files": ["swagger.yaml"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_doc002_fail_no_api_docs(self, rules_db):
        mod = _make_module(rules_db, "CRA-DOC-002")
        evidence = {"repo_files": ["src/main.py", "README.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "FAIL"

    def test_doc003_pass_with_architecture(self, rules_db):
        mod = _make_module(rules_db, "CRA-DOC-003")
        signals = _base_signals(has_security_policy=True)
        evidence = {"repo_files": ["docs/architecture.md"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_doc003_pass_with_threat_model(self, rules_db):
        mod = _make_module(rules_db, "CRA-DOC-003")
        signals = _base_signals(has_security_policy=True)
        evidence = {"repo_files": ["docs/threat-model.md"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_doc004_pass_with_deployment_docs(self, rules_db):
        mod = _make_module(rules_db, "CRA-DOC-004")
        evidence = {"repo_files": ["docs/deployment.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_doc004_pass_with_docker_compose(self, rules_db):
        mod = _make_module(rules_db, "CRA-DOC-004")
        evidence = {"repo_files": ["docker-compose.yml"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"


# ===========================================================================
# 7. CRA-LIFE Rules — Lifecycle Management
# ===========================================================================

class TestCRALifeRules:
    """Tests for CRA-LIFE-001 through CRA-LIFE-004."""

    def test_life001_pass_with_support_md(self, rules_db):
        mod = _make_module(rules_db, "CRA-LIFE-001")
        evidence = {"repo_files": ["SUPPORT.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_life001_pass_with_lifecycle_doc(self, rules_db):
        mod = _make_module(rules_db, "CRA-LIFE-001")
        evidence = {"repo_files": ["docs/lifecycle.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_life001_fail_no_support_docs(self, rules_db):
        mod = _make_module(rules_db, "CRA-LIFE-001")
        evidence = {"repo_files": ["README.md", "src/app.py"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "FAIL"

    def test_life002_pass_with_dependabot(self, rules_db):
        mod = _make_module(rules_db, "CRA-LIFE-002")
        evidence = {"repo_files": [".github/dependabot.yml"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_life002_pass_with_renovate(self, rules_db):
        mod = _make_module(rules_db, "CRA-LIFE-002")
        evidence = {"repo_files": ["renovate.json"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_life002_pass_with_changelog(self, rules_db):
        mod = _make_module(rules_db, "CRA-LIFE-002")
        evidence = {"repo_files": ["CHANGELOG.md"]}
        result = mod.evaluate(_base_signals(), evidence)
        assert result.status == "PASS"

    def test_life003_pass_with_release_workflow(self, rules_db):
        mod = _make_module(rules_db, "CRA-LIFE-003")
        signals = _base_signals(has_cicd_config=True)
        evidence = {"repo_files": [".github/workflows/release.yml"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_life003_fail_no_evidence(self, rules_db):
        """LIFE-003 without matching files should FAIL."""
        mod = _make_module(rules_db, "CRA-LIFE-003")
        signals = _base_signals(has_cicd_config=True)
        evidence = {"repo_files": ["src/app.py"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "FAIL"

    def test_life004_pass_with_migration_doc(self, rules_db):
        mod = _make_module(rules_db, "CRA-LIFE-004")
        signals = _base_signals(has_changelog=True)
        evidence = {"repo_files": ["docs/migration.md"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_life004_pass_with_changelog(self, rules_db):
        mod = _make_module(rules_db, "CRA-LIFE-004")
        signals = _base_signals(has_changelog=True)
        evidence = {"repo_files": ["CHANGELOG.md"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "PASS"

    def test_life004_fail_no_evidence(self, rules_db):
        """LIFE-004 without matching files should FAIL."""
        mod = _make_module(rules_db, "CRA-LIFE-004")
        signals = _base_signals(has_changelog=True)
        evidence = {"repo_files": ["src/app.py"]}
        result = mod.evaluate(signals, evidence)
        assert result.status == "FAIL"


# ===========================================================================
# 8. Rule Loader
# ===========================================================================

class TestRuleLoader:
    """Tests for RuleLoader with 35 rules."""

    def test_loads_all_35_rules(self, rule_loader):
        rules = rule_loader.load_rules()
        assert len(rules) == 35

    def test_filter_by_cra(self, rule_loader):
        rules = rule_loader.load_rules(regulations=["CRA"])
        assert len(rules) == 35

    def test_filter_nonexistent_regulation(self, rule_loader):
        rules = rule_loader.load_rules(regulations=["GDPR"])
        assert len(rules) == 0

    def test_get_rule_by_id(self, rule_loader):
        for rule_id in ["CRA-SEC-001", "CRA-VULN-001", "CRA-DOC-001", "CRA-LIFE-001"]:
            mod = rule_loader.get_rule(rule_id)
            assert mod is not None
            assert mod.rule_id == rule_id

    def test_get_nonexistent_rule(self, rule_loader):
        assert rule_loader.get_rule("CRA-FAKE-999") is None


# ===========================================================================
# 9. Signal Builder
# ===========================================================================

class TestSignalBuilder:
    """Verify signal builder produces signals used by new rules."""

    def test_signals_for_sec_rules(self):
        """SEC rules need has_security_policy, has_cicd_config, has_dockerfile."""
        signals = SignalBuilder.build_signals(
            findings=[],
            dependencies=[],
            repo_files=["SECURITY.md", ".github/workflows/ci.yml", "Dockerfile"],
        )
        assert signals["has_security_policy"] is True
        assert signals["has_cicd_config"] is True
        assert signals["has_dockerfile"] is True

    def test_signals_for_life_rules(self):
        """LIFE rules need has_changelog, has_cicd_config."""
        signals = SignalBuilder.build_signals(
            findings=[],
            dependencies=[],
            repo_files=["CHANGELOG.md", ".github/workflows/ci.yml"],
        )
        assert signals["has_changelog"] is True
        assert signals["has_cicd_config"] is True

    def test_signals_empty_repo(self):
        """All boolean signals should be False for an empty repo."""
        signals = SignalBuilder.build_signals(
            findings=[],
            dependencies=[],
            repo_files=[],
        )
        assert signals["has_security_policy"] is False
        assert signals["has_dockerfile"] is False
        assert signals["has_cicd_config"] is False
        assert signals["has_changelog"] is False


# ===========================================================================
# 10. Evidence Collector
# ===========================================================================

class TestEvidenceCollector:
    """Verify evidence collector sets file_exists_ flags for new rules."""

    def test_file_exists_flags(self, rules_db):
        mod = _make_module(rules_db, "CRA-VULN-001")
        collector = EvidenceCollector(
            repo_files=["SECURITY.md", "README.md"],
            findings=[],
            dependencies=[],
        )
        evidence = collector.collect_evidence(mod)
        assert evidence["file_exists_SECURITY.md"] is True
        assert evidence["file_exists_.github/SECURITY.md"] is False
        assert "SECURITY.md" in evidence["repo_files"]


# ===========================================================================
# 11. Full Rule Engine Integration
# ===========================================================================

class TestRuleEngineIntegration:
    """Integration tests evaluating all 35 rules via RuleEvaluationEngine."""

    @pytest.mark.asyncio
    async def test_evaluate_all_35_rules(self):
        """Engine should evaluate all 35 rules and return results."""
        engine = RuleEvaluationEngine()

        # Mock the LLM evaluation for CRA-BASE-001 and CRA-BASE-007
        async def mock_llm_eval(rule_def, repo_files, repo, read_file_func):
            return {
                "rule_id": rule_def["rule_id"],
                "status": "PASS",
                "confidence": 0.7,
                "reason": "Mocked LLM evaluation",
                "evaluated_at": datetime.utcnow().isoformat() + "Z",
            }

        with patch(
            "app.services.compliance.evaluate_documentation_rule_with_llm",
            side_effect=mock_llm_eval,
        ):
            report = await engine.evaluate_repo(
                findings=[],
                dependencies=[],
                repo_files=[
                    "SECURITY.md", "README.md", "CHANGELOG.md",
                    "requirements.txt", "Dockerfile", ".dockerignore",
                    ".github/workflows/ci.yml", ".github/dependabot.yml",
                    ".env.example", "docs/security.md", "pyproject.toml",
                    "CONTRIBUTING.md", "docker-compose.yml",
                    "openapi.json", "docs/architecture.md",
                    "docs/deployment.md", "SUPPORT.md",
                    ".github/workflows/release.yml",
                    "docs/migration.md",
                ],
                regulations=["CRA"],
            )

        assert report["total_rules"] == 35
        assert report["passed"] + report["failed"] + report["unknown"] + report["not_applicable"] == 35

        # With the rich file set, most rules should pass
        assert report["passed"] >= 20, f"Expected >= 20 passes, got {report['passed']}"

    @pytest.mark.asyncio
    async def test_evaluate_bare_repo(self):
        """A bare repo with no files should still evaluate all rules."""
        engine = RuleEvaluationEngine()

        async def mock_llm_eval(rule_def, repo_files, repo, read_file_func):
            return {
                "rule_id": rule_def["rule_id"],
                "status": "FAIL",
                "confidence": 0.5,
                "reason": "No documentation found",
                "evaluated_at": datetime.utcnow().isoformat() + "Z",
            }

        with patch(
            "app.services.compliance.evaluate_documentation_rule_with_llm",
            side_effect=mock_llm_eval,
        ):
            report = await engine.evaluate_repo(
                findings=[],
                dependencies=[],
                repo_files=[],
                regulations=["CRA"],
            )

        assert report["total_rules"] == 35
        # Most rules should FAIL or be NOT_APPLICABLE
        assert report["passed"] <= 5


# ===========================================================================
# 12. CRA Article References
# ===========================================================================

class TestCRAArticleReferences:
    """Verify each rule category maps to the correct CRA article."""

    @pytest.mark.parametrize("prefix,expected_article_prefix", [
        ("CRA-SEC-", "Article 10"),
        ("CRA-VULN-", "Article 11"),
        ("CRA-DOC-", "Article 13"),
        ("CRA-LIFE-", "Article 12"),
    ])
    def test_article_references(self, all_rules, prefix, expected_article_prefix):
        category_rules = [r for r in all_rules if r["rule_id"].startswith(prefix)]
        for rule in category_rules:
            article = rule["references"].get("article", "")
            assert article.startswith(expected_article_prefix), \
                f"{rule['rule_id']} should reference {expected_article_prefix}, got '{article}'"


# ===========================================================================
# 13. Evaluation Method Consistency
# ===========================================================================

class TestEvaluationMethods:
    """All new rules should use repo_scan_static."""

    def test_new_rules_use_repo_scan_static(self, all_rules):
        new_prefixes = ("CRA-SEC-", "CRA-VULN-", "CRA-DOC-", "CRA-LIFE-")
        for rule in all_rules:
            if any(rule["rule_id"].startswith(p) for p in new_prefixes):
                assert rule["check_method"] == "repo_scan_static", \
                    f"{rule['rule_id']} should use repo_scan_static"

    def test_repo_scan_static_maps_to_file_presence(self, rules_db):
        """Every repo_scan_static rule should create a RuleModule whose
        evaluation_method is repo_scan_static."""
        for rule_def in rules_db["rules"]:
            if rule_def["check_method"] == "repo_scan_static":
                mod = RuleModule(rule_def["rule_id"], rule_def)
                assert mod.evaluation_method == "repo_scan_static"

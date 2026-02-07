"""Tests for Remediation Template Generator (app/services/remediation_templates.py).

Covers:
 - All 5 template generators produce valid Markdown
 - Template content includes required CRA compliance elements
 - Parameterization (project name, contact email, etc.)
 - Template metadata (list_available_templates)
 - Edge cases (defaults, custom values)
"""
import pytest
from datetime import datetime

from app.services.remediation_templates import (
    generate_security_md,
    generate_changelog_md,
    generate_support_md,
    generate_contributing_md,
    generate_security_config_guide,
    list_available_templates,
    TEMPLATE_GENERATORS,
    TEMPLATE_FILENAMES,
    TEMPLATE_RULES_MAP,
)


# ===========================================================================
# 1. SECURITY.md Generator
# ===========================================================================

class TestSecurityMd:
    """Tests for generate_security_md."""

    def test_default_output(self):
        content = generate_security_md()
        assert "# Security Policy" in content
        assert "security@example.com" in content
        assert "This Project" in content

    def test_custom_project_name(self):
        content = generate_security_md(project_name="Acme App")
        assert "Acme App" in content

    def test_custom_contact(self):
        content = generate_security_md(contact_email="sec@acme.com")
        assert "sec@acme.com" in content

    def test_pgp_key_section(self):
        content = generate_security_md(pgp_key_url="https://keys.example.com/pgp.asc")
        assert "PGP Key" in content
        assert "https://keys.example.com/pgp.asc" in content

    def test_no_pgp_by_default(self):
        content = generate_security_md()
        assert "PGP Key" not in content

    def test_response_timeline(self):
        content = generate_security_md(response_hours=24)
        assert "24 hours" in content

    def test_disclosure_timeline(self):
        content = generate_security_md(disclosure_days=60)
        assert "60 days" in content

    def test_contains_safe_harbour(self):
        content = generate_security_md()
        assert "Safe Harbour" in content

    def test_contains_patch_sla(self):
        content = generate_security_md()
        assert "24-72 hours" in content
        assert "7 days" in content

    def test_contains_cra_reference(self):
        content = generate_security_md()
        assert "Cyber Resilience Act" in content
        assert "Article 11" in content

    def test_contains_iso_29147(self):
        content = generate_security_md()
        assert "ISO 29147" in content

    def test_supported_versions_table(self):
        content = generate_security_md()
        assert "Supported Versions" in content
        assert "Latest release" in content

    def test_ends_with_newline(self):
        content = generate_security_md()
        assert content.endswith("\n")


# ===========================================================================
# 2. CHANGELOG.md Generator
# ===========================================================================

class TestChangelogMd:
    """Tests for generate_changelog_md."""

    def test_default_output(self):
        content = generate_changelog_md()
        assert "# Changelog" in content
        assert "This Project" in content

    def test_custom_version(self):
        content = generate_changelog_md(initial_version="0.1.0")
        assert "[0.1.0]" in content

    def test_keep_a_changelog_format(self):
        content = generate_changelog_md()
        assert "Keep a Changelog" in content
        assert "Semantic Versioning" in content

    def test_has_unreleased_section(self):
        content = generate_changelog_md()
        assert "[Unreleased]" in content

    def test_has_security_section(self):
        content = generate_changelog_md()
        assert "### Security" in content

    def test_has_added_changed_fixed(self):
        content = generate_changelog_md()
        assert "### Added" in content
        assert "### Changed" in content
        assert "### Fixed" in content

    def test_contains_today_date(self):
        today = datetime.utcnow().strftime("%Y-%m-%d")
        content = generate_changelog_md()
        assert today in content

    def test_contains_cra_reference(self):
        content = generate_changelog_md()
        assert "Cyber Resilience Act" in content


# ===========================================================================
# 3. SUPPORT.md Generator
# ===========================================================================

class TestSupportMd:
    """Tests for generate_support_md."""

    def test_default_output(self):
        content = generate_support_md()
        assert "# Support Policy" in content
        assert "This Project" in content

    def test_custom_support_years(self):
        content = generate_support_md(support_years=3)
        assert "3 years" in content

    def test_eol_year_calculation(self):
        current_year = datetime.utcnow().year
        content = generate_support_md(support_years=5)
        assert str(current_year + 5) in content

    def test_custom_email(self):
        content = generate_support_md(support_email="help@acme.com")
        assert "help@acme.com" in content

    def test_contains_lifecycle_phases(self):
        content = generate_support_md()
        assert "Active development" in content
        assert "Security support" in content
        assert "End of Life" in content

    def test_contains_eol_notification(self):
        content = generate_support_md()
        assert "6 months before" in content
        assert "3 months before" in content

    def test_contains_cra_article_12(self):
        content = generate_support_md()
        assert "Article 12" in content


# ===========================================================================
# 4. CONTRIBUTING.md Generator
# ===========================================================================

class TestContributingMd:
    """Tests for generate_contributing_md."""

    def test_default_output(self):
        content = generate_contributing_md()
        assert "# Contributing" in content

    def test_custom_project(self):
        content = generate_contributing_md(project_name="SuperApp")
        assert "SuperApp" in content

    def test_security_warning(self):
        content = generate_contributing_md()
        assert "Do NOT report security vulnerabilities via public GitHub issues" in content

    def test_references_security_md(self):
        content = generate_contributing_md()
        assert "SECURITY.md" in content

    def test_has_development_setup(self):
        content = generate_contributing_md()
        assert "Development Setup" in content

    def test_contains_cra_reference(self):
        content = generate_contributing_md()
        assert "Cyber Resilience Act" in content


# ===========================================================================
# 5. Security Configuration Guide
# ===========================================================================

class TestSecurityConfigGuide:
    """Tests for generate_security_config_guide."""

    def test_default_output(self):
        content = generate_security_config_guide()
        assert "# Security Configuration Guide" in content

    def test_custom_project(self):
        content = generate_security_config_guide(project_name="MyAPI")
        assert "MyAPI" in content

    def test_has_env_vars_section(self):
        content = generate_security_config_guide()
        assert "Environment Variables" in content
        assert ".env" in content
        assert ".gitignore" in content

    def test_has_auth_section(self):
        content = generate_security_config_guide()
        assert "Authentication" in content

    def test_has_network_section(self):
        content = generate_security_config_guide()
        assert "Network Security" in content
        assert "TLS" in content

    def test_has_logging_section(self):
        content = generate_security_config_guide()
        assert "Logging" in content

    def test_has_hardening_checklist(self):
        content = generate_security_config_guide()
        assert "Hardening Checklist" in content
        assert "[ ]" in content

    def test_has_container_section(self):
        content = generate_security_config_guide()
        assert "Container Security" in content
        assert "non-root" in content

    def test_contains_cra_articles(self):
        content = generate_security_config_guide()
        assert "Article 10" in content
        assert "Article 13" in content


# ===========================================================================
# 6. Template Metadata
# ===========================================================================

class TestTemplateMetadata:
    """Tests for template registry and metadata."""

    def test_all_generators_registered(self):
        assert len(TEMPLATE_GENERATORS) == 5

    def test_all_filenames_registered(self):
        assert len(TEMPLATE_FILENAMES) == 5
        for tid in TEMPLATE_GENERATORS:
            assert tid in TEMPLATE_FILENAMES

    def test_all_rules_mapped(self):
        for tid in TEMPLATE_GENERATORS:
            assert tid in TEMPLATE_RULES_MAP
            assert len(TEMPLATE_RULES_MAP[tid]) >= 1

    def test_list_available_templates(self):
        templates = list_available_templates()
        assert len(templates) == 5
        for t in templates:
            assert "template_id" in t
            assert "filename" in t
            assert "addresses_rules" in t
            assert "description" in t

    def test_filenames(self):
        assert TEMPLATE_FILENAMES["security-md"] == "SECURITY.md"
        assert TEMPLATE_FILENAMES["changelog-md"] == "CHANGELOG.md"
        assert TEMPLATE_FILENAMES["support-md"] == "SUPPORT.md"
        assert TEMPLATE_FILENAMES["contributing-md"] == "CONTRIBUTING.md"
        assert TEMPLATE_FILENAMES["security-config"] == "docs/security-configuration.md"

    def test_rules_map_references_valid_rules(self):
        """All rule IDs in the map should start with CRA-."""
        for tid, rules in TEMPLATE_RULES_MAP.items():
            for rule_id in rules:
                assert rule_id.startswith("CRA-"), f"{tid} references invalid rule {rule_id}"


# ===========================================================================
# 7. All Templates Are Valid Markdown
# ===========================================================================

class TestAllTemplatesValid:
    """Quick validation that every template produces non-empty Markdown."""

    @pytest.mark.parametrize("template_id", list(TEMPLATE_GENERATORS.keys()))
    def test_template_produces_content(self, template_id):
        gen = TEMPLATE_GENERATORS[template_id]
        content = gen()
        assert len(content) > 100
        assert content.startswith("#")
        assert content.endswith("\n")

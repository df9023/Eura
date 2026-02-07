"""Tests for compliance badge generation (app/services/badge.py)."""
import pytest
from app.services.badge import (
    generate_verdict_badge,
    generate_score_badge,
    generate_compliance_badge,
    generate_error_badge,
    _score_color,
    _verdict_color,
    _text_width,
    COLORS,
)


# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

class TestScoreColor:
    """Tests for _score_color helper."""

    def test_perfect_score(self):
        assert _score_color(100) == COLORS["brightgreen"]

    def test_high_score(self):
        assert _score_color(92) == COLORS["brightgreen"]

    def test_good_score(self):
        assert _score_color(80) == COLORS["green"]

    def test_medium_score(self):
        assert _score_color(65) == COLORS["yellowgreen"]

    def test_low_score(self):
        assert _score_color(45) == COLORS["yellow"]

    def test_poor_score(self):
        assert _score_color(25) == COLORS["orange"]

    def test_failing_score(self):
        assert _score_color(10) == COLORS["red"]

    def test_zero_score(self):
        assert _score_color(0) == COLORS["red"]

    def test_boundary_90(self):
        assert _score_color(90) == COLORS["brightgreen"]
        assert _score_color(89.9) == COLORS["green"]

    def test_boundary_75(self):
        assert _score_color(75) == COLORS["green"]
        assert _score_color(74.9) == COLORS["yellowgreen"]


class TestVerdictColor:
    """Tests for _verdict_color helper."""

    def test_ship_allowed(self):
        assert _verdict_color("SHIP_ALLOWED") == COLORS["brightgreen"]

    def test_ship_blocked(self):
        assert _verdict_color("SHIP_BLOCKED") == COLORS["red"]

    def test_unknown_verdict(self):
        assert _verdict_color("SOMETHING_ELSE") == COLORS["lightgrey"]


class TestTextWidth:
    """Tests for _text_width estimator."""

    def test_empty_string(self):
        assert _text_width("") == 0

    def test_short_string(self):
        w = _text_width("CRA")
        assert w > 0

    def test_longer_string_wider(self):
        assert _text_width("COMPLIANT") > _text_width("CRA")

    def test_uppercase_wider_than_lowercase(self):
        assert _text_width("ABCD") > _text_width("abcd")


# ---------------------------------------------------------------------------
# Verdict badges
# ---------------------------------------------------------------------------

class TestVerdictBadge:
    """Tests for generate_verdict_badge."""

    def test_ship_allowed_contains_text(self):
        svg = generate_verdict_badge("SHIP_ALLOWED")
        assert "SHIP ALLOWED" in svg
        assert "EURA" in svg

    def test_ship_blocked_contains_text(self):
        svg = generate_verdict_badge("SHIP_BLOCKED")
        assert "SHIP BLOCKED" in svg

    def test_custom_label(self):
        svg = generate_verdict_badge("SHIP_ALLOWED", label="CRA")
        assert "CRA" in svg

    def test_is_valid_svg(self):
        svg = generate_verdict_badge("SHIP_ALLOWED")
        assert svg.strip().startswith("<svg")
        assert svg.strip().endswith("</svg>")

    def test_flat_style(self):
        svg = generate_verdict_badge("SHIP_ALLOWED", style="flat")
        assert "linearGradient" in svg

    def test_flat_square_style(self):
        svg = generate_verdict_badge("SHIP_ALLOWED", style="flat-square")
        assert "crispEdges" in svg
        assert "linearGradient" not in svg

    def test_ship_allowed_has_green(self):
        svg = generate_verdict_badge("SHIP_ALLOWED")
        assert COLORS["brightgreen"] in svg

    def test_ship_blocked_has_red(self):
        svg = generate_verdict_badge("SHIP_BLOCKED")
        assert COLORS["red"] in svg

    def test_aria_label(self):
        svg = generate_verdict_badge("SHIP_ALLOWED", label="EURA")
        assert 'aria-label="EURA: SHIP ALLOWED"' in svg


# ---------------------------------------------------------------------------
# Score badges
# ---------------------------------------------------------------------------

class TestScoreBadge:
    """Tests for generate_score_badge."""

    def test_score_displayed(self):
        svg = generate_score_badge(92.7, "CRA")
        assert "93%" in svg  # rounds to nearest integer
        assert "CRA" in svg

    def test_zero_score(self):
        svg = generate_score_badge(0, "CRA")
        assert "0%" in svg

    def test_perfect_score(self):
        svg = generate_score_badge(100, "CRA")
        assert "100%" in svg

    def test_score_color_gradient(self):
        svg_high = generate_score_badge(95)
        svg_low = generate_score_badge(15)
        assert COLORS["brightgreen"] in svg_high
        assert COLORS["red"] in svg_low

    def test_custom_regulation(self):
        svg = generate_score_badge(80, "AI Act")
        assert "AI Act" in svg

    def test_is_valid_svg(self):
        svg = generate_score_badge(50)
        assert svg.strip().startswith("<svg")
        assert svg.strip().endswith("</svg>")


# ---------------------------------------------------------------------------
# Compliance badges
# ---------------------------------------------------------------------------

class TestComplianceBadge:
    """Tests for generate_compliance_badge."""

    def test_compliant(self):
        svg = generate_compliance_badge("SHIP_ALLOWED", "CRA")
        assert "COMPLIANT" in svg
        assert "CRA" in svg

    def test_non_compliant(self):
        svg = generate_compliance_badge("SHIP_BLOCKED", "CRA")
        assert "NON-COMPLIANT" in svg
        assert COLORS["red"] in svg

    def test_unknown_verdict(self):
        svg = generate_compliance_badge("SOMETHING", "CRA")
        assert "UNKNOWN" in svg
        assert COLORS["lightgrey"] in svg

    def test_ai_act_regulation(self):
        svg = generate_compliance_badge("SHIP_ALLOWED", "AI Act")
        assert "AI Act" in svg

    def test_flat_square_style(self):
        svg = generate_compliance_badge("SHIP_ALLOWED", style="flat-square")
        assert "crispEdges" in svg


# ---------------------------------------------------------------------------
# Error badges
# ---------------------------------------------------------------------------

class TestErrorBadge:
    """Tests for generate_error_badge."""

    def test_default_error(self):
        svg = generate_error_badge()
        assert "EURA" in svg
        assert "no data" in svg
        assert COLORS["lightgrey"] in svg

    def test_custom_message(self):
        svg = generate_error_badge(label="CRA", message="no scans")
        assert "CRA" in svg
        assert "no scans" in svg

    def test_is_valid_svg(self):
        svg = generate_error_badge()
        assert svg.strip().startswith("<svg")
        assert svg.strip().endswith("</svg>")


# ---------------------------------------------------------------------------
# SVG structure
# ---------------------------------------------------------------------------

class TestSvgStructure:
    """Tests for SVG output correctness."""

    def test_has_xmlns(self):
        svg = generate_verdict_badge("SHIP_ALLOWED")
        assert 'xmlns="http://www.w3.org/2000/svg"' in svg

    def test_has_width_and_height(self):
        svg = generate_verdict_badge("SHIP_ALLOWED")
        assert 'width=' in svg
        assert 'height="20"' in svg

    def test_has_title(self):
        svg = generate_verdict_badge("SHIP_ALLOWED", label="EURA")
        assert "<title>EURA: SHIP ALLOWED</title>" in svg

    def test_has_role_img(self):
        svg = generate_verdict_badge("SHIP_ALLOWED")
        assert 'role="img"' in svg

    def test_font_family(self):
        svg = generate_verdict_badge("SHIP_ALLOWED")
        assert "Verdana" in svg

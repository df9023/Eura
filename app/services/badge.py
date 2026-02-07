"""Compliance badge generation service.

Generates shields.io-style SVG badges for embedding in READMEs and dashboards.
Supports verdict badges, score badges, and per-regulation badges.

Usage in README:
    ![CRA Compliance](https://your-api.example.com/api/v1/badges/{project_id}?regulation=CRA)
    ![EURA](https://your-api.example.com/api/v1/badges/scan/{scan_id})
"""
from typing import Literal, Optional


# ---------------------------------------------------------------------------
# Color palette (shields.io conventions)
# ---------------------------------------------------------------------------

COLORS = {
    "brightgreen": "#4c1",
    "green": "#97ca00",
    "yellowgreen": "#a4a61d",
    "yellow": "#dfb317",
    "orange": "#fe7d37",
    "red": "#e05d44",
    "blue": "#007ec6",
    "grey": "#555",
    "lightgrey": "#9f9f9f",
}


def _score_color(score: float) -> str:
    """Return a hex color for a compliance score (0-100)."""
    if score >= 90:
        return COLORS["brightgreen"]
    if score >= 75:
        return COLORS["green"]
    if score >= 60:
        return COLORS["yellowgreen"]
    if score >= 40:
        return COLORS["yellow"]
    if score >= 20:
        return COLORS["orange"]
    return COLORS["red"]


def _verdict_color(verdict: str) -> str:
    """Return a hex color for a verdict string."""
    if verdict == "SHIP_ALLOWED":
        return COLORS["brightgreen"]
    if verdict == "SHIP_BLOCKED":
        return COLORS["red"]
    return COLORS["lightgrey"]


def _text_width(text: str) -> int:
    """Estimate rendered text width in tenths-of-a-pixel (×10) for SVG layout.

    Uses a simplified character-width table calibrated to Verdana 11px, the
    same font shields.io uses.  Good enough for badge rendering; exact kerning
    is not required.
    """
    WIDTHS = {
        " ": 33, "f": 33, "i": 33, "j": 33, "l": 33, "t": 37,
        "r": 37, "!": 33, ".": 33, ",": 33, ";": 33, ":": 33,
        "'": 20, '"': 42, "(": 37, ")": 37, "-": 37, "_": 48,
        "m": 80, "w": 72, "M": 80, "W": 80,
        "%": 73, "/": 37, "@": 88,
    }
    DEFAULT = 62  # average character width
    UPPERCASE_DEFAULT = 72
    total = 0
    for ch in text:
        if ch in WIDTHS:
            total += WIDTHS[ch]
        elif ch.isupper():
            total += UPPERCASE_DEFAULT
        elif ch.isdigit():
            total += 60
        else:
            total += DEFAULT
    return total


def _render_svg(
    label: str,
    message: str,
    message_color: str,
    style: str = "flat",
) -> str:
    """Render a shields.io-compatible SVG badge.

    Args:
        label: Left-hand text (e.g. "CRA", "EURA").
        message: Right-hand text (e.g. "COMPLIANT", "92%").
        message_color: Hex color for the right side (with leading #).
        style: Badge style – "flat" (default) or "flat-square".

    Returns:
        SVG string (UTF-8).
    """
    label_color = COLORS["grey"]

    # Compute widths (tenths of a pixel)
    PADDING = 100  # 10px padding each side
    label_w10 = _text_width(label) + PADDING
    msg_w10 = _text_width(message) + PADDING
    total_w10 = label_w10 + msg_w10

    # Convert to actual pixels
    label_w = label_w10 / 10.0
    msg_w = msg_w10 / 10.0
    total_w = total_w10 / 10.0

    label_x = label_w / 2
    msg_x = label_w + msg_w / 2

    if style == "flat-square":
        return _flat_square_svg(
            total_w, label_w, msg_w, label_x, msg_x,
            label, message, label_color, message_color,
        )
    return _flat_svg(
        total_w, label_w, msg_w, label_x, msg_x,
        label, message, label_color, message_color,
    )


def _flat_svg(
    total_w: float, label_w: float, msg_w: float,
    label_x: float, msg_x: float,
    label: str, message: str,
    label_color: str, message_color: str,
) -> str:
    """Flat style badge (rounded corners, gradient shadow)."""
    return f"""\
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="{total_w:.0f}" height="20" role="img" aria-label="{label}: {message}">
  <title>{label}: {message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_w:.0f}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_w:.0f}" height="20" fill="{label_color}"/>
    <rect x="{label_w:.0f}" width="{msg_w:.0f}" height="20" fill="{message_color}"/>
    <rect width="{total_w:.0f}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle"
     font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision"
     font-size="110">
    <text aria-hidden="true" x="{label_x * 10:.0f}" y="150" fill="#010101" fill-opacity=".3"
          transform="scale(.1)" textLength="{_text_width(label)}">{label}</text>
    <text x="{label_x * 10:.0f}" y="140" transform="scale(.1)"
          textLength="{_text_width(label)}">{label}</text>
    <text aria-hidden="true" x="{msg_x * 10:.0f}" y="150" fill="#010101" fill-opacity=".3"
          transform="scale(.1)" textLength="{_text_width(message)}">{message}</text>
    <text x="{msg_x * 10:.0f}" y="140" transform="scale(.1)"
          textLength="{_text_width(message)}">{message}</text>
  </g>
</svg>"""


def _flat_square_svg(
    total_w: float, label_w: float, msg_w: float,
    label_x: float, msg_x: float,
    label: str, message: str,
    label_color: str, message_color: str,
) -> str:
    """Flat-square style badge (no rounded corners, no gradient)."""
    return f"""\
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="{total_w:.0f}" height="20" role="img" aria-label="{label}: {message}">
  <title>{label}: {message}</title>
  <g shape-rendering="crispEdges">
    <rect width="{label_w:.0f}" height="20" fill="{label_color}"/>
    <rect x="{label_w:.0f}" width="{msg_w:.0f}" height="20" fill="{message_color}"/>
  </g>
  <g fill="#fff" text-anchor="middle"
     font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision"
     font-size="110">
    <text x="{label_x * 10:.0f}" y="140" transform="scale(.1)"
          textLength="{_text_width(label)}">{label}</text>
    <text x="{msg_x * 10:.0f}" y="140" transform="scale(.1)"
          textLength="{_text_width(message)}">{message}</text>
  </g>
</svg>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_verdict_badge(
    verdict: str,
    label: str = "EURA",
    style: str = "flat",
) -> str:
    """Generate an SVG badge showing the shipping verdict.

    Args:
        verdict: "SHIP_ALLOWED" or "SHIP_BLOCKED".
        label: Left-hand label text (default "EURA").
        style: "flat" or "flat-square".

    Returns:
        SVG string.

    Examples:
        >>> svg = generate_verdict_badge("SHIP_ALLOWED")
        >>> "SHIP ALLOWED" in svg
        True
    """
    display = verdict.replace("_", " ")
    color = _verdict_color(verdict)
    return _render_svg(label, display, color, style)


def generate_score_badge(
    score: float,
    regulation: str = "CRA",
    style: str = "flat",
) -> str:
    """Generate an SVG badge showing a numeric compliance score.

    Args:
        score: Compliance score 0–100.
        regulation: Regulation label (e.g. "CRA", "AI Act").
        style: "flat" or "flat-square".

    Returns:
        SVG string.

    Examples:
        >>> svg = generate_score_badge(92.5, "CRA")
        >>> "93%" in svg
        True
    """
    display = f"{round(score)}%"
    color = _score_color(score)
    return _render_svg(regulation, display, color, style)


def generate_compliance_badge(
    verdict: str,
    regulation: str = "CRA",
    style: str = "flat",
) -> str:
    """Generate a regulation-specific COMPLIANT / NON-COMPLIANT badge.

    Args:
        verdict: "SHIP_ALLOWED" or "SHIP_BLOCKED".
        regulation: Regulation label (e.g. "CRA", "AI Act").
        style: "flat" or "flat-square".

    Returns:
        SVG string.

    Examples:
        >>> svg = generate_compliance_badge("SHIP_ALLOWED", "CRA")
        >>> "COMPLIANT" in svg
        True
    """
    if verdict == "SHIP_ALLOWED":
        message = "COMPLIANT"
        color = COLORS["brightgreen"]
    elif verdict == "SHIP_BLOCKED":
        message = "NON-COMPLIANT"
        color = COLORS["red"]
    else:
        message = "UNKNOWN"
        color = COLORS["lightgrey"]
    return _render_svg(regulation, message, color, style)


def generate_error_badge(
    label: str = "EURA",
    message: str = "no data",
    style: str = "flat",
) -> str:
    """Generate a grey error / placeholder badge.

    Args:
        label: Left-hand label text.
        message: Right-hand message text.
        style: "flat" or "flat-square".

    Returns:
        SVG string.
    """
    return _render_svg(label, message, COLORS["lightgrey"], style)

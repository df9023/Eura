"""OpenVEX report generation for EURA compliance scan results.

Generates Vulnerability Exploitability eXchange (VEX) documents in the
OpenVEX v0.2.0 format from EURA scan data — vulnerability reports and
dependency analysis.  VEX documents communicate the exploitability status
of known vulnerabilities in a software product.

Specification: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
PRD Reference:  Section 3.8.1 — CRA Mandatory Artifacts (VEX export).
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.logger import logger

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
TOOL_NAME = "EURA"
TOOL_VERSION = "2.0"
TOOL_URI = "https://github.com/eura-compliance/eura"

# Valid VEX statuses per OpenVEX spec
VEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}

# Valid justification values for "not_affected" status
VEX_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}

# Map from OSV severity to a VEX-friendly impact description
_SEVERITY_IMPACT: Dict[str, str] = {
    "CRITICAL": "Critical severity — immediate remediation recommended.",
    "HIGH": "High severity — remediation should be prioritized.",
    "MEDIUM": "Medium severity — schedule remediation in next release cycle.",
    "LOW": "Low severity — track and remediate as capacity allows.",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_product_id(
    package_name: str,
    version: str = "",
    ecosystem: str = "",
) -> str:
    """Build a product identifier string (purl-like) for VEX statements."""
    eco = ecosystem.lower() if ecosystem else "generic"
    base = f"pkg:{eco}/{package_name}"
    if version:
        base += f"@{version}"
    return base


def _determine_vex_status(vuln: Dict[str, Any]) -> str:
    """Determine the VEX status for a vulnerability.

    Uses explicit ``vex_status`` if provided, otherwise infers from the
    vulnerability data:
    - If ``fixed_version`` is present → ``fixed``
    - If ``affected`` flag is explicitly False → ``not_affected``
    - Otherwise → ``affected``
    """
    explicit = vuln.get("vex_status", "").lower()
    if explicit in VEX_STATUSES:
        return explicit

    if vuln.get("fixed_version"):
        return "affected"  # fix available but package still on vulnerable version
    if vuln.get("affected") is False:
        return "not_affected"
    return "affected"


def _determine_justification(vuln: Dict[str, Any]) -> Optional[str]:
    """Return a justification string if the status is ``not_affected``."""
    just = vuln.get("justification", "")
    if just and just in VEX_JUSTIFICATIONS:
        return just
    return None


def _make_vex_statement(
    vuln: Dict[str, Any],
    product_ids: List[str],
) -> Dict[str, Any]:
    """Convert a single vulnerability dict to an OpenVEX statement."""
    vuln_id = vuln.get("vuln_id", vuln.get("id", f"EURA-UNKNOWN-{uuid.uuid4().hex[:8]}"))
    summary = vuln.get("summary", "")
    severity = vuln.get("severity", "UNKNOWN").upper()
    status = _determine_vex_status(vuln)

    statement: Dict[str, Any] = {
        "vulnerability": {
            "@id": vuln_id,
            "name": vuln_id,
        },
        "products": [{"@id": pid} for pid in product_ids],
        "status": status,
    }

    # Add description to vulnerability node
    if summary:
        statement["vulnerability"]["description"] = summary

    # Add justification for not_affected
    if status == "not_affected":
        justification = _determine_justification(vuln)
        if justification:
            statement["justification"] = justification
        impact = vuln.get("impact_statement", "")
        if impact:
            statement["impact_statement"] = impact

    # Add action_statement for affected/fixed
    if status in ("affected", "fixed"):
        fixed_version = vuln.get("fixed_version", "")
        action = vuln.get("action_statement", "")
        if not action and fixed_version:
            pkg = vuln.get("affected_package", "the affected package")
            action = f"Upgrade {pkg} to version {fixed_version} or later."
        if action:
            statement["action_statement"] = action

    # Add impact description based on severity
    if severity in _SEVERITY_IMPACT and "impact_statement" not in statement:
        statement["impact_statement"] = _SEVERITY_IMPACT[severity]

    return statement


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_vex(
    vulnerabilities: List[Dict[str, Any]],
    *,
    repo_name: Optional[str] = None,
    commit_sha: Optional[str] = None,
    scan_id: Optional[str] = None,
    author: str = f"{TOOL_NAME} Compliance Scanner",
    author_role: str = "tool",
    document_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate an OpenVEX v0.2.0 JSON document from vulnerability data.

    Args:
        vulnerabilities: List of vulnerability dicts, each containing at
            minimum ``vuln_id`` (or ``id``), ``affected_package``,
            ``severity``.  Optional fields: ``affected_version``,
            ``fixed_version``, ``summary``, ``vex_status``,
            ``justification``, ``action_statement``, ``impact_statement``,
            ``ecosystem``.
        repo_name: Repository identifier (e.g. ``owner/repo``).
        commit_sha: Git commit hash.
        scan_id: EURA scan UUID.
        author: VEX document author.
        author_role: Author role (``tool``, ``vendor``, ``discoverer``).
        document_id: Explicit document ``@id``.  Auto-generated if omitted.

    Returns:
        OpenVEX 0.2.0 document as a Python dict (JSON-serializable).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = document_id or f"https://eura.dev/vex/{uuid.uuid4()}"

    # ------------------------------------------------------------------
    # Build statements
    # ------------------------------------------------------------------
    statements: List[Dict[str, Any]] = []

    for vuln in vulnerabilities:
        package = vuln.get("affected_package", "unknown")
        version = vuln.get("affected_version", "")
        ecosystem = vuln.get("ecosystem", vuln.get("type", ""))

        product_id = _make_product_id(package, version, ecosystem)
        statement = _make_vex_statement(vuln, [product_id])
        statements.append(statement)

    # ------------------------------------------------------------------
    # Assemble VEX document
    # ------------------------------------------------------------------
    vex: Dict[str, Any] = {
        "@context": OPENVEX_CONTEXT,
        "@id": doc_id,
        "author": author,
        "role": author_role,
        "timestamp": now,
        "version": 1,
        "tooling": f"{TOOL_NAME}/{TOOL_VERSION}",
        "statements": statements,
    }

    # Add metadata
    if repo_name or commit_sha or scan_id:
        metadata: Dict[str, Any] = {}
        if repo_name:
            metadata["repo"] = repo_name
        if commit_sha:
            metadata["commit"] = commit_sha
        if scan_id:
            metadata["scan_id"] = scan_id
        vex["metadata"] = metadata

    # ------------------------------------------------------------------
    # Summary stats
    # ------------------------------------------------------------------
    status_counts: Dict[str, int] = {}
    for s in statements:
        st = s.get("status", "unknown")
        status_counts[st] = status_counts.get(st, 0) + 1

    logger.debug(
        "Generated VEX document: %d statements (%s)",
        len(statements),
        ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items())),
    )

    return vex

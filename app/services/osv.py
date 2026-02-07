"""OSV (Open Source Vulnerabilities) API client.

Queries the free osv.dev API to check dependencies for known vulnerabilities.
Used by CRA-BASE-003 to make vulnerability scanning functional.

API documentation: https://osv.dev/docs/
- POST https://api.osv.dev/v1/query        (single package)
- POST https://api.osv.dev/v1/querybatch   (batch, up to 1000 queries)

No API key required.
"""
import asyncio
from typing import Any, Dict, List, Optional

import httpx

from app.core.logger import logger

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSV_API_BASE = "https://api.osv.dev/v1"
OSV_QUERY_URL = f"{OSV_API_BASE}/query"
OSV_BATCH_URL = f"{OSV_API_BASE}/querybatch"

# Maximum queries per batch request (OSV API limit)
OSV_BATCH_LIMIT = 1000

# HTTP timeout (seconds)
OSV_TIMEOUT = 30.0

# Map internal dependency types to OSV ecosystem names
ECOSYSTEM_MAP: Dict[str, str] = {
    "python": "PyPI",
    "poetry": "PyPI",
    "node": "npm",
    "npm": "npm",
    "go": "Go",
    "rust": "crates.io",
    "ruby": "RubyGems",
    "java": "Maven",
    "nuget": "NuGet",
    "php": "Packagist",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class Vulnerability:
    """Represents a single vulnerability found for a dependency."""

    __slots__ = (
        "vuln_id", "summary", "severity", "aliases",
        "affected_package", "affected_version", "fixed_version",
        "references", "database_specific",
    )

    def __init__(
        self,
        vuln_id: str,
        summary: str = "",
        severity: str = "UNKNOWN",
        aliases: Optional[List[str]] = None,
        affected_package: str = "",
        affected_version: str = "",
        fixed_version: str = "",
        references: Optional[List[str]] = None,
        database_specific: Optional[Dict[str, Any]] = None,
    ):
        self.vuln_id = vuln_id
        self.summary = summary
        self.severity = severity
        self.aliases = aliases or []
        self.affected_package = affected_package
        self.affected_version = affected_version
        self.fixed_version = fixed_version
        self.references = references or []
        self.database_specific = database_specific or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "summary": self.summary,
            "severity": self.severity,
            "aliases": self.aliases,
            "affected_package": self.affected_package,
            "affected_version": self.affected_version,
            "fixed_version": self.fixed_version,
            "references": self.references[:5],  # limit for payload size
        }


class VulnerabilityReport:
    """Aggregated vulnerability report for a set of dependencies."""

    __slots__ = (
        "total_dependencies", "vulnerable_count", "vulnerability_count",
        "critical_count", "high_count", "medium_count", "low_count",
        "vulnerabilities",
    )

    def __init__(self) -> None:
        self.total_dependencies: int = 0
        self.vulnerable_count: int = 0
        self.vulnerability_count: int = 0
        self.critical_count: int = 0
        self.high_count: int = 0
        self.medium_count: int = 0
        self.low_count: int = 0
        self.vulnerabilities: List[Vulnerability] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_dependencies": self.total_dependencies,
            "vulnerable_count": self.vulnerable_count,
            "vulnerability_count": self.vulnerability_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_version(version: str) -> str:
    """Strip leading operators from version strings (e.g. '^1.2.0' -> '1.2.0')."""
    return version.lstrip("^~>=<! ")


def _map_ecosystem(dep_type: str) -> Optional[str]:
    """Map an internal dependency type to an OSV ecosystem string."""
    return ECOSYSTEM_MAP.get(dep_type.lower())


def _extract_severity(vuln_data: Dict[str, Any]) -> str:
    """Extract the highest severity from an OSV vulnerability record.

    OSV uses the `database_specific.severity` field or CVSS vectors in
    `severity` array.  We try several locations and fall back to UNKNOWN.
    """
    # Try database_specific.severity (used by GitHub Advisory)
    db_specific = vuln_data.get("database_specific", {})
    if isinstance(db_specific, dict):
        sev = db_specific.get("severity", "")
        if sev and isinstance(sev, str):
            return sev.upper()

    # Try severity array with CVSS scores
    severity_list = vuln_data.get("severity", [])
    if isinstance(severity_list, list):
        for entry in severity_list:
            if isinstance(entry, dict):
                score_str = entry.get("score", "")
                # CVSS v3 vector contains /S: or score is numeric
                # Try to extract from type=CVSS_V3
                sev_type = entry.get("type", "")
                if sev_type == "CVSS_V3" and score_str:
                    # Parse base score from CVSS vector or numeric
                    try:
                        # Sometimes it's a full vector string
                        if "/" in score_str:
                            # Rough estimation from vector
                            return _severity_from_cvss_vector(score_str)
                        else:
                            base_score = float(score_str)
                            return _severity_from_cvss_score(base_score)
                    except (ValueError, TypeError):
                        pass

    # Try ecosystem-specific fields
    for affected in vuln_data.get("affected", []):
        eco_sev = affected.get("database_specific", {})
        if isinstance(eco_sev, dict):
            sev = eco_sev.get("severity") or eco_sev.get("cvss_severity", "")
            if sev and isinstance(sev, str):
                return sev.upper()

    return "UNKNOWN"


def _severity_from_cvss_score(score: float) -> str:
    """Convert a CVSS 3.x base score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _severity_from_cvss_vector(vector: str) -> str:
    """Rough severity estimation from a CVSS v3 vector string."""
    # Look for /S:H or /AV:N patterns to estimate severity
    vector_upper = vector.upper()
    # Simple heuristic: count attack complexity + scope + impact
    if "AV:N" in vector_upper and "AC:L" in vector_upper:
        if "C:H" in vector_upper or "I:H" in vector_upper:
            return "CRITICAL"
        return "HIGH"
    if "AV:N" in vector_upper:
        return "HIGH"
    if "AC:L" in vector_upper:
        return "MEDIUM"
    return "MEDIUM"


def _extract_fixed_version(vuln_data: Dict[str, Any], package_name: str) -> str:
    """Extract the fixed version for a specific package from OSV data."""
    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() == package_name.lower():
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        return fixed
    return ""


def _extract_references(vuln_data: Dict[str, Any]) -> List[str]:
    """Extract reference URLs from OSV vulnerability record."""
    refs = []
    for ref in vuln_data.get("references", []):
        url = ref.get("url", "")
        if url:
            refs.append(url)
    return refs


# ---------------------------------------------------------------------------
# Core API functions
# ---------------------------------------------------------------------------

async def query_single(
    package_name: str,
    version: str,
    ecosystem: str,
) -> List[Dict[str, Any]]:
    """Query OSV for vulnerabilities affecting a single package version.

    Args:
        package_name: Package name (e.g. "requests").
        version: Package version (e.g. "2.28.0").
        ecosystem: OSV ecosystem (e.g. "PyPI", "npm").

    Returns:
        List of raw OSV vulnerability dicts, or empty list on error.
    """
    payload: Dict[str, Any] = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
    }

    # Only include version if it's a concrete version (not "unspecified" or range)
    clean_version = _normalize_version(version)
    if clean_version and clean_version not in ("unspecified", "*", "latest"):
        payload["version"] = clean_version

    try:
        async with httpx.AsyncClient(timeout=OSV_TIMEOUT) as client:
            resp = await client.post(OSV_QUERY_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data.get("vulns", [])
    except httpx.HTTPStatusError as e:
        logger.warning("OSV query failed for %s@%s: HTTP %d", package_name, version, e.response.status_code)
        return []
    except Exception as e:
        logger.warning("OSV query failed for %s@%s: %s", package_name, version, str(e)[:100])
        return []


async def query_batch(
    dependencies: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Query OSV for vulnerabilities across multiple dependencies using batch API.

    Args:
        dependencies: List of dependency dicts with keys: name, version, type.

    Returns:
        Dict mapping "name@version" to list of raw OSV vulnerability dicts.
    """
    # Build batch queries
    queries: List[Dict[str, Any]] = []
    dep_keys: List[str] = []  # Track which key each query index maps to

    for dep in dependencies:
        name = dep.get("name", "")
        version = dep.get("version", "")
        dep_type = dep.get("type", "")

        ecosystem = _map_ecosystem(dep_type)
        if not ecosystem or not name:
            continue

        clean_version = _normalize_version(version)
        query: Dict[str, Any] = {
            "package": {
                "name": name,
                "ecosystem": ecosystem,
            },
        }
        if clean_version and clean_version not in ("unspecified", "*", "latest"):
            query["version"] = clean_version

        queries.append(query)
        dep_keys.append(f"{name}@{version}")

    if not queries:
        logger.info("OSV: No queryable dependencies (no recognized ecosystems)")
        return {}

    # Split into batches of OSV_BATCH_LIMIT
    results: Dict[str, List[Dict[str, Any]]] = {}
    for batch_start in range(0, len(queries), OSV_BATCH_LIMIT):
        batch_queries = queries[batch_start : batch_start + OSV_BATCH_LIMIT]
        batch_keys = dep_keys[batch_start : batch_start + OSV_BATCH_LIMIT]

        try:
            async with httpx.AsyncClient(timeout=OSV_TIMEOUT) as client:
                resp = await client.post(
                    OSV_BATCH_URL,
                    json={"queries": batch_queries},
                )
                resp.raise_for_status()
                data = resp.json()

                batch_results = data.get("results", [])
                for i, result in enumerate(batch_results):
                    if i < len(batch_keys):
                        vulns = result.get("vulns", [])
                        if vulns:
                            results[batch_keys[i]] = vulns

        except httpx.HTTPStatusError as e:
            logger.warning("OSV batch query failed: HTTP %d", e.response.status_code)
        except Exception as e:
            logger.warning("OSV batch query failed: %s", str(e)[:200])

    return results


# ---------------------------------------------------------------------------
# High-level scan function
# ---------------------------------------------------------------------------

async def scan_dependencies(
    dependencies: List[Dict[str, Any]],
) -> VulnerabilityReport:
    """Scan a list of dependencies for known vulnerabilities via OSV.

    This is the main entry point used by the scan executor and local scanner.

    Args:
        dependencies: List of dependency dicts with keys: name, version, type, file_source.
            Can also be Pydantic Dependency objects (have .name, .version, .type attributes).

    Returns:
        VulnerabilityReport with aggregated results.
    """
    report = VulnerabilityReport()

    # Normalize: accept both dicts and Pydantic objects
    dep_dicts: List[Dict[str, str]] = []
    for dep in dependencies:
        if isinstance(dep, dict):
            dep_dicts.append(dep)
        else:
            # Pydantic model
            dep_dicts.append({
                "name": getattr(dep, "name", ""),
                "version": getattr(dep, "version", ""),
                "type": getattr(dep, "type", ""),
                "file_source": getattr(dep, "file_source", ""),
            })

    report.total_dependencies = len(dep_dicts)

    if not dep_dicts:
        return report

    # Query OSV in batch
    logger.info("OSV: Querying vulnerabilities for %d dependencies...", len(dep_dicts))
    raw_results = await query_batch(dep_dicts)
    logger.info("OSV: Found vulnerabilities in %d packages", len(raw_results))

    # Process results
    seen_vulns: set = set()  # Deduplicate by vuln ID

    for dep_key, vuln_list in raw_results.items():
        parts = dep_key.split("@", 1)
        pkg_name = parts[0] if parts else dep_key
        pkg_version = parts[1] if len(parts) > 1 else ""

        report.vulnerable_count += 1

        for vuln_data in vuln_list:
            vuln_id = vuln_data.get("id", "UNKNOWN")
            if vuln_id in seen_vulns:
                continue
            seen_vulns.add(vuln_id)

            severity = _extract_severity(vuln_data)
            summary = vuln_data.get("summary", vuln_data.get("details", ""))[:300]
            aliases = vuln_data.get("aliases", [])
            fixed_version = _extract_fixed_version(vuln_data, pkg_name)
            references = _extract_references(vuln_data)

            vuln = Vulnerability(
                vuln_id=vuln_id,
                summary=summary,
                severity=severity,
                aliases=aliases,
                affected_package=pkg_name,
                affected_version=pkg_version,
                fixed_version=fixed_version,
                references=references,
            )
            report.vulnerabilities.append(vuln)
            report.vulnerability_count += 1

            # Count by severity
            if severity == "CRITICAL":
                report.critical_count += 1
            elif severity == "HIGH":
                report.high_count += 1
            elif severity == "MEDIUM":
                report.medium_count += 1
            elif severity == "LOW":
                report.low_count += 1

    logger.info(
        "OSV: Scan complete — %d vulnerabilities across %d packages "
        "(critical=%d, high=%d, medium=%d, low=%d)",
        report.vulnerability_count,
        report.vulnerable_count,
        report.critical_count,
        report.high_count,
        report.medium_count,
        report.low_count,
    )

    return report

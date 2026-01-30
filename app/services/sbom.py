"""SBOM (Software Bill of Materials) generation in SPDX and CycloneDX formats.

Generates standard SBOMs from dependency data—no external APIs or services required.
Supports CRA-SBOM-004: SBOM exportable in standard format (SPDX, CycloneDX).
"""
import re
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Literal, Union

from app.core.logger import logger
from app.schemas.requests import Dependency


def _sanitize_spdx_id(value: str) -> str:
    """Make a string safe for SPDX ID: alphanumeric, hyphen, period only."""
    return re.sub(r"[^a-zA-Z0-9.\-]", "-", value)[:50]


def _dep_to_dict(d: Union[Dependency, Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize Dependency or dict to {name, version, type, file_source}."""
    if isinstance(d, Dependency):
        return {"name": d.name, "version": d.version, "type": d.type, "file_source": d.file_source}
    return {
        "name": d.get("name", "unknown"),
        "version": d.get("version", ""),
        "type": d.get("type", "unknown"),
        "file_source": d.get("file_source", ""),
    }


def generate_spdx_json(
    dependencies: List[Union[Dependency, Dict[str, Any]]],
    *,
    name: str = "EURA SBOM",
    document_namespace: str | None = None,
    repo_name: str | None = None,
    commit_sha: str | None = None,
    tool_name: str = "EURA",
    tool_version: str = "2.0",
) -> Dict[str, Any]:
    """
    Generate an SPDX 2.3 JSON document from a list of dependencies.

    No external services required. Suitable for CRA-SBOM-004 (SPDX export).

    Args:
        dependencies: List of Dependency objects or dicts with name, version, type, file_source.
        name: Document name.
        document_namespace: Unique URI for the document (default: urn with UUID).
        repo_name: Optional repository identifier (e.g. owner/repo).
        commit_sha: Optional commit hash.
        tool_name: Creator tool name.
        tool_version: Creator tool version.

    Returns:
        SPDX 2.3 JSON document as a Python dict (serialize with json.dumps).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not document_namespace:
        document_namespace = f"https://eura.example.com/spdx/{uuid.uuid4()}"

    packages: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for dep in dependencies:
        d = _dep_to_dict(dep)
        pkg_id = f"SPDXRef-{_sanitize_spdx_id(d['name'])}-{_sanitize_spdx_id(d['version'] or 'no-version')}"
        if pkg_id in seen:
            continue
        seen.add(pkg_id)

        packages.append({
            "SPDXID": pkg_id,
            "name": d["name"],
            "versionInfo": d["version"] or "NOASSERTION",
            "downloadLocation": d["file_source"] or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "description": f"Package from {d['type']} manifest: {d['file_source']}" or "NOASSERTION",
        })

    doc: Dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": document_namespace,
        "creationInfo": {
            "created": now,
            "creators": [
                f"Tool: {tool_name}-{tool_version}",
                "Organization: EURA (EURA 2.0)",
            ],
            "licenseListVersion": "3.23",
        },
        "packages": packages,
    }

    if repo_name or commit_sha:
        doc["creationInfo"]["comment"] = f"Repository: {repo_name or 'N/A'}; Commit: {commit_sha or 'N/A'}"

    logger.debug("Generated SPDX document with %d packages", len(packages))
    return doc


def generate_cyclonedx_json(
    dependencies: List[Union[Dependency, Dict[str, Any]]],
    *,
    repo_name: str | None = None,
    commit_sha: str | None = None,
    tool_name: str = "EURA",
    tool_version: str = "2.0",
) -> Dict[str, Any]:
    """
    Generate a CycloneDX 1.5 JSON BOM from a list of dependencies.

    No external services required. Suitable for CRA-SBOM-004 (CycloneDX export).

    Args:
        dependencies: List of Dependency objects or dicts with name, version, type, file_source.
        repo_name: Optional repository identifier.
        commit_sha: Optional commit hash.
        tool_name: Tool name in metadata.
        tool_version: Tool version in metadata.

    Returns:
        CycloneDX 1.5 JSON BOM as a Python dict (serialize with json.dumps).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = f"urn:uuid:{uuid.uuid4()}"

    components: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for dep in dependencies:
        d = _dep_to_dict(dep)
        key = (d["name"], d["version"] or "")
        if key in seen:
            continue
        seen.add(key)

        purl = _build_purl(d)
        comp: Dict[str, Any] = {
            "type": "library",
            "name": d["name"],
            "version": d["version"] or None,
        }
        if purl:
            comp["purl"] = purl
        if d.get("file_source"):
            comp["description"] = f"From {d['type']} manifest: {d['file_source']}"
        components.append(comp)

    bom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "name": tool_name,
                    "version": tool_version,
                }
            ],
        },
        "components": components,
    }

    if repo_name or commit_sha:
        props = []
        if repo_name:
            props.append({"name": "eura:repo:name", "value": repo_name})
        if commit_sha:
            props.append({"name": "eura:repo:commit", "value": commit_sha})
        if props:
            bom["metadata"]["properties"] = props

    logger.debug("Generated CycloneDX BOM with %d components", len(components))
    return bom


def _build_purl(d: Dict[str, Any]) -> str:
    """Build package-url (purl) for CycloneDX component if possible."""
    name = d.get("name", "").strip()
    version = (d.get("version") or "").strip()
    if not name:
        return ""
    t = (d.get("type") or "generic").lower()
    # https://github.com/package-url/purl-spec
    if t in ("python", "pip"):
        return f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
    if t in ("node", "npm"):
        return f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}"
    if t == "poetry":
        return f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
    return ""


def generate_sbom(
    dependencies: List[Union[Dependency, Dict[str, Any]]],
    format: Literal["spdx", "cyclonedx"],
    *,
    name: str = "EURA SBOM",
    repo_name: str | None = None,
    commit_sha: str | None = None,
) -> Dict[str, Any]:
    """
    Generate SBOM in the requested format.

    Args:
        dependencies: List of dependencies (Dependency or dict).
        format: "spdx" or "cyclonedx".
        name: Document name (used for SPDX).
        repo_name: Optional repo identifier.
        commit_sha: Optional commit hash.

    Returns:
        SBOM as a Python dict (JSON-serializable).
    """
    if format == "spdx":
        return generate_spdx_json(
            dependencies,
            name=name,
            repo_name=repo_name,
            commit_sha=commit_sha,
        )
    if format == "cyclonedx":
        return generate_cyclonedx_json(
            dependencies,
            repo_name=repo_name,
            commit_sha=commit_sha,
        )
    raise ValueError(f"Unsupported SBOM format: {format}. Use 'spdx' or 'cyclonedx'.")

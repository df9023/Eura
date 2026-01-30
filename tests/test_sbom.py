"""Tests for SBOM (Software Bill of Materials) generation."""
import pytest
from app.services.sbom import (
    generate_spdx_json,
    generate_cyclonedx_json,
    generate_sbom,
)
from app.schemas.requests import Dependency


def test_generate_spdx_json_minimal():
    """SPDX document has required fields and packages."""
    deps = [
        {"name": "requests", "version": "2.28.0", "type": "python", "file_source": "requirements.txt"},
        {"name": "fastapi", "version": "0.104.0", "type": "python", "file_source": "requirements.txt"},
    ]
    doc = generate_spdx_json(deps, name="Test SBOM")
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["name"] == "Test SBOM"
    assert "documentNamespace" in doc
    assert "creationInfo" in doc
    assert doc["creationInfo"]["created"]
    assert len(doc["packages"]) == 2
    names = {p["name"] for p in doc["packages"]}
    assert names == {"requests", "fastapi"}


def test_generate_spdx_json_with_dependency_model():
    """SPDX accepts Dependency Pydantic models."""
    deps = [
        Dependency(name="pytest", version="7.0.0", type="python", file_source="pyproject.toml"),
    ]
    doc = generate_spdx_json(deps)
    assert len(doc["packages"]) == 1
    assert doc["packages"][0]["name"] == "pytest"
    assert doc["packages"][0]["versionInfo"] == "7.0.0"


def test_generate_cyclonedx_json_minimal():
    """CycloneDX BOM has required fields and components."""
    deps = [
        {"name": "express", "version": "4.18.0", "type": "node", "file_source": "package.json"},
    ]
    bom = generate_cyclonedx_json(deps)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert "serialNumber" in bom
    assert bom["metadata"]["tools"][0]["name"] == "EURA"
    assert len(bom["components"]) == 1
    assert bom["components"][0]["name"] == "express"
    assert bom["components"][0]["version"] == "4.18.0"
    assert bom["components"][0]["type"] == "library"


def test_generate_sbom_format_spdx():
    """generate_sbom with format=spdx returns SPDX document."""
    deps = [{"name": "foo", "version": "1.0", "type": "python", "file_source": ""}]
    out = generate_sbom(deps, "spdx")
    assert out["spdxVersion"] == "SPDX-2.3"
    assert "packages" in out


def test_generate_sbom_format_cyclonedx():
    """generate_sbom with format=cyclonedx returns CycloneDX BOM."""
    deps = [{"name": "bar", "version": "2.0", "type": "node", "file_source": ""}]
    out = generate_sbom(deps, "cyclonedx")
    assert out["bomFormat"] == "CycloneDX"
    assert "components" in out


def test_generate_sbom_invalid_format():
    """generate_sbom raises for unsupported format."""
    with pytest.raises(ValueError, match="Unsupported SBOM format"):
        generate_sbom([], "invalid")


def test_spdx_deduplicates_same_package():
    """SPDX deduplicates packages by SPDXID."""
    deps = [
        {"name": "requests", "version": "2.28.0", "type": "python", "file_source": "req.txt"},
        {"name": "requests", "version": "2.28.0", "type": "python", "file_source": "req2.txt"},
    ]
    doc = generate_spdx_json(deps)
    assert len(doc["packages"]) == 1

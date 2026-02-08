"""Dependency extraction from package manifest files.

Supported ecosystems:
  - Python: requirements.txt, pyproject.toml (Poetry)
  - Node.js: package.json
  - Java: pom.xml (Maven), build.gradle / build.gradle.kts (Gradle)
  - Go: go.mod
  - Rust: Cargo.toml
  - Ruby: Gemfile, *.gemspec
"""
import re
import json
import tomllib
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from app.core.logger import logger


# All manifest filenames we recognize (used by scanners for filtering)
MANIFEST_FILES = [
    "requirements.txt",
    "package.json",
    "pyproject.toml",
    "Pipfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
]


def extract_dependencies(file_path: str, content: str) -> List[Dict[str, str]]:
    """
    Extract dependencies from package manifest files using regex/parsing.
    
    Args:
        file_path: Path to the file
        content: File content as string
        
    Returns:
        List of dependency dictionaries with keys: name, version, type, file_source
    """
    dependencies: List[Dict[str, str]] = []
    file_lower = file_path.lower()
    basename = file_lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    
    try:
        # ----- Python -----
        if basename == "requirements.txt":
            deps = _parse_requirements_txt(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "python",
                    "file_source": file_path
                })
        
        elif basename == "package.json":
            deps = _parse_package_json(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "node",
                    "file_source": file_path
                })
        
        elif basename == "pyproject.toml":
            deps = _parse_pyproject_toml(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "poetry",
                    "file_source": file_path
                })

        # ----- Java -----
        elif basename == "pom.xml":
            deps = _parse_pom_xml(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "java",
                    "file_source": file_path
                })

        elif basename in ("build.gradle", "build.gradle.kts"):
            deps = _parse_build_gradle(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "java",
                    "file_source": file_path
                })

        # ----- Go -----
        elif basename == "go.mod":
            deps = _parse_go_mod(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "go",
                    "file_source": file_path
                })

        # ----- Rust -----
        elif basename == "cargo.toml":
            deps = _parse_cargo_toml(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "rust",
                    "file_source": file_path
                })

        # ----- Ruby -----
        elif basename == "gemfile":
            deps = _parse_gemfile(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "ruby",
                    "file_source": file_path
                })

        elif basename.endswith(".gemspec"):
            deps = _parse_gemspec(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "ruby",
                    "file_source": file_path
                })

        if dependencies:
            logger.debug("Extracted %d dependencies from %s", len(dependencies), file_path)
    
    except Exception as e:
        logger.warning("Failed to extract dependencies from %s: %s", file_path, str(e)[:200])
    
    return dependencies


def _parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    """Parse Python requirements.txt format.

    Handles:
      - ``package==1.0``, ``package>=1.0,<2``, ``package~=1.0``
      - ``package[extras]>=1.0`` (extras stripped from name)
      - ``package @ https://...`` (URL deps, version = URL)
      - ``-e ./local-package`` (editable installs, skipped)
      - ``;`` environment markers (stripped)
      - ``-r``, ``-f``, ``-i``, ``--`` option lines (skipped)
      - Line continuations with ``\\``
    """
    dependencies = []

    # Join line continuations
    content = content.replace("\\\n", "")

    for raw_line in content.split('\n'):
        line = raw_line.strip()

        # Skip empty, comments, option flags, editable installs
        if not line or line.startswith('#'):
            continue
        if line.startswith(('-r', '-f', '-i', '-c', '--', '-e')):
            continue

        # Strip inline comments
        line = line.split('#')[0].strip()
        if not line:
            continue

        # Strip environment markers: "package>=1.0 ; python_version<'3.8'"
        line = line.split(';')[0].strip()

        # Handle URL deps: "package @ https://..."
        if ' @ ' in line:
            parts = line.split(' @ ', 1)
            name = _clean_pkg_name(parts[0].strip())
            url = parts[1].strip()
            if name:
                dependencies.append({"name": name, "version": url})
            continue

        # Handle versioned: package[extras]==1.0, package>=1.0,<2
        if '==' in line:
            parts = line.split('==', 1)
            name = _clean_pkg_name(parts[0].strip())
            version = parts[1].split(',')[0].strip()
            if name:
                dependencies.append({"name": name, "version": version})
        elif any(op in line for op in ['>=', '<=', '>', '<', '~=', '!=']):
            match = re.match(r'^([a-zA-Z0-9_\-\.]+(?:\[[^\]]*\])?)', line)
            if match:
                name = _clean_pkg_name(match.group(1))
                version_match = re.search(r'[=~<>!]+(.+)', line)
                version = version_match.group(1).strip() if version_match else "unspecified"
                if name:
                    dependencies.append({"name": name, "version": version})
        else:
            name = _clean_pkg_name(line)
            if name:
                dependencies.append({"name": name, "version": "unspecified"})

    return dependencies


def _clean_pkg_name(raw: str) -> str:
    """Strip extras brackets from a package name: ``pkg[extra]`` -> ``pkg``."""
    return re.sub(r'\[.*?\]', '', raw).strip()


def _parse_package_json(content: str) -> List[Dict[str, str]]:
    """Parse Node.js package.json format."""
    dependencies = []
    
    try:
        data = json.loads(content)
        
        # Check dependencies, devDependencies, peerDependencies, optionalDependencies
        dep_sections = [
            ("dependencies", "node"),
            ("devDependencies", "node"),
            ("peerDependencies", "node"),
            ("optionalDependencies", "node")
        ]
        
        for section_name, dep_type in dep_sections:
            if section_name in data and isinstance(data[section_name], dict):
                for name, version_spec in data[section_name].items():
                    # Normalize version (remove ^, ~, etc.)
                    version = version_spec.strip() if isinstance(version_spec, str) else str(version_spec)
                    dependencies.append({"name": name, "version": version})
    
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse package.json as JSON: %s", str(e)[:100])
    
    return dependencies


def _parse_pyproject_toml(content: str) -> List[Dict[str, str]]:
    """Parse Python pyproject.toml using ``tomllib`` (stdlib).

    Supports:
      - PEP 621 ``[project.dependencies]`` and ``[project.optional-dependencies]``
      - Poetry ``[tool.poetry.dependencies]`` and ``[tool.poetry.group.*.dependencies]``
      - Poetry legacy ``[tool.poetry.dev-dependencies]``

    Properly handles multi-line values, inline tables, and nested structures.
    """
    dependencies = []

    try:
        data = tomllib.loads(content)
    except Exception as e:
        logger.warning("Failed to parse pyproject.toml: %s", str(e)[:100])
        return dependencies

    # --- PEP 621: [project] dependencies ---
    project = data.get("project", {})
    for dep_str in project.get("dependencies", []):
        if isinstance(dep_str, str):
            parsed = _parse_pep508(dep_str)
            if parsed:
                dependencies.append(parsed)

    for _group, deps in project.get("optional-dependencies", {}).items():
        if isinstance(deps, list):
            for dep_str in deps:
                if isinstance(dep_str, str):
                    parsed = _parse_pep508(dep_str)
                    if parsed:
                        dependencies.append(parsed)

    # --- Poetry: [tool.poetry.dependencies] ---
    poetry = data.get("tool", {}).get("poetry", {})
    for name, spec in poetry.get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        version = _extract_poetry_version(spec)
        dependencies.append({"name": name, "version": version})

    # Poetry dev-dependencies (legacy)
    for name, spec in poetry.get("dev-dependencies", {}).items():
        version = _extract_poetry_version(spec)
        dependencies.append({"name": name, "version": version})

    # Poetry group dependencies: [tool.poetry.group.<name>.dependencies]
    for _group_name, group_data in poetry.get("group", {}).items():
        if isinstance(group_data, dict):
            for name, spec in group_data.get("dependencies", {}).items():
                version = _extract_poetry_version(spec)
                dependencies.append({"name": name, "version": version})

    return dependencies


def _parse_pep508(dep_str: str) -> Optional[Dict[str, str]]:
    """Parse a PEP 508 dependency string like ``requests>=2.28,<3`` or ``black[jupyter]``."""
    # Strip environment markers (everything after ";")
    dep_str = dep_str.split(";")[0].strip()
    # Strip extras: name[extra1,extra2]
    match = re.match(r'^([a-zA-Z0-9_\-\.]+)(?:\[[^\]]*\])?\s*(.*)', dep_str)
    if not match:
        return None
    name = match.group(1).strip()
    version_spec = match.group(2).strip()
    if not name:
        return None
    version = version_spec if version_spec else "unspecified"
    return {"name": name, "version": version}


def _extract_poetry_version(spec) -> str:
    """Extract version from a Poetry dependency spec (string, dict, or list)."""
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return spec.get("version", "unspecified")
    return "unspecified"


# ---------------------------------------------------------------------------
# Java: pom.xml (Maven)
# ---------------------------------------------------------------------------

def _parse_pom_xml(content: str) -> List[Dict[str, str]]:
    """Parse Maven pom.xml for ``<dependency>`` elements.

    Handles XML namespaces properly by detecting the default namespace and
    using it in all element lookups.  Also searches ``<dependencyManagement>``
    and ``<profile>`` dependency sections.

    Property placeholders (``${...}``) are preserved as-is since resolution
    would require the full Maven settings / parent POM chain.
    """
    dependencies = []

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        logger.warning("Failed to parse pom.xml: %s", str(e)[:100])
        return dependencies

    # Detect default namespace (Maven POM uses xmlns="http://maven.apache.org/POM/4.0.0")
    ns = ""
    tag = root.tag
    if tag.startswith("{"):
        ns = tag[1:tag.index("}")]

    prefix = f"{{{ns}}}" if ns else ""

    # Search all <dependency> elements anywhere in the document
    # This covers: <dependencies>, <dependencyManagement>, and <profiles>
    for dep in root.iter(f"{prefix}dependency"):
        group_id = (dep.findtext(f"{prefix}groupId") or "").strip()
        artifact_id = (dep.findtext(f"{prefix}artifactId") or "").strip()
        version = (dep.findtext(f"{prefix}version") or "unspecified").strip()

        if artifact_id:
            name = f"{group_id}:{artifact_id}" if group_id else artifact_id
            dependencies.append({"name": name, "version": version})

    return dependencies


# ---------------------------------------------------------------------------
# Java: build.gradle / build.gradle.kts (Gradle)
# ---------------------------------------------------------------------------

def _parse_build_gradle(content: str) -> List[Dict[str, str]]:
    """Parse Gradle build files for dependency declarations.

    Handles common patterns in both Groovy and Kotlin DSL:

      - ``implementation 'group:artifact:version'``
      - ``implementation "group:artifact:version"``
      - ``implementation("group:artifact:version")``
      - ``api``, ``compileOnly``, ``runtimeOnly``, ``testImplementation``, etc.
      - ``group:artifact`` without version (version managed externally)
      - Kotlin ``platform()`` and ``enforcedPlatform()`` dependencies

    **Known limitations** (Gradle is a full Groovy/Kotlin DSL):

      - Variable interpolation (``"$group:$artifact:$version"``) is not resolved
      - ``project()`` dependencies are skipped (internal module refs)
      - Version catalog references (``libs.some.dep``) are not resolved
      - ``buildSrc`` plugin dependencies are not parsed
      - Multi-line dependency declarations are not supported
    """
    dependencies = []

    _CONFIGS = (
        r'implementation|api|compile|compileOnly|runtimeOnly|'
        r'testImplementation|testCompile|testCompileOnly|testRuntimeOnly|'
        r'annotationProcessor|kapt|ksp|classpath|'
        r'developmentOnly|compileOnlyApi|debugImplementation|releaseImplementation'
    )

    # Pattern 1: group:artifact:version (3-part GAV)
    gav3 = re.compile(
        rf'(?:{_CONFIGS})'
        r'\s*[\(\s]*["\']'
        r'([^"\'$]+):([^"\'$]+):([^"\'$]+)'  # group:artifact:version
        r'["\']',
        re.IGNORECASE,
    )

    # Pattern 2: group:artifact without version (managed dependency)
    gav2 = re.compile(
        rf'(?:{_CONFIGS})'
        r'\s*[\(\s]*["\']'
        r'([^"\'$:]+):([^"\'$:]+)'  # group:artifact (no version)
        r'["\']',
        re.IGNORECASE,
    )

    # Pattern 3: platform("group:artifact:version") or enforcedPlatform(...)
    platform_pat = re.compile(
        r'(?:enforced)?[Pp]latform\s*\(\s*["\']'
        r'([^"\'$]+):([^"\'$]+):([^"\'$]+)'
        r'["\']',
        re.IGNORECASE,
    )

    seen = set()

    for m in gav3.finditer(content):
        group_id = m.group(1).strip()
        artifact_id = m.group(2).strip()
        version = m.group(3).strip()
        key = f"{group_id}:{artifact_id}"
        if key not in seen:
            seen.add(key)
            dependencies.append({"name": key, "version": version})

    for m in gav2.finditer(content):
        group_id = m.group(1).strip()
        artifact_id = m.group(2).strip()
        key = f"{group_id}:{artifact_id}"
        if key not in seen:
            seen.add(key)
            dependencies.append({"name": key, "version": "unspecified"})

    for m in platform_pat.finditer(content):
        group_id = m.group(1).strip()
        artifact_id = m.group(2).strip()
        version = m.group(3).strip()
        key = f"{group_id}:{artifact_id}"
        if key not in seen:
            seen.add(key)
            dependencies.append({"name": key, "version": version})

    return dependencies


# ---------------------------------------------------------------------------
# Go: go.mod
# ---------------------------------------------------------------------------

def _parse_go_mod(content: str) -> List[Dict[str, str]]:
    """Parse Go go.mod for ``require`` directives.

    Handles both single-line and block syntax::

        require golang.org/x/text v0.3.7
        require (
            github.com/gin-gonic/gin v1.9.1
            github.com/go-sql-driver/mysql v1.7.0 // indirect
        )
    """
    dependencies = []
    in_require_block = False

    for line in content.split("\n"):
        stripped = line.strip()

        # Skip comments and empty lines
        if not stripped or stripped.startswith("//"):
            continue

        # Detect require block
        if stripped.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and stripped == ")":
            in_require_block = False
            continue

        # Single-line require
        if stripped.startswith("require ") and "(" not in stripped:
            parts = stripped[len("require "):].strip().split()
            if len(parts) >= 2:
                module = parts[0]
                version = parts[1].lstrip("v")
                dependencies.append({"name": module, "version": version})
            continue

        # Inside require block
        if in_require_block:
            # Remove inline comments
            clean = stripped.split("//")[0].strip()
            parts = clean.split()
            if len(parts) >= 2:
                module = parts[0]
                version = parts[1].lstrip("v")
                dependencies.append({"name": module, "version": version})

    return dependencies


# ---------------------------------------------------------------------------
# Rust: Cargo.toml
# ---------------------------------------------------------------------------

def _parse_cargo_toml(content: str) -> List[Dict[str, str]]:
    """Parse Rust Cargo.toml using ``tomllib`` (stdlib).

    Reads ``[dependencies]``, ``[dev-dependencies]``, ``[build-dependencies]``,
    and ``[target.'cfg(...)'.dependencies]`` sections.  Properly handles inline
    tables, multi-line values, workspace inheritance, git/path deps.
    """
    dependencies = []

    try:
        data = tomllib.loads(content)
    except Exception as e:
        logger.warning("Failed to parse Cargo.toml: %s", str(e)[:100])
        return dependencies

    dep_sections = ["dependencies", "dev-dependencies", "build-dependencies"]

    for section in dep_sections:
        _collect_cargo_deps(data.get(section, {}), dependencies)

    # Target-specific dependencies: [target.'cfg(...)'.dependencies]
    for _target, target_data in data.get("target", {}).items():
        if isinstance(target_data, dict):
            for section in dep_sections:
                _collect_cargo_deps(target_data.get(section, {}), dependencies)

    # Workspace dependencies: [workspace.dependencies]
    workspace = data.get("workspace", {})
    _collect_cargo_deps(workspace.get("dependencies", {}), dependencies)

    return dependencies


def _collect_cargo_deps(
    section: Dict, out: List[Dict[str, str]]
) -> None:
    """Extract name/version pairs from a Cargo dependency section dict."""
    if not isinstance(section, dict):
        return
    for name, spec in section.items():
        if isinstance(spec, str):
            out.append({"name": name, "version": spec})
        elif isinstance(spec, dict):
            version = spec.get("version", "unspecified")
            out.append({"name": name, "version": version})
        else:
            out.append({"name": name, "version": "unspecified"})


# ---------------------------------------------------------------------------
# Ruby: Gemfile
# ---------------------------------------------------------------------------

def _parse_gemfile(content: str) -> List[Dict[str, str]]:
    """Parse Ruby Gemfile for ``gem`` declarations.

    Handles::

        gem 'rails', '~> 7.0'
        gem "sidekiq", ">= 6.0", "< 8"
        gem 'puma'
        gem 'pg', group: :production
        gem 'nokogiri', '~> 1.15', platforms: [:mri, :mingw]

    Skips gems sourced from ``git:`` or ``path:`` (local/dev only).
    """
    dependencies = []

    for raw_line in content.split("\n"):
        line = raw_line.strip()

        # Skip comments, empty, source/ruby/group directives
        if not line or line.startswith("#"):
            continue

        # Must start with "gem "
        match = re.match(r"""gem\s+['"]([^'"]+)['"](.*)""", line, re.IGNORECASE)
        if not match:
            continue

        name = match.group(1).strip()
        rest = match.group(2).strip()

        # Skip git/path source gems (not published packages)
        if re.search(r'(?:git|path)\s*:', rest):
            continue

        # Extract version constraint(s) — first quoted string after name
        version_match = re.match(r"""\s*,\s*['"]([^'"]+)['"]""", rest)
        version = version_match.group(1).strip() if version_match else "unspecified"

        dependencies.append({"name": name, "version": version})

    return dependencies


# ---------------------------------------------------------------------------
# Ruby: *.gemspec
# ---------------------------------------------------------------------------

def _parse_gemspec(content: str) -> List[Dict[str, str]]:
    """Parse Ruby gemspec for dependency declarations.

    Handles::

        spec.add_dependency 'rake', '~> 13.0'
        s.add_runtime_dependency "rspec", ">= 3.0"
        s.add_development_dependency "rubocop"
        spec.add_dependency("concurrent-ruby", "~> 1.2")   # parens syntax
    """
    dependencies = []

    # Matches both space-separated and parenthesized forms:
    #   .add_dependency 'name', 'version'
    #   .add_dependency('name', 'version')
    pattern = re.compile(
        r"""\.add_(?:runtime_|development_)?dependency"""
        r"""[\s(]+['"]([^'"]+)['"]"""             # name
        r"""(?:\s*,\s*['"]([^'"]+)['"])?""",      # optional version
        re.IGNORECASE,
    )

    for m in pattern.finditer(content):
        name = m.group(1).strip()
        version = (m.group(2) or "unspecified").strip()
        dependencies.append({"name": name, "version": version})

    return dependencies


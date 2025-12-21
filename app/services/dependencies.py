"""Dependency extraction from package manifest files."""
import re
import json
from typing import List, Dict, Optional
from app.core.logger import logger


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
    
    try:
        # Python requirements.txt
        if file_lower.endswith("requirements.txt"):
            deps = _parse_requirements_txt(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "python",
                    "file_source": file_path
                })
        
        # Node.js package.json
        elif file_lower.endswith("package.json"):
            deps = _parse_package_json(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "node",
                    "file_source": file_path
                })
        
        # Python Poetry pyproject.toml
        elif file_lower.endswith("pyproject.toml"):
            deps = _parse_pyproject_toml(content)
            for dep in deps:
                dependencies.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": "poetry",
                    "file_source": file_path
                })
        
        if dependencies:
            logger.debug("Extracted %d dependencies from %s", len(dependencies), file_path)
    
    except Exception as e:
        logger.warning("Failed to extract dependencies from %s: %s", file_path, str(e)[:200])
    
    return dependencies


def _parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    """Parse Python requirements.txt format."""
    dependencies = []
    
    # Pattern: package==version, package>=version, package~=version, package, etc.
    # Also handles: package @ git+https://..., -r other_file.txt, etc.
    pattern = re.compile(
        r'^([a-zA-Z0-9_\-\.]+)'  # Package name
        r'(?:\s*[=~<>!]+.*?)?'    # Version specifier (optional)
        r'(?:\s*#.*)?$',          # Comments (optional)
        re.MULTILINE
    )
    
    for line in content.split('\n'):
        line = line.strip()
        
        # Skip comments, empty lines, and includes
        if not line or line.startswith('#') or line.startswith('-r') or line.startswith('-f'):
            continue
        
        # Handle: package==version, package>=version, etc.
        if '==' in line:
            parts = line.split('==', 1)
            name = parts[0].strip()
            version = parts[1].split('#')[0].strip()  # Remove comments
            dependencies.append({"name": name, "version": version})
        elif any(op in line for op in ['>=', '<=', '>', '<', '~=', '!=']):
            # Extract name before operator
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)', line)
            if match:
                name = match.group(1)
                # Extract version after operator
                version_match = re.search(r'[=~<>!]+(.+?)(?:\s|#|$)', line)
                version = version_match.group(1).strip() if version_match else "unspecified"
                dependencies.append({"name": name, "version": version})
        else:
            # Just package name, no version
            name = line.split('#')[0].strip()
            if name:
                dependencies.append({"name": name, "version": "unspecified"})
    
    return dependencies


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
    """Parse Python Poetry pyproject.toml format."""
    dependencies = []
    
    try:
        # Simple TOML parsing for [tool.poetry.dependencies] section
        # This is a basic parser - for production, consider using tomli or tomllib
        
        in_dependencies = False
        in_dev_dependencies = False
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Check for section headers
            if line == '[tool.poetry.dependencies]':
                in_dependencies = True
                in_dev_dependencies = False
                continue
            elif line == '[tool.poetry.group.dev.dependencies]' or line == '[tool.poetry.dev-dependencies]':
                in_dev_dependencies = True
                in_dependencies = False
                continue
            elif line.startswith('[') and line.endswith(']'):
                # New section, stop parsing dependencies
                in_dependencies = False
                in_dev_dependencies = False
                continue
            
            # Parse dependency lines
            if (in_dependencies or in_dev_dependencies) and '=' in line and not line.startswith('#'):
                # Format: "package" = "version" or package = "version"
                line = line.split('#')[0].strip()  # Remove comments
                
                # Match: "package" = "version" or package = "version"
                match = re.match(r'["\']?([^"\']+)["\']?\s*=\s*["\']?([^"\']+)["\']?', line)
                if match:
                    name = match.group(1).strip()
                    version = match.group(2).strip()
                    
                    # Skip python version specification
                    if name.lower() != 'python':
                        dependencies.append({"name": name, "version": version})
    
    except Exception as e:
        logger.warning("Failed to parse pyproject.toml: %s", str(e)[:100])
    
    return dependencies


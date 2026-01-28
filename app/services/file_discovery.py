"""File discovery service with prioritization for repository scanning."""
from typing import List, Set, Optional
from app.core.logger import logger


class FileDiscoveryService:
    """Service for discovering and prioritizing files in a repository."""
    
    # Manifest files (highest priority)
    MANIFEST_PATTERNS = {
        "requirements.txt", "package.json", "pyproject.toml", "Pipfile",
        "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
        "yarn.lock", "package-lock.json", "pnpm-lock.yaml", "go.sum", "Cargo.lock",
        "composer.json", "Gemfile", "Gemfile.lock", "Podfile", "Podfile.lock",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml"
    }
    
    # Configuration files (high priority)
    CONFIG_PATTERNS = {
        ".env", ".env.example", ".env.local", ".env.production",
        "config.json", "config.yaml", "config.yml", "config.toml",
        ".gitignore", ".dockerignore", ".editorconfig",
        "tsconfig.json", "jsconfig.json", "webpack.config.js",
        "next.config.js", "vite.config.js", "rollup.config.js",
        ".eslintrc", ".eslintrc.json", ".prettierrc", ".prettierrc.json",
        "nginx.conf", "apache.conf", ".htaccess"
    }
    
    # Documentation files (medium-high priority)
    DOC_PATTERNS = {
        "README.md", "README.txt", "README.rst", "README",
        "SECURITY.md", "SECURITY.txt", "SECURITY",
        "CHANGELOG.md", "CHANGELOG.txt", "CHANGELOG",
        "LICENSE", "LICENSE.txt", "LICENSE.md",
        "CONTRIBUTING.md", "CONTRIBUTING.txt",
        "CODE_OF_CONDUCT.md", "CODE_OF_CONDUCT.txt",
        "docs/", "documentation/", ".github/", ".gitlab/"
    }
    
    # Source code extensions (medium priority)
    CODE_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
        ".cpp", ".c", ".h", ".hpp", ".cs", ".php", ".rb", ".swift",
        ".kt", ".scala", ".clj", ".sh", ".bash", ".zsh"
    }
    
    def __init__(self, skip_dirs: Optional[Set[str]] = None):
        """
        Initialize file discovery service.
        
        Args:
            skip_dirs: Set of directory names to skip (defaults to standard skip list)
        """
        self.skip_dirs = skip_dirs or {
            "node_modules", ".git", "dist", "build", ".next", ".nuxt",
            ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
            "coverage", ".coverage", "target", ".idea", ".vscode"
        }
    
    def prioritize_files(self, files: List[str]) -> List[str]:
        """
        Prioritize files for scanning based on importance.
        
        Priority order:
        1. Manifest files (package.json, requirements.txt, etc.)
        2. Configuration files (.env, config files)
        3. Documentation files (README, SECURITY.md, etc.)
        4. Source code files
        5. Other files
        
        Args:
            files: List of file paths
        
        Returns:
            Prioritized list of file paths
        """
        prioritized: List[str] = []
        manifests: List[str] = []
        configs: List[str] = []
        docs: List[str] = []
        code: List[str] = []
        other: List[str] = []
        
        for file_path in files:
            file_lower = file_path.lower()
            file_name = file_path.split("/")[-1].lower()
            
            # Check if it's a manifest file
            if (file_name in self.MANIFEST_PATTERNS or 
                any(file_lower.endswith(f"/{pattern}") for pattern in self.MANIFEST_PATTERNS)):
                manifests.append(file_path)
            # Check if it's a config file
            elif (file_name in self.CONFIG_PATTERNS or
                  any(file_lower.endswith(f"/{pattern}") for pattern in self.CONFIG_PATTERNS) or
                  any(file_lower.startswith(pattern) for pattern in self.CONFIG_PATTERNS if "/" in pattern)):
                configs.append(file_path)
            # Check if it's a documentation file
            elif (file_name in self.DOC_PATTERNS or
                  any(file_lower.startswith(pattern) for pattern in self.DOC_PATTERNS if "/" in pattern)):
                docs.append(file_path)
            # Check if it's source code
            elif any(file_lower.endswith(ext) for ext in self.CODE_EXTENSIONS):
                code.append(file_path)
            else:
                other.append(file_path)
        
        # Combine in priority order
        prioritized.extend(manifests)
        prioritized.extend(configs)
        prioritized.extend(docs)
        prioritized.extend(code)
        prioritized.extend(other)
        
        logger.debug(
            "File prioritization: manifests=%d, configs=%d, docs=%d, code=%d, other=%d",
            len(manifests), len(configs), len(docs), len(code), len(other)
        )
        
        return prioritized
    
    def discover_files(
        self,
        repo_files: List[str],
        max_files: int = 120,
        prioritize: bool = True
    ) -> List[str]:
        """
        Discover and optionally prioritize files from repository file list.
        
        Args:
            repo_files: List of all file paths from repository
            max_files: Maximum number of files to return
            prioritize: Whether to prioritize files (default: True)
        
        Returns:
            List of file paths, optionally prioritized and limited to max_files
        """
        # Filter out skipped directories
        filtered_files = [
            f for f in repo_files
            if not any(part in self.skip_dirs for part in f.split("/"))
        ]
        
        # Prioritize if requested
        if prioritize:
            filtered_files = self.prioritize_files(filtered_files)
        
        # Limit to max_files
        result = filtered_files[:max_files]
        
        logger.info(
            "File discovery: total=%d, filtered=%d, prioritized=%s, returning=%d",
            len(repo_files), len(filtered_files), prioritize, len(result)
        )
        
        return result

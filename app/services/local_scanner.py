"""Local Scanner Service - Scan local directories for CRA/AI Act compliance.

This service enables offline scanning without GitHub or API server by:
1. Walking local directory tree
2. Reading file contents from disk
3. Calling existing services (FileDiscovery, Dependencies, Secrets, AI)
4. Evaluating rules with RuleEvaluationEngine
5. Generating verdict with VerdictGenerator
"""
import os
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.core.logger import logger
from app.services.file_discovery import FileDiscoveryService
from app.services.dependencies import extract_dependencies
from app.services.secret_detector import SecretDetector
from app.services.ai_detector import AIDetector
from app.services.rule_engine import RuleEvaluationEngine, SignalBuilder
from app.services.compliance_evaluation import VerdictGenerator, ComplianceScorer
from app.services.compliance import load_rules_db
from app.models.domain import Finding, Evidence
from app.schemas.requests import Dependency


class LocalScanner:
    """Scans local directories for CRA and AI Act compliance."""
    
    # Directories to skip
    SKIP_DIRS = {
        "node_modules", ".git", "dist", "build", ".next", ".nuxt",
        ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
        "coverage", ".coverage", "target", ".idea", ".vscode",
        ".tox", ".nox", "htmlcov", ".hypothesis", ".ruff_cache",
        "eggs", ".eggs", "*.egg-info", "wheels"
    }
    
    # Binary file extensions to skip content reading
    BINARY_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
        ".zip", ".tar", ".gz", ".rar", ".7z",
        ".exe", ".dll", ".so", ".dylib",
        ".pyc", ".pyo", ".class",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".ttf", ".otf", ".woff", ".woff2",
        ".h5", ".hdf5", ".pkl", ".pickle", ".onnx", ".pb", ".pt", ".pth",
        ".safetensors", ".gguf", ".ggml", ".bin", ".weights"
    }
    
    def __init__(self, max_files: int = 500, max_file_size: int = 1024 * 1024):
        """
        Initialize local scanner.
        
        Args:
            max_files: Maximum number of files to scan
            max_file_size: Maximum file size to read (default 1MB)
        """
        self.max_files = max_files
        self.max_file_size = max_file_size
        
        # Initialize services
        self.file_discovery = FileDiscoveryService()
        self.secret_detector = SecretDetector()
        self.ai_detector = AIDetector()
        self.rule_engine = RuleEvaluationEngine()
        self.verdict_generator = VerdictGenerator()
        self.compliance_scorer = ComplianceScorer()
    
    def _walk_directory(self, root_path: str) -> List[str]:
        """
        Walk directory and return list of file paths (relative to root).
        
        Args:
            root_path: Root directory path
            
        Returns:
            List of relative file paths
        """
        files = []
        root = Path(root_path).resolve()
        
        for dirpath, dirnames, filenames in os.walk(root):
            # Filter out skip directories (modify in-place to skip subdirs)
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            
            for filename in filenames:
                if len(files) >= self.max_files:
                    break
                
                full_path = Path(dirpath) / filename
                # Use forward slashes for consistency
                relative_path = str(full_path.relative_to(root)).replace("\\", "/")
                files.append(relative_path)
            
            if len(files) >= self.max_files:
                break
        
        logger.info("Found %d files in %s", len(files), root_path)
        return files
    
    def _read_file_content(self, root_path: str, relative_path: str) -> Optional[str]:
        """
        Read file content from disk.
        
        Args:
            root_path: Root directory path
            relative_path: Relative path to file
            
        Returns:
            File content as string, or None if unreadable
        """
        full_path = Path(root_path) / relative_path
        
        # Skip binary files
        if any(relative_path.lower().endswith(ext) for ext in self.BINARY_EXTENSIONS):
            return None
        
        try:
            # Check file size
            if full_path.stat().st_size > self.max_file_size:
                logger.debug("Skipping large file: %s", relative_path)
                return None
            
            # Try to read as text
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            logger.debug("Could not read %s: %s", relative_path, str(e)[:50])
            return None
    
    async def scan_directory(
        self,
        path: str,
        environment: str = "production",
        regulations: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Scan a local directory for CRA/AI Act compliance.
        
        Args:
            path: Path to directory to scan
            environment: Deployment environment (dev/staging/production/eu-production)
            regulations: Optional list of regulations to evaluate
            
        Returns:
            Scan result dictionary with verdict, scores, rule results
        """
        scan_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        logger.info("Starting local scan: path=%s, environment=%s", path, environment)
        
        # 1. Walk directory and get file list
        all_files = self._walk_directory(path)
        
        # 2. Prioritize files using FileDiscoveryService
        prioritized_files = self.file_discovery.discover_files(
            all_files, 
            max_files=self.max_files,
            prioritize=True
        )
        
        # 3. Read file contents
        file_contents: Dict[str, str] = {}
        for file_path in prioritized_files:
            content = self._read_file_content(path, file_path)
            if content is not None:
                file_contents[file_path] = content
        
        logger.info("Read content from %d files", len(file_contents))
        
        # 4. Extract dependencies from manifest files
        dependencies: List[Dict[str, str]] = []
        manifest_files = ["requirements.txt", "package.json", "pyproject.toml", "Pipfile"]
        
        for file_path, content in file_contents.items():
            if any(file_path.endswith(m) or file_path.endswith(m.lower()) for m in manifest_files):
                deps = extract_dependencies(file_path, content)
                dependencies.extend(deps)
        
        logger.info("Extracted %d dependencies", len(dependencies))
        
        # 5. Detect secrets
        secrets_detected: List[Dict[str, Any]] = []
        for file_path, content in file_contents.items():
            secrets = self.secret_detector.detect_secrets(file_path, content)
            secrets_detected.extend(secrets)
        
        # Convert high-confidence secrets to findings
        findings: List[Finding] = []
        for idx, secret in enumerate(secrets_detected):
            if secret.get("confidence", 0) >= 0.7:
                file_path = secret.get("file_path", "unknown")
                line_num = secret.get("line_number", 0)
                secret_type = secret.get("type", "secret")
                
                findings.append(Finding(
                    id=f"SECRET-{idx+1}",
                    title=f"Potential {secret_type} detected",
                    severity="high",
                    confidence=secret.get("confidence", 0.7),
                    summary=f"Found potential {secret_type} in {file_path}",
                    details=f"Line {line_num}: Detected pattern matching {secret_type}",
                    evidence=[Evidence(
                        file=file_path,
                        lines=str(line_num),
                        snippet=secret.get("snippet", "")[:100]
                    )],
                    recommendation="Remove hardcoded secret and use environment variables",
                    category="secrets"
                ))
        
        logger.info("Detected %d potential secrets (%d high-confidence)", 
                   len(secrets_detected), len(findings))
        
        # 6. Detect AI/ML components
        ai_components = self.ai_detector.detect_ai_components(
            file_paths=prioritized_files,
            dependencies=dependencies,
            file_contents=file_contents
        )
        
        if ai_components.get("has_ai"):
            logger.info("AI components detected: frameworks=%s", 
                       ai_components.get("frameworks", []))
        
        # 7. Convert dependencies to Dependency objects for rule engine
        dep_objects = [
            Dependency(
                name=d.get("name", ""),
                version=d.get("version", ""),
                type=d.get("type", "unknown"),
                file_source=d.get("file_source", "")
            )
            for d in dependencies
        ]
        
        # 7b. OSV vulnerability scan
        vulnerability_report = None
        if dependencies:
            try:
                from app.services.osv import scan_dependencies as osv_scan
                logger.info("Running OSV vulnerability scan for %d dependencies...", len(dependencies))
                osv_result = await osv_scan(dependencies)
                vulnerability_report = osv_result.to_dict()
                
                if osv_result.vulnerability_count > 0:
                    logger.warning(
                        "OSV: Found %d vulnerabilities in %d packages (critical=%d, high=%d)",
                        osv_result.vulnerability_count,
                        osv_result.vulnerable_count,
                        osv_result.critical_count,
                        osv_result.high_count,
                    )
                else:
                    logger.info("OSV: No known vulnerabilities found")
            except Exception as e:
                logger.warning("OSV vulnerability scan failed (non-fatal): %s", str(e)[:200])
        
        # 8. Create a local file reader function for rule engine
        # Note: Signature matches compliance.py which calls read_file_func(repo, file_path)
        def local_read_file(repo: Any, file_path: str) -> Optional[str]:
            # repo is ignored for local scanning - we read from file_contents dict
            return file_contents.get(file_path)
        
        # 9. Evaluate rules
        compliance_report = await self.rule_engine.evaluate_repo(
            findings=findings,
            dependencies=dep_objects,
            repo_files=prioritized_files,
            regulations=regulations,
            ai_components=ai_components,
            repo=None,  # No GitHub repo
            read_file_func=local_read_file,
            vulnerability_report=vulnerability_report,
        )
        
        rule_results = compliance_report.get("rule_results", [])
        logger.info("Evaluated %d rules", len(rule_results))
        
        # 10. Generate verdict
        rules_db = load_rules_db()
        verdict = self.verdict_generator.generate_verdict(
            rule_results=rule_results,
            environment=environment,
            rules_db=rules_db
        )
        
        # 11. Calculate compliance scores
        scores = self.compliance_scorer.calculate_per_regulation_scores(
            rule_results=rule_results,
            rules_db=rules_db
        )
        
        # Convert ComplianceScore to dict
        scores_dict = {}
        for reg, score in scores.items():
            scores_dict[reg] = {
                "score": score.score,
                "passed": score.passed,
                "failed": score.failed,
                "unknown": score.unknown,
                "not_applicable": score.not_applicable
            }
        
        # 12. Build result
        end_time = datetime.utcnow()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        
        result = {
            "scan_id": scan_id,
            "path": str(Path(path).resolve()),
            "environment": environment,
            "evaluated_at": end_time.isoformat() + "Z",
            "duration_ms": duration_ms,
            
            # Verdict
            "verdict": verdict.verdict,
            "blocking_rules": verdict.blocking_rules,
            "verdict_reason": verdict.reason,
            
            # Scores
            "compliance_scores": scores_dict,
            
            # Stats
            "files_scanned": len(prioritized_files),
            "files_read": len(file_contents),
            "dependency_count": len(dependencies),
            "dependencies": dependencies,
            
            # AI detection
            "ai_components": ai_components,
            
            # Vulnerability scan
            "vulnerability_report": vulnerability_report,
            
            # Secrets
            "secrets_detected": secrets_detected,
            
            # Rule results
            "rule_results": rule_results,
            "rule_summary": {
                "total": compliance_report.get("total_rules", 0),
                "passed": compliance_report.get("passed", 0),
                "failed": compliance_report.get("failed", 0),
                "unknown": compliance_report.get("unknown", 0),
                "not_applicable": compliance_report.get("not_applicable", 0)
            }
        }
        
        logger.info(
            "Local scan complete: verdict=%s, score=%s, duration=%dms",
            verdict.verdict,
            {k: v.get("score", 0) for k, v in scores_dict.items()},
            duration_ms
        )
        
        return result

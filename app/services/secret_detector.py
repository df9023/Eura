"""Secret detection service for finding exposed credentials in code."""
import re
from typing import List, Dict, Optional
from app.core.logger import logger


class SecretDetector:
    """Detects secrets, API keys, passwords, and tokens in code files."""
    
    # Common secret patterns
    SECRET_PATTERNS = [
        # API Keys
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "api_key"),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "secret_key"),
        
        # AWS
        (r'AKIA[0-9A-Z]{16}', "aws_access_key"),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', "aws_secret_key"),
        
        # GitHub
        (r'ghp_[a-zA-Z0-9]{36}', "github_personal_token"),
        (r'gho_[a-zA-Z0-9]{36}', "github_oauth_token"),
        (r'ghu_[a-zA-Z0-9]{36}', "github_user_token"),
        (r'ghs_[a-zA-Z0-9]{36}', "github_app_token"),
        (r'ghr_[a-zA-Z0-9]{36}', "github_refresh_token"),
        
        # Generic tokens
        (r'(?i)(token|bearer)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{32,})["\']?', "generic_token"),
        
        # Passwords
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?', "password"),
        
        # Database credentials
        (r'(?i)(database[_-]?password|db[_-]?pass|db[_-]?password)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?', "db_password"),
        (r'(?i)(mongodb[_-]?uri|mongo[_-]?connection)\s*[=:]\s*["\']?(mongodb://[^\s"\']+)["\']?', "mongodb_uri"),
        (r'(?i)(postgres[_-]?uri|postgresql[_-]?uri|postgres[_-]?connection)\s*[=:]\s*["\']?(postgres://[^\s"\']+)["\']?', "postgres_uri"),
        
        # Private keys
        (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "private_key"),
        
        # JWT tokens (base64-like)
        (r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', "jwt_token"),
        
        # OAuth
        (r'(?i)(oauth[_-]?token|oauth[_-]?secret)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "oauth_token"),
        
        # Slack tokens
        (r'xox[baprs]-[0-9a-zA-Z-]{10,}', "slack_token"),
        
        # Stripe keys
        (r'sk_live_[0-9a-zA-Z]{24,}', "stripe_secret_key"),
        (r'pk_live_[0-9a-zA-Z]{24,}', "stripe_publishable_key"),
        
        # Email/SMTP
        (r'(?i)(smtp[_-]?password|email[_-]?password|mail[_-]?password)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?', "email_password"),
    ]
    
    # False positive patterns (things that look like secrets but aren't)
    FALSE_POSITIVE_PATTERNS = [
        r'example[_-]?key',
        r'test[_-]?key',
        r'dummy[_-]?key',
        r'placeholder',
        r'your[_-]?.*[_-]?here',
        r'xxx+',
        r'<.*>',  # HTML/XML tags
    ]
    
    def __init__(self):
        """Initialize secret detector."""
        self.compiled_patterns = [
            (re.compile(pattern, re.MULTILINE | re.IGNORECASE), secret_type)
            for pattern, secret_type in self.SECRET_PATTERNS
        ]
        self.false_positive_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.FALSE_POSITIVE_PATTERNS
        ]
    
    def detect_secrets(self, file_path: str, content: str) -> List[Dict[str, any]]:
        """
        Detect secrets in file content.
        
        Args:
            file_path: Path to the file being analyzed
            content: File content as string
        
        Returns:
            List of secret findings with keys:
            - type: Secret type (e.g., "api_key", "password")
            - line_number: Line number where secret was found
            - snippet: Code snippet containing the secret (masked)
            - confidence: Confidence score (0.0-1.0)
        """
        findings: List[Dict[str, any]] = []
        
        if not content:
            return findings
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            # Check each pattern
            for pattern, secret_type in self.compiled_patterns:
                matches = pattern.finditer(line)
                
                for match in matches:
                    # Extract the matched secret (group 2 if exists, else group 0)
                    secret_value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
                    
                    # Check for false positives
                    if self._is_false_positive(line, secret_value):
                        continue
                    
                    # Mask the secret in snippet
                    masked_snippet = self._mask_secret(line, secret_value)
                    
                    # Calculate confidence based on pattern and context
                    confidence = self._calculate_confidence(secret_type, line, secret_value)
                    
                    findings.append({
                        "type": secret_type,
                        "line_number": line_num,
                        "snippet": masked_snippet.strip(),
                        "confidence": confidence,
                        "file_path": file_path
                    })
        
        if findings:
            logger.debug("Detected %d potential secrets in %s", len(findings), file_path)
        
        return findings
    
    def _is_false_positive(self, line: str, secret_value: str) -> bool:
        """Check if a detected secret is likely a false positive."""
        line_lower = line.lower()
        value_lower = secret_value.lower()
        
        # Check against false positive patterns
        for fp_pattern in self.false_positive_patterns:
            if fp_pattern.search(line_lower) or fp_pattern.search(value_lower):
                return True
        
        # Check for common placeholder values
        placeholder_indicators = ["example", "test", "dummy", "placeholder", "your", "xxx", "changeme"]
        if any(indicator in value_lower for indicator in placeholder_indicators):
            return True
        
        return False
    
    def _mask_secret(self, line: str, secret_value: str) -> str:
        """Mask secret value in code snippet for safe logging."""
        if len(secret_value) <= 8:
            return line.replace(secret_value, "***")
        else:
            # Show first 4 and last 4 chars, mask the middle
            masked = secret_value[:4] + "*" * min(len(secret_value) - 8, 20) + secret_value[-4:]
            return line.replace(secret_value, masked)
    
    def _calculate_confidence(self, secret_type: str, line: str, secret_value: str) -> float:
        """
        Calculate confidence score for detected secret.
        
        Higher confidence for:
        - Longer secrets
        - Secrets in assignment contexts
        - Specific patterns (AWS keys, GitHub tokens, etc.)
        """
        confidence = 0.5  # Base confidence
        
        # Longer secrets are more likely to be real
        if len(secret_value) >= 32:
            confidence += 0.2
        elif len(secret_value) >= 20:
            confidence += 0.1
        
        # Specific patterns have higher confidence
        high_confidence_types = ["aws_access_key", "github_personal_token", "private_key", "jwt_token"]
        if secret_type in high_confidence_types:
            confidence += 0.2
        
        # Assignment context increases confidence
        if "=" in line or ":" in line:
            confidence += 0.1
        
        # Clamp to 0.0-1.0
        return min(1.0, max(0.0, confidence))

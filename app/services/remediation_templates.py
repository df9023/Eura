"""Remediation Template Generator — produces ready-to-commit compliance documents.

Generates Markdown templates for common CRA compliance files that appear in
rule evaluations:  SECURITY.md, CHANGELOG.md, SUPPORT.md, CONTRIBUTING.md,
and security configuration guides.  Templates are parameterized by project
metadata (name, contact, etc.) so users can immediately fill gaps flagged by
EURA's 35 CRA rules.

PRD Reference: Section 3.8 — Compliance Artifacts; Remediation Guidance.
"""
from datetime import datetime, timezone
from typing import Optional

from app.core.logger import logger


# ---------------------------------------------------------------------------
# SECURITY.md — CRA-BASE-001, CRA-VULN-001, CRA-BASE-014
# ---------------------------------------------------------------------------

def generate_security_md(
    *,
    project_name: str = "This Project",
    contact_email: str = "security@example.com",
    pgp_key_url: Optional[str] = None,
    response_hours: int = 48,
    disclosure_days: int = 90,
) -> str:
    """Generate a CRA-compliant SECURITY.md with coordinated vulnerability disclosure.

    Satisfies: CRA-BASE-001, CRA-VULN-001, CRA-VULN-002, CRA-BASE-014.

    Args:
        project_name: Name of the project.
        contact_email: Security team email.
        pgp_key_url: Optional URL to PGP public key for encrypted reports.
        response_hours: Hours to acknowledge receipt of vulnerability report.
        disclosure_days: Days before coordinated public disclosure.

    Returns:
        Markdown content for SECURITY.md.
    """
    pgp_section = ""
    if pgp_key_url:
        pgp_section = f"""
## Encrypted Communication

For sensitive reports, encrypt your email using our PGP key:
- **PGP Key**: [{pgp_key_url}]({pgp_key_url})
"""

    template = f"""# Security Policy

## Reporting a Vulnerability

**{project_name}** takes security seriously. If you discover a vulnerability,
please report it responsibly using the process below.

### How to Report

- **Email**: [{contact_email}](mailto:{contact_email})
- **Subject line**: `[SECURITY] Brief description of the issue`
- **Do NOT** open a public GitHub issue for security vulnerabilities.
{pgp_section}
## Response Timeline

| Action | Timeline |
|--------|----------|
| Acknowledge receipt | Within **{response_hours} hours** |
| Initial assessment | Within **5 business days** |
| Fix development | Severity-dependent (see below) |
| Coordinated disclosure | **{disclosure_days} days** after report |

### Patch SLA by Severity

| Severity | Target Patch Time |
|----------|-------------------|
| Critical | 24-72 hours |
| High | 7 days |
| Medium | 30 days |
| Low | Next scheduled release |

## Scope

The following are **in scope** for vulnerability reports:

- The {project_name} application code
- Dependencies shipped with the project
- Configuration and deployment files
- Authentication and authorization mechanisms

The following are **out of scope**:

- Third-party services not maintained by this project
- Social engineering attacks
- Denial of service attacks

## Safe Harbour

We will not take legal action against researchers who:

- Act in good faith and follow this disclosure policy
- Avoid accessing or modifying data belonging to others
- Report vulnerabilities promptly and do not exploit them
- Allow reasonable time for remediation before public disclosure

## Security Updates

Security advisories are published via:

- [GitHub Security Advisories](../../security/advisories)
- Release notes in [CHANGELOG.md](CHANGELOG.md)

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | ✅ Active support |
| Previous major | ⚠️ Security fixes only |
| Older versions | ❌ End of life |

---

*This security policy follows [ISO 29147](https://www.iso.org/standard/72311.html)
(Vulnerability Disclosure) and [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)
(security.txt) guidelines, in compliance with the EU Cyber Resilience Act (CRA)
Article 11.*
"""
    return template.strip() + "\n"


# ---------------------------------------------------------------------------
# CHANGELOG.md — CRA-BASE-005, CRA-BASE-017, CRA-VULN-004
# ---------------------------------------------------------------------------

def generate_changelog_md(
    *,
    project_name: str = "This Project",
    initial_version: str = "1.0.0",
) -> str:
    """Generate a Keep-a-Changelog format CHANGELOG.md.

    Satisfies: CRA-BASE-005, CRA-BASE-017, CRA-VULN-004, CRA-LIFE-003.

    Args:
        project_name: Name of the project.
        initial_version: Version to seed the first entry.

    Returns:
        Markdown content for CHANGELOG.md.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    template = f"""# Changelog

All notable changes to **{project_name}** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- _Describe new features here_

### Changed
- _Describe changes to existing features_

### Fixed
- _Describe bug fixes_

### Security
- _Describe security-related changes and vulnerability fixes_

## [{initial_version}] - {today}

### Added
- Initial release of {project_name}

---

*Maintaining a changelog is required by the EU Cyber Resilience Act (CRA)
Article 11 for update and patch management transparency.*
"""
    return template.strip() + "\n"


# ---------------------------------------------------------------------------
# SUPPORT.md — CRA-LIFE-001, CRA-BASE-011
# ---------------------------------------------------------------------------

def generate_support_md(
    *,
    project_name: str = "This Project",
    support_email: str = "support@example.com",
    support_years: int = 5,
) -> str:
    """Generate a SUPPORT.md with lifecycle and EOL policy.

    Satisfies: CRA-LIFE-001, CRA-LIFE-002, CRA-BASE-011.

    Args:
        project_name: Name of the project.
        support_email: Support contact email.
        support_years: Number of years of committed support.

    Returns:
        Markdown content for SUPPORT.md.
    """
    current_year = datetime.now(timezone.utc).year
    eol_year = current_year + support_years

    template = f"""# Support Policy

## {project_name} — Lifecycle & Support

### Support Period

| Period | Duration |
|--------|----------|
| **Active development** | Current release |
| **Security support** | {support_years} years (until {eol_year}) |
| **End of Life (EOL)** | After {eol_year} |

### What "Supported" Means

- **Active development**: New features, bug fixes, and security patches
- **Security support**: Security patches only; no new features
- **EOL**: No further updates; users should migrate to a successor or fork

### Getting Help

| Channel | Link |
|---------|------|
| Bug reports | [GitHub Issues](../../issues) |
| Security issues | See [SECURITY.md](SECURITY.md) |
| General questions | [{support_email}](mailto:{support_email}) |
| Documentation | [docs/](docs/) |

### Maintenance Commitment

- Dependencies are updated regularly (automated via Dependabot/Renovate)
- Security vulnerabilities are patched within SLA (see SECURITY.md)
- Breaking changes follow our deprecation policy (see CHANGELOG.md)

### End-of-Life Notification

When {project_name} approaches EOL:

1. **6 months before**: Public announcement with migration guidance
2. **3 months before**: Final feature release; security-only mode begins
3. **At EOL**: Repository archived; README updated with successor info

---

*This support policy complies with the EU Cyber Resilience Act (CRA)
Article 12 (Product Lifecycle Management), which requires manufacturers to
determine and document the expected product lifetime and support period.*
"""
    return template.strip() + "\n"


# ---------------------------------------------------------------------------
# CONTRIBUTING.md — CRA-VULN-003
# ---------------------------------------------------------------------------

def generate_contributing_md(
    *,
    project_name: str = "This Project",
) -> str:
    """Generate a CONTRIBUTING.md with security bug reporting guidance.

    Satisfies: CRA-VULN-003.

    Args:
        project_name: Name of the project.

    Returns:
        Markdown content for CONTRIBUTING.md.
    """
    template = f"""# Contributing to {project_name}

Thank you for your interest in contributing! This document provides guidelines
for contributing to {project_name}.

## How to Contribute

### Reporting Bugs

1. **Search existing issues** to avoid duplicates
2. **Use the bug report template** when creating a new issue
3. Include: steps to reproduce, expected behavior, actual behavior, environment

### Security Vulnerabilities

> **Do NOT report security vulnerabilities via public GitHub issues.**
>
> Please follow our [Security Policy](SECURITY.md) for responsible disclosure.

### Feature Requests

1. Open a **Feature Request** issue using the template
2. Describe the use case and expected behavior
3. Discuss in the issue before starting implementation

### Pull Requests

1. Fork the repository and create a feature branch
2. Follow the code style of the project
3. Write or update tests for your changes
4. Update documentation as needed
5. Submit a pull request with a clear description

## Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/{project_name.lower().replace(' ', '-')}.git

# Install dependencies
pip install -r requirements.txt  # or npm install

# Run tests
pytest tests/ -v  # or npm test
```

## Code of Conduct

Please be respectful and constructive in all interactions. We follow the
[Contributor Covenant](https://www.contributor-covenant.org/) code of conduct.

---

*This project follows coordinated vulnerability disclosure practices in
compliance with the EU Cyber Resilience Act (CRA) Article 11.*
"""
    return template.strip() + "\n"


# ---------------------------------------------------------------------------
# docs/security-configuration.md — CRA-DOC-001
# ---------------------------------------------------------------------------

def generate_security_config_guide(
    *,
    project_name: str = "This Project",
) -> str:
    """Generate a security configuration guide for end users.

    Satisfies: CRA-DOC-001, CRA-SEC-004.

    Args:
        project_name: Name of the project.

    Returns:
        Markdown content for docs/security-configuration.md.
    """
    template = f"""# Security Configuration Guide

## {project_name} — Secure Configuration

This guide helps you configure {project_name} securely for production use.

### 1. Environment Variables

Store all secrets in environment variables, **never in code**:

```bash
# .env (DO NOT commit this file)
SECRET_KEY=<generate-a-strong-random-key>
DATABASE_URL=postgresql://user:pass@host:5432/db
API_KEY=<your-api-key>
```

Ensure `.env` is listed in `.gitignore`.

### 2. Authentication

- Enable authentication for all API endpoints
- Use strong passwords (12+ characters, mixed case, numbers, symbols)
- Enable MFA/2FA where available
- Rotate API keys regularly (every 90 days recommended)

### 3. Network Security

- Use HTTPS/TLS 1.2+ for all communications
- Configure firewall rules to restrict access
- Use a reverse proxy (nginx, Caddy) in production
- Disable debug mode and verbose error messages

### 4. Logging

- Enable security event logging
- Do NOT log sensitive data (passwords, tokens, PII)
- Set log level to `WARNING` or `ERROR` in production
- Forward logs to a centralized logging system (ELK, Datadog, etc.)

### 5. Dependencies

- Keep all dependencies up to date
- Use lockfiles for reproducible builds
- Run `pip audit` / `npm audit` regularly
- Enable automated dependency updates (Dependabot/Renovate)

### 6. Container Security (if applicable)

- Run containers as non-root user
- Use minimal base images (Alpine, distroless)
- Scan images for vulnerabilities
- Don't store secrets in Docker images

### 7. Hardening Checklist

- [ ] All secrets in environment variables
- [ ] HTTPS enabled with TLS 1.2+
- [ ] Debug mode disabled
- [ ] Authentication enabled
- [ ] Rate limiting configured
- [ ] Error messages don't leak internal details
- [ ] Logging configured (no sensitive data)
- [ ] Dependencies up to date
- [ ] `.env` in `.gitignore`
- [ ] Container runs as non-root (if applicable)

---

*This guide supports compliance with the EU Cyber Resilience Act (CRA)
Article 10 (Security by Design) and Article 13 (Technical Documentation).*
"""
    return template.strip() + "\n"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

TEMPLATE_GENERATORS = {
    "security-md": generate_security_md,
    "changelog-md": generate_changelog_md,
    "support-md": generate_support_md,
    "contributing-md": generate_contributing_md,
    "security-config": generate_security_config_guide,
}

TEMPLATE_FILENAMES = {
    "security-md": "SECURITY.md",
    "changelog-md": "CHANGELOG.md",
    "support-md": "SUPPORT.md",
    "contributing-md": "CONTRIBUTING.md",
    "security-config": "docs/security-configuration.md",
}

TEMPLATE_RULES_MAP = {
    "security-md": ["CRA-BASE-001", "CRA-VULN-001", "CRA-VULN-002", "CRA-BASE-014"],
    "changelog-md": ["CRA-BASE-005", "CRA-BASE-017", "CRA-VULN-004", "CRA-LIFE-003"],
    "support-md": ["CRA-LIFE-001", "CRA-LIFE-002", "CRA-BASE-011"],
    "contributing-md": ["CRA-VULN-003"],
    "security-config": ["CRA-DOC-001", "CRA-SEC-004"],
}


def list_available_templates():
    """List all available remediation templates with metadata."""
    return [
        {
            "template_id": tid,
            "filename": TEMPLATE_FILENAMES[tid],
            "addresses_rules": TEMPLATE_RULES_MAP.get(tid, []),
            "description": TEMPLATE_GENERATORS[tid].__doc__.split("\n")[0] if TEMPLATE_GENERATORS[tid].__doc__ else "",
        }
        for tid in TEMPLATE_GENERATORS
    ]

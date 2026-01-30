#!/usr/bin/env python3
"""
EURA CLI - Local Compliance Scanner

Scan local folders for CRA and AI Act compliance without GitHub or API server.

Usage:
    python -m cli.eura_cli scan ./my-project
    python -m cli.eura_cli scan . --environment production --format json
    python -m cli.eura_cli scan ./path --output report.json
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional


def print_banner():
    """Print EURA banner."""
    print("""
===============================================================
                    EURA Compliance Scanner
              CRA & AI Act Local Compliance Check
===============================================================
""")


def print_pretty_result(result: dict, path: str):
    """Print scan result in human-readable format."""
    verdict = result.get("verdict", "UNKNOWN")
    
    # Verdict banner
    if verdict == "SHIP_ALLOWED":
        print("\n[PASS] VERDICT: SHIP_ALLOWED")
    else:
        print("\n[FAIL] VERDICT: SHIP_BLOCKED")
    
    print(f"\nPath: {path}")
    print(f"Environment: {result.get('environment', 'N/A')}")
    print(f"Files scanned: {result.get('files_scanned', 0)}")
    print(f"Dependencies found: {result.get('dependency_count', 0)}")
    
    # Scores
    scores = result.get("compliance_scores", {})
    print("\n[SCORES] Compliance Scores:")
    for regulation, score_data in scores.items():
        if isinstance(score_data, dict):
            score = score_data.get("score", 0)
            passed = score_data.get("passed", 0)
            failed = score_data.get("failed", 0)
            print(f"   {regulation}: {score:.1f}/100 ({passed} passed, {failed} failed)")
        else:
            print(f"   {regulation}: N/A")
    
    # AI Detection
    ai_components = result.get("ai_components", {})
    if ai_components.get("has_ai"):
        print("\n[AI] AI/ML Detected:")
        print(f"   Frameworks: {', '.join(ai_components.get('frameworks', [])) or 'None'}")
        print(f"   Model files: {len(ai_components.get('model_files', []))}")
        print(f"   Confidence: {ai_components.get('confidence', 0):.0%}")
    else:
        print("\n[AI] AI/ML: Not detected")
    
    # Rule results summary
    rule_results = result.get("rule_results", [])
    passed = [r for r in rule_results if r.get("status") == "PASS"]
    failed = [r for r in rule_results if r.get("status") == "FAIL"]
    unknown = [r for r in rule_results if r.get("status") == "UNKNOWN"]
    not_applicable = [r for r in rule_results if r.get("status") == "NOT_APPLICABLE"]
    
    print(f"\n[RULES] Rules: {len(passed)} passed, {len(failed)} failed, {len(unknown)} unknown, {len(not_applicable)} N/A")
    
    # Failed rules
    if failed:
        print("\n[FAILED] Failed Rules:")
        for rule in failed[:10]:  # Show first 10
            rule_id = rule.get("rule_id", "UNKNOWN")
            reason = rule.get("reason", "No reason provided")
            print(f"   - {rule_id}: {reason[:60]}...")
        if len(failed) > 10:
            print(f"   ... and {len(failed) - 10} more")
    
    # Blocking rules
    blocking_rules = result.get("blocking_rules", [])
    if blocking_rules:
        print("\n[BLOCKING] Blocking Rules (causing SHIP_BLOCKED):")
        for rule_id in blocking_rules:
            print(f"   - {rule_id}")
    
    # Secrets warning
    secrets = result.get("secrets_detected", [])
    if secrets:
        print(f"\n[WARNING] Secrets Detected: {len(secrets)} potential secrets found!")
        for secret in secrets[:3]:
            print(f"   - {secret.get('type', 'unknown')} in {secret.get('file_path', 'unknown')}")
    
    print("\n" + "=" * 65)


async def run_scan(path: str, environment: str, output_format: str, output_file: Optional[str]):
    """Run local scan and output results."""
    # Import here to avoid circular imports
    from app.services.local_scanner import LocalScanner
    
    scanner = LocalScanner()
    
    print(f"Scanning: {path}")
    print(f"Environment: {environment}")
    print("...")
    
    result = await scanner.scan_directory(path, environment=environment)
    
    if output_format == "json":
        json_output = json.dumps(result, indent=2, default=str)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"\nResults written to: {output_file}")
        else:
            print(json_output)
    else:
        # Pretty format
        print_pretty_result(result, path)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\nJSON results also saved to: {output_file}")
    
    # Return exit code based on verdict
    return 0 if result.get("verdict") == "SHIP_ALLOWED" else 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="eura",
        description="EURA Compliance Scanner - Check CRA and AI Act compliance locally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m cli.eura_cli scan .
  python -m cli.eura_cli scan ./my-project --environment production
  python -m cli.eura_cli scan . --format json --output report.json
  python -m cli.eura_cli scan . --environment dev --format pretty
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a local directory for compliance"
    )
    scan_parser.add_argument(
        "path",
        help="Path to directory to scan"
    )
    scan_parser.add_argument(
        "--environment", "-e",
        default="production",
        choices=["dev", "staging", "production", "eu-production"],
        help="Deployment environment (affects which rules block shipping)"
    )
    scan_parser.add_argument(
        "--format", "-f",
        default="pretty",
        choices=["json", "pretty"],
        help="Output format (default: pretty)"
    )
    scan_parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path (optional)"
    )
    
    # Version
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="EURA CLI 2.0"
    )
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    if args.command == "scan":
        # Validate path
        path = Path(args.path).resolve()
        if not path.exists():
            print(f"Error: Path does not exist: {path}")
            sys.exit(1)
        if not path.is_dir():
            print(f"Error: Path is not a directory: {path}")
            sys.exit(1)
        
        print_banner()
        
        # Run async scan
        exit_code = asyncio.run(run_scan(
            str(path),
            args.environment,
            args.format,
            args.output
        ))
        sys.exit(exit_code)


if __name__ == "__main__":
    main()

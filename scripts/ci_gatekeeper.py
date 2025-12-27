#!/usr/bin/env python3
"""
EURA CI/CD Gatekeeper Script

Simulates a CI/CD pipeline step that calls the Phase 0 API contract
and blocks deployment if verdict is SHIP_BLOCKED.

Usage:
    python scripts/ci_gatekeeper.py --repo_url owner/repo --environment production
    python scripts/ci_gatekeeper.py --repo_url https://github.com/owner/repo --environment staging
"""
import argparse
import sys
import requests
from typing import Dict, Any, Optional


def print_banner(text: str, color: str = "white"):
    """Print a banner with color (using ANSI codes)."""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "reset": "\033[0m"
    }
    
    width = 80
    border = "=" * width
    padding = " " * ((width - len(text) - 2) // 2)
    
    print(f"\n{colors.get(color, '')}{border}")
    print(f"{padding}{text}{padding}")
    print(f"{border}{colors['reset']}\n")


def call_scan_api(repo_url: str, environment: str, installation_id: Optional[int] = None, base_url: str = "http://localhost:8000") -> Dict[str, Any]:
    """
    Call the EURA v1 scan API.
    
    Args:
        repo_url: Repository URL or identifier
        environment: Deployment environment
        installation_id: Optional GitHub App installation ID
        base_url: Base URL of the API server
    
    Returns:
        JSON response as dictionary
    
    Raises:
        SystemExit: If API call fails (exits with code 1)
    """
    url = f"{base_url}/v1/scans/run"
    
    payload = {
        "repo_url": repo_url,
        "environment": environment
    }
    
    if installation_id:
        payload["installation_id"] = installation_id
    
    try:
        print(f"📡 Calling EURA API: {url}")
        response = requests.post(url, json=payload, timeout=300)  # 5 minute timeout for scan
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code >= 500:
            print_banner("❌ EURA API SERVER ERROR", "red")
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text[:500]}")
            print("\n⚠️  Failing closed: Deployment blocked due to API error.")
            sys.exit(1)
        else:
            print_banner("❌ EURA API CLIENT ERROR", "red")
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text[:500]}")
            print("\n⚠️  Failing closed: Deployment blocked due to API error.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print_banner("❌ EURA API UNAVAILABLE", "red")
        print("Could not connect to EURA API at", url)
        print("Ensure the backend server is running: uvicorn app.main:app --reload")
        print("\n⚠️  Failing closed: Deployment blocked due to API unavailability.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print_banner("❌ EURA API TIMEOUT", "red")
        print("API request timed out after 5 minutes.")
        print("\n⚠️  Failing closed: Deployment blocked due to API timeout.")
        sys.exit(1)
    except Exception as e:
        print_banner("❌ EURA API ERROR", "red")
        print(f"Unexpected error: {str(e)}")
        print("\n⚠️  Failing closed: Deployment blocked due to API error.")
        sys.exit(1)


def validate_response(response: Dict[str, Any]) -> None:
    """Validate that response has required Phase 0 contract fields."""
    required_fields = ["verdict", "scan_id", "repo_url", "environment", "evaluated_at", "rule_results", "evidence_refs"]
    
    missing = [field for field in required_fields if field not in response]
    if missing:
        print_banner("❌ INVALID API RESPONSE", "red")
        print(f"Missing required fields: {', '.join(missing)}")
        print("Response does not match Phase 0 contract (ScanResultV1).")
        print("\n⚠️  Failing closed: Deployment blocked due to invalid response.")
        sys.exit(1)
    
    if response["verdict"] not in ["SHIP_ALLOWED", "SHIP_BLOCKED"]:
        print_banner("❌ INVALID VERDICT", "red")
        print(f"Invalid verdict value: {response['verdict']}")
        print("Expected: SHIP_ALLOWED or SHIP_BLOCKED")
        print("\n⚠️  Failing closed: Deployment blocked due to invalid response.")
        sys.exit(1)


def main():
    """Main gatekeeper logic."""
    parser = argparse.ArgumentParser(
        description="EURA CI/CD Gatekeeper - Blocks deployment if compliance check fails",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/ci_gatekeeper.py --repo_url owner/repo --environment production
  python scripts/ci_gatekeeper.py --repo_url https://github.com/owner/repo --environment staging --installation_id 12345
  python scripts/ci_gatekeeper.py --repo_url owner/repo --environment production --api_url http://api.eura.com
        """
    )
    
    parser.add_argument(
        "--repo_url",
        required=True,
        help="Repository URL or identifier (e.g., 'owner/repo' or 'https://github.com/owner/repo')"
    )
    
    parser.add_argument(
        "--environment",
        default="production",
        choices=["dev", "staging", "production", "eu-production"],
        help="Deployment environment (default: production)"
    )
    
    parser.add_argument(
        "--installation_id",
        type=int,
        help="GitHub App installation ID (required for private repos)"
    )
    
    parser.add_argument(
        "--api_url",
        default="http://localhost:8000",
        help="Base URL of EURA API (default: http://localhost:8000)"
    )
    
    args = parser.parse_args()
    
    # Print scan initiation message
    print(f"🚀 EURA Security Gate: Scanning {args.repo_url} for {args.environment}...")
    print(f"   API Endpoint: {args.api_url}/v1/scans/run")
    if args.installation_id:
        print(f"   Installation ID: {args.installation_id}")
    print()
    
    # Call API
    response = call_scan_api(
        repo_url=args.repo_url,
        environment=args.environment,
        installation_id=args.installation_id,
        base_url=args.api_url
    )
    
    # Validate response structure
    validate_response(response)
    
    verdict = response["verdict"]
    blocking_rules = response.get("blocking_rules", [])
    advisory_findings = response.get("advisory_findings", [])
    rule_results = response.get("rule_results", [])
    
    # Handle SHIP_BLOCKED
    if verdict == "SHIP_BLOCKED":
        print_banner("❌ DEPLOYMENT BLOCKED", "red")
        
        print("The following compliance rules are blocking deployment:\n")
        
        if blocking_rules:
            for rule_id in blocking_rules:
                # Find the rule result for details
                rule_result = next((r for r in rule_results if r["rule_id"] == rule_id), None)
                if rule_result:
                    print(f"  ❌ {rule_id}: {rule_result.get('title', rule_id)}")
                    print(f"     Status: {rule_result.get('status', 'FAIL')}")
                    reason = rule_result.get('evidence', {}).get('reason', 'No reason provided')
                    print(f"     Reason: {reason}")
                    print()
                else:
                    print(f"  ❌ {rule_id}")
                    print()
        else:
            print("  (No specific blocking rules listed in response)\n")
        
        print("⚠️  Deployment cannot proceed until compliance issues are resolved.")
        print("   Review the blocking rules above and address the failures.")
        print()
        
        sys.exit(1)
    
    # Handle SHIP_ALLOWED
    elif verdict == "SHIP_ALLOWED":
        print_banner("✅ GATE PASSED", "green")
        
        # Show rule summary
        passed_count = sum(1 for r in rule_results if r.get("status") == "PASS")
        failed_count = sum(1 for r in rule_results if r.get("status") == "FAIL")
        not_applicable_count = sum(1 for r in rule_results if r.get("status") == "NOT_APPLICABLE")
        
        print(f"Compliance Summary:")
        print(f"  ✅ Passed: {passed_count}")
        if failed_count > 0:
            print(f"  ❌ Failed: {failed_count} (non-blocking)")
        print(f"  ⚪ Not Applicable: {not_applicable_count}")
        print()
        
        # Show advisory findings as warnings
        if advisory_findings:
            print("⚠️  Advisory Findings (non-blocking recommendations):\n")
            for i, finding in enumerate(advisory_findings, 1):
                category = finding.get("category", "other")
                message = finding.get("message", "No message")
                file_path = finding.get("file_path")
                line_start = finding.get("line_start")
                suggested_fix = finding.get("suggested_fix")
                
                print(f"  [{i}] {category.upper()}: {message}")
                if file_path:
                    location = f"{file_path}"
                    if line_start:
                        location += f":{line_start}"
                    print(f"      Location: {location}")
                if suggested_fix:
                    print(f"      Suggestion: {suggested_fix}")
                print()
        else:
            print("✅ No advisory findings.\n")
        
        print("✅ Deployment approved. Proceeding with pipeline...")
        print()
        
        sys.exit(0)
    
    else:
        # Should not reach here due to validation, but handle anyway
        print_banner("❌ UNKNOWN VERDICT", "red")
        print(f"Received unexpected verdict: {verdict}")
        print("\n⚠️  Failing closed: Deployment blocked due to unknown verdict.")
        sys.exit(1)


if __name__ == "__main__":
    main()


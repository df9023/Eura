"""Phase 0 contract validation tests.

Tests that execute_scan returns ScanResultV1 with correct structure and types.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
from app.services.scan_executor import execute_scan
from app.schemas.scan_result_v1 import ScanResultV1


@pytest.mark.asyncio
async def test_execute_scan_returns_scan_result_v1():
    """Test that execute_scan returns ScanResultV1 with required fields."""
    
    # Mock GitHub client and repo
    mock_repo = MagicMock()
    mock_repo.default_branch = "main"
    mock_repo.get_contents = MagicMock(return_value=[])
    mock_repo.get_branch = MagicMock(return_value=MagicMock(commit=MagicMock(sha="abc123")))
    
    mock_github_client = MagicMock()
    mock_github_client.get_repo = MagicMock(return_value=mock_repo)
    
    # Mock file listing to return empty (no files to scan)
    with patch("app.services.scan_executor.get_github_client", return_value=mock_github_client), \
         patch("app.services.scan_executor.list_repo_files", return_value=[]), \
         patch("app.services.scan_executor.evaluate_repo") as mock_evaluate, \
         patch("app.services.scan_executor.load_rules_db") as mock_load_rules, \
         patch("app.services.scan_executor.supabase", None):  # Disable DB operations
        
        # Mock rules DB
        mock_load_rules.return_value = {
            "rules": [
                {
                    "rule_id": "CRA-BASE-001",
                    "title": "Test Rule",
                    "description_short": "Test description",
                    "severity": {"overall": "medium"}
                }
            ]
        }
        
        # Mock compliance evaluation to return minimal valid response
        mock_evaluate.return_value = {
            "rule_results": [
                {
                    "rule_id": "CRA-BASE-001",
                    "status": "PASS",
                    "confidence": 0.9,
                    "reason": "Test rule passed",
                    "evaluated_at": "2024-12-21T12:00:00Z"
                }
            ],
            "evaluated_at": "2024-12-21T12:00:00Z",
            "total_rules": 1,
            "passed": 1,
            "failed": 0,
            "unknown": 0,
            "not_applicable": 0
        }
        
        # Execute scan
        result = await execute_scan(
            repo_name="test-owner/test-repo",
            installation_id=12345,
            project_id=None,  # Ephemeral scan
            repo_url="test-owner/test-repo",
            environment="dev"
        )
        
        # Assert result is ScanResultV1
        assert isinstance(result, ScanResultV1), "Result must be ScanResultV1 instance"
        
        # Assert required keys exist
        required_keys = [
            "verdict", "commit_sha", "environment", "evaluated_at",
            "rule_results", "evidence_refs"
        ]
        for key in required_keys:
            assert hasattr(result, key), f"Missing required field: {key}"
            assert getattr(result, key) is not None, f"Field {key} must not be None"
        
        # Assert verdict is valid
        assert result.verdict in ["SHIP_ALLOWED", "SHIP_BLOCKED"], \
            f"verdict must be SHIP_ALLOWED or SHIP_BLOCKED, got {result.verdict}"
        
        # Assert evaluated_at is timezone-aware
        assert result.evaluated_at.tzinfo is not None, \
            "evaluated_at must be timezone-aware"
        assert result.evaluated_at.tzinfo == timezone.utc, \
            "evaluated_at should be in UTC timezone"
        
        # Assert commit_sha is a string
        assert isinstance(result.commit_sha, str), \
            "commit_sha must be a string"
        
        # Assert environment is valid
        assert result.environment in ["dev", "staging", "production", "eu-production"], \
            f"environment must be one of valid values, got {result.environment}"
        
        # Assert rule_results is a list
        assert isinstance(result.rule_results, list), \
            "rule_results must be a list"
        
        # Assert rule_results items have required fields
        for rule_result in result.rule_results:
            assert hasattr(rule_result, "rule_id"), \
                "rule_result must have rule_id"
            assert hasattr(rule_result, "status"), \
                "rule_result must have status"
            assert rule_result.status in ["PASS", "FAIL", "NOT_APPLICABLE"], \
                f"rule_result.status must be PASS, FAIL, or NOT_APPLICABLE, got {rule_result.status}"
        
        # Assert evidence_refs has required fields
        assert hasattr(result.evidence_refs, "scan_id"), \
            "evidence_refs must have scan_id"
        assert isinstance(result.evidence_refs.scan_id, str), \
            "evidence_refs.scan_id must be a string"
        
        # Assert blocking_rules is a list
        assert isinstance(result.blocking_rules, list), \
            "blocking_rules must be a list"
        
        # Assert advisory_findings is a list
        assert isinstance(result.advisory_findings, list), \
            "advisory_findings must be a list"


@pytest.mark.asyncio
async def test_execute_scan_with_failed_rule_blocks_shipping():
    """Test that failed high-severity rules result in SHIP_BLOCKED verdict."""
    
    # Mock GitHub client and repo
    mock_repo = MagicMock()
    mock_repo.default_branch = "main"
    mock_repo.get_contents = MagicMock(return_value=[])
    mock_repo.get_branch = MagicMock(return_value=MagicMock(commit=MagicMock(sha="abc123")))
    
    mock_github_client = MagicMock()
    mock_github_client.get_repo = MagicMock(return_value=mock_repo)
    
    # Mock compliance evaluation with a failed high-severity rule
    with patch("app.services.scan_executor.get_github_client", return_value=mock_github_client), \
         patch("app.services.scan_executor.list_repo_files", return_value=[]), \
         patch("app.services.scan_executor.evaluate_repo") as mock_evaluate, \
         patch("app.services.scan_executor.load_rules_db") as mock_load_rules, \
         patch("app.services.scan_executor.supabase", None):
        
        # Mock rules DB with a high-severity rule
        mock_load_rules.return_value = {
            "rules": [
                {
                    "rule_id": "CRA-BASE-008",
                    "title": "No Hardcoded Secrets",
                    "description_short": "Secrets must not be hardcoded",
                    "severity": {
                        "overall": "high"
                    }
                }
            ]
        }
        
        # Mock compliance evaluation with a failed rule
        mock_evaluate.return_value = {
            "rule_results": [
                {
                    "rule_id": "CRA-BASE-008",
                    "status": "FAIL",
                    "confidence": 0.9,
                    "reason": "Hardcoded secrets detected",
                    "evaluated_at": "2024-12-21T12:00:00Z"
                }
            ],
            "evaluated_at": "2024-12-21T12:00:00Z",
            "total_rules": 1,
            "passed": 0,
            "failed": 1,
            "unknown": 0,
            "not_applicable": 0
        }
        
        # Execute scan
        result = await execute_scan(
            repo_name="test-owner/test-repo",
            installation_id=12345,
            project_id=None,
            repo_url="test-owner/test-repo",
            environment="dev"
        )
        
        # Assert verdict is SHIP_BLOCKED
        assert result.verdict == "SHIP_BLOCKED", \
            "Failed high-severity rule should result in SHIP_BLOCKED"
        
        # Assert blocking_rules contains the failed rule
        assert "CRA-BASE-008" in result.blocking_rules, \
            "blocking_rules should contain failed high-severity rule"
        
        # Assert rule_result has is_blocking=True
        blocking_rule = next(r for r in result.rule_results if r.rule_id == "CRA-BASE-008")
        assert blocking_rule.is_blocking is True, \
            "Failed high-severity rule should have is_blocking=True"


@pytest.mark.asyncio
async def test_execute_scan_evaluated_at_timezone():
    """Test that evaluated_at is properly timezone-aware and in UTC."""
    
    # Mock GitHub client and repo
    mock_repo = MagicMock()
    mock_repo.default_branch = "main"
    mock_repo.get_contents = MagicMock(return_value=[])
    mock_repo.get_branch = MagicMock(return_value=MagicMock(commit=MagicMock(sha="abc123")))
    
    mock_github_client = MagicMock()
    mock_github_client.get_repo = MagicMock(return_value=mock_repo)
    
    with patch("app.services.scan_executor.get_github_client", return_value=mock_github_client), \
         patch("app.services.scan_executor.list_repo_files", return_value=[]), \
         patch("app.services.scan_executor.evaluate_repo") as mock_evaluate, \
         patch("app.services.scan_executor.load_rules_db", return_value={"rules": []}), \
         patch("app.services.scan_executor.supabase", None):
        
        mock_evaluate.return_value = {
            "rule_results": [],
            "evaluated_at": "2024-12-21T12:00:00Z",
            "total_rules": 0,
            "passed": 0,
            "failed": 0,
            "unknown": 0,
            "not_applicable": 0
        }
        
        result = await execute_scan(
            repo_name="test-owner/test-repo",
            installation_id=12345,
            repo_url="test-owner/test-repo",
            environment="dev"
        )
        
        # Assert evaluated_at is timezone-aware datetime
        assert isinstance(result.evaluated_at, datetime), \
            "evaluated_at must be a datetime object"
        assert result.evaluated_at.tzinfo is not None, \
            "evaluated_at must be timezone-aware"
        assert result.evaluated_at.tzinfo == timezone.utc, \
            "evaluated_at must be in UTC timezone"


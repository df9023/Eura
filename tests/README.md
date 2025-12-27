# Tests

## Phase 0 Contract Tests

Tests validate that `execute_scan()` returns `ScanResultV1` with the correct structure and types.

## Running Tests

### Install dependencies:
```bash
pip install -r requirements.txt
```

### Run all tests:
```bash
pytest tests/ -v
```

### Run Phase 0 contract tests:
```bash
pytest tests/test_phase0_contract.py -v
```

### Run with coverage:
```bash
pytest tests/ --cov=app --cov-report=term-missing
```

## Test Structure

- `test_phase0_contract.py`: Validates Phase 0 API contract
  - Tests that required fields exist
  - Tests verdict values
  - Tests timezone-awareness of evaluated_at
  - Tests rule_results structure
  - Tests blocking rules logic

All tests use mocks to avoid network calls and database operations.


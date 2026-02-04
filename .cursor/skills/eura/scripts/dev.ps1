# EURA Development Helper Script
# Usage: .\scripts\dev.ps1 [command]

param(
    [Parameter(Position=0)]
    [ValidateSet("server", "test", "scan", "lint", "help")]
    [string]$Command = "help"
)

$ErrorActionPreference = "Stop"

function Start-Server {
    Write-Host "Starting EURA server..." -ForegroundColor Cyan
    uvicorn app.main:app --reload --port 8000
}

function Run-Tests {
    Write-Host "Running tests..." -ForegroundColor Cyan
    pytest tests/ -v
}

function Run-LocalScan {
    param([string]$Path = ".")
    Write-Host "Running local scan on: $Path" -ForegroundColor Cyan
    python -m cli.eura_cli scan $Path
}

function Run-Lint {
    Write-Host "Running linter..." -ForegroundColor Cyan
    if (Get-Command ruff -ErrorAction SilentlyContinue) {
        ruff check app/
    } else {
        Write-Host "ruff not installed. Install with: pip install ruff" -ForegroundColor Yellow
    }
}

function Show-Help {
    Write-Host @"
EURA Development Helper

Usage: .\scripts\dev.ps1 [command]

Commands:
  server    Start the FastAPI development server
  test      Run the test suite
  scan      Run a local compliance scan
  lint      Run the linter (ruff)
  help      Show this help message

Examples:
  .\scripts\dev.ps1 server
  .\scripts\dev.ps1 test
  .\scripts\dev.ps1 scan
"@ -ForegroundColor Green
}

switch ($Command) {
    "server" { Start-Server }
    "test" { Run-Tests }
    "scan" { Run-LocalScan }
    "lint" { Run-Lint }
    "help" { Show-Help }
    default { Show-Help }
}

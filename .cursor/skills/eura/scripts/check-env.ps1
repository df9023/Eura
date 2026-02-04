# Check EURA environment setup
# Usage: .\scripts\check-env.ps1

Write-Host "Checking EURA environment..." -ForegroundColor Cyan
Write-Host ""

$allGood = $true

# Check Python
Write-Host "Python:" -NoNewline
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host " $pythonVersion" -ForegroundColor Green
} else {
    Write-Host " NOT FOUND" -ForegroundColor Red
    $allGood = $false
}

# Check virtual environment
Write-Host "Virtual Env:" -NoNewline
if ($env:VIRTUAL_ENV) {
    Write-Host " Active ($env:VIRTUAL_ENV)" -ForegroundColor Green
} else {
    Write-Host " NOT ACTIVE (run: .\venv\Scripts\Activate.ps1)" -ForegroundColor Yellow
}

# Check .env file
Write-Host ".env file:" -NoNewline
if (Test-Path ".env") {
    Write-Host " Found" -ForegroundColor Green
} else {
    Write-Host " NOT FOUND (create from README.md template)" -ForegroundColor Red
    $allGood = $false
}

# Check required env vars
Write-Host ""
Write-Host "Environment Variables:" -ForegroundColor Cyan

$requiredVars = @(
    "GITHUB_APP_ID",
    "GITHUB_PRIVATE_KEY", 
    "OPENAI_API_KEY",
    "SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY"
)

foreach ($var in $requiredVars) {
    Write-Host "  $var :" -NoNewline
    $value = [Environment]::GetEnvironmentVariable($var)
    if ($value) {
        $masked = $value.Substring(0, [Math]::Min(8, $value.Length)) + "..."
        Write-Host " Set ($masked)" -ForegroundColor Green
    } else {
        Write-Host " NOT SET" -ForegroundColor Yellow
    }
}

Write-Host ""
if ($allGood) {
    Write-Host "Environment is ready!" -ForegroundColor Green
} else {
    Write-Host "Some issues found. See above." -ForegroundColor Yellow
}

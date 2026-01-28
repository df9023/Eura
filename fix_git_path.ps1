# Script to add Git to PowerShell PATH (for current session)
# To make it permanent, add Git to your system PATH environment variable

Write-Host "Adding Git to PATH for current PowerShell session..." -ForegroundColor Cyan

$gitPath = "C:\Program Files\Git\bin"
$gitCmdPath = "C:\Program Files\Git\cmd"

# Add to current session PATH
if ($env:PATH -notlike "*$gitPath*") {
    $env:PATH += ";$gitPath;$gitCmdPath"
    Write-Host "✓ Git added to PATH for this session" -ForegroundColor Green
} else {
    Write-Host "✓ Git already in PATH" -ForegroundColor Green
}

# Test Git
Write-Host ""
Write-Host "Testing Git..." -ForegroundColor Yellow
$gitVersion = git --version
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Git is working: $gitVersion" -ForegroundColor Green
} else {
    Write-Host "✗ Git test failed" -ForegroundColor Red
}

Write-Host ""
Write-Host "To make this permanent:" -ForegroundColor Cyan
Write-Host "1. Open System Properties > Environment Variables" -ForegroundColor White
Write-Host "2. Edit the 'Path' variable under 'User variables'" -ForegroundColor White
Write-Host "3. Add these two paths:" -ForegroundColor White
Write-Host "   - C:\Program Files\Git\bin" -ForegroundColor Gray
Write-Host "   - C:\Program Files\Git\cmd" -ForegroundColor Gray
Write-Host "4. Restart PowerShell" -ForegroundColor White
Write-Host ""
Write-Host "Or run this command in PowerShell (as Administrator) to add permanently:" -ForegroundColor Cyan
Write-Host '[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\Git\bin;C:\Program Files\Git\cmd", "User")' -ForegroundColor Gray

#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Quick JIRA Integration Test Script

.DESCRIPTION
    Tests JIRA integration by creating a sample security incident ticket.
    Validates credentials and connection before running GitHub Actions.

.EXAMPLE
    # Set credentials first:
    $env:JIRA_URL="https://secure-transaction.atlassian.net"
    $env:JIRA_USERNAME="darshsundar007@gmail.com"
    $env:JIRA_API_TOKEN="your-token-here"
    $env:JIRA_PROJECT_KEY="KAN"
    
    # Then run test:
    .\test-jira.ps1
#>

Write-Host ""
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "  JIRA Integration Test" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ ERROR: Python not found" -ForegroundColor Red
    exit 1
}

# Check environment variables
$required = @('JIRA_URL', 'JIRA_USERNAME', 'JIRA_API_TOKEN')
$missing = @()

foreach ($var in $required) {
    if ([string]::IsNullOrEmpty((Get-Item -Path "env:$var" -ErrorAction SilentlyContinue).Value)) {
        $missing += $var
    }
}

if ($missing.Count -gt 0) {
    Write-Host "✗ ERROR: Missing environment variables:" -ForegroundColor Red
    foreach ($var in $missing) {
        Write-Host "  - $var" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Set your JIRA credentials first:" -ForegroundColor Yellow
    Write-Host '  $env:JIRA_URL="https://secure-transaction.atlassian.net"'
    Write-Host '  $env:JIRA_USERNAME="darshsundar007@gmail.com"'
    Write-Host '  $env:JIRA_API_TOKEN="your-token-here"'
    Write-Host '  $env:JIRA_PROJECT_KEY="KAN"'
    Write-Host ""
    exit 1
}

# Set default project key
if ([string]::IsNullOrEmpty($env:JIRA_PROJECT_KEY)) {
    $env:JIRA_PROJECT_KEY = "KAN"
}

Write-Host "Testing JIRA connection..." -ForegroundColor Cyan
Write-Host "  URL:     $env:JIRA_URL"
Write-Host "  User:    $env:JIRA_USERNAME"
Write-Host "  Project: $env:JIRA_PROJECT_KEY"
Write-Host ""

# Check dependencies
Write-Host "Checking Python dependencies..." -ForegroundColor Cyan
python -c "import requests" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing requests library..." -ForegroundColor Yellow
    pip install requests | Out-Null
}

# Run test
Push-Location scripts\python
try {
    Write-Host ""
    Write-Host "Running test..." -ForegroundColor Cyan
    Write-Host ""
    
    python test_jira_integration.py
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "=======================================" -ForegroundColor Green
        Write-Host "  ✓ SUCCESS! JIRA integration works!" -ForegroundColor Green
        Write-Host "=======================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Cyan
        Write-Host "  1. Your GitHub secrets are already configured" -ForegroundColor White
        Write-Host "  2. Push code to trigger the workflow" -ForegroundColor White
        Write-Host "  3. Check Actions tab for ticket creation" -ForegroundColor White
    } else {
        Write-Host ""
        Write-Host "=======================================" -ForegroundColor Red
        Write-Host "  ✗ FAILED! Check your credentials" -ForegroundColor Red
        Write-Host "=======================================" -ForegroundColor Red
    }
} finally {
    Pop-Location
}

# ========================================
# QUICK DEMO SCRIPT FOR INTERNSHIP
# ========================================
# Run this script to demonstrate the complete secure transaction monitoring platform

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECURE TRANSACTION MONITORING DEMO" -ForegroundColor Cyan
Write-Host "100% OWASP Top 10 2021 Coverage" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Function to wait for user
function Wait-ForUser {
    Write-Host "`nPress any key to continue..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host ""
}

# Step 1: Show project structure
Write-Host "STEP 1: Project Overview" -ForegroundColor Green
Write-Host "Multi-module Maven project with:" -ForegroundColor White
Write-Host "  - E-Commerce Application (Spring Boot 3.5.0)" -ForegroundColor Gray
Write-Host "  - Security Test Suite (27 test files)" -ForegroundColor Gray
Write-Host "  - SIEM Integration (Elasticsearch/Splunk)" -ForegroundColor Gray
Write-Host "  - Multi-Channel Alerting (Slack/Email/PagerDuty)" -ForegroundColor Gray
Wait-ForUser

# Step 2: Build the project
Write-Host "STEP 2: Building Project" -ForegroundColor Green
mvn clean compile -DskipTests
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ BUILD SUCCESS" -ForegroundColor Green
} else {
    Write-Host "❌ BUILD FAILED" -ForegroundColor Red
    exit 1
}
Wait-ForUser

# Step 3: Run SIEM Integration Tests
Write-Host "STEP 3: Testing SIEM Integration" -ForegroundColor Green
Set-Location ecommerce-app
mvn test -Dtest=SiemIntegrationTest
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ ALL SIEM TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host "❌ SIEM TESTS FAILED" -ForegroundColor Red
}
Set-Location ..
Wait-ForUser

# Step 4: Start the application
Write-Host "STEP 4: Starting E-Commerce Application" -ForegroundColor Green
Write-Host "Starting Spring Boot on http://localhost:8080..." -ForegroundColor White
Set-Location ecommerce-app
Start-Process powershell -ArgumentList "-NoExit", "-Command", "mvn spring-boot:run" -WindowStyle Minimized
Write-Host "Waiting for application to start (30 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Test if app is running
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8080" -UseBasicParsing -TimeoutSec 5
    Write-Host "✅ Application is running on port 8080" -ForegroundColor Green
    Write-Host "   Status: $($response.StatusCode) $($response.StatusDescription)" -ForegroundColor Gray
} catch {
    Write-Host "⚠️ Application may still be starting..." -ForegroundColor Yellow
}
Set-Location ..
Wait-ForUser

# Step 5: Show available demos
Write-Host "STEP 5: Choose a Demo" -ForegroundColor Green
Write-Host "Select what you'd like to demonstrate:" -ForegroundColor White
Write-Host "  1. Run SQL Injection Test (OWASP A03)" -ForegroundColor Gray
Write-Host "  2. Run Brute Force Test (OWASP A07)" -ForegroundColor Gray
Write-Host "  3. Run SSRF Prevention Test (OWASP A10)" -ForegroundColor Gray
Write-Host "  4. Open Application in Browser" -ForegroundColor Gray
Write-Host "  5. Open H2 Database Console" -ForegroundColor Gray
Write-Host "  6. Run All Security Tests" -ForegroundColor Gray
Write-Host "  7. Exit Demo" -ForegroundColor Gray

$choice = Read-Host "`nEnter your choice (1-7)"

switch ($choice) {
    "1" {
        Write-Host "`nRunning SQL Injection Tests..." -ForegroundColor Cyan
        Set-Location security-tests
        mvn test -Dtest=SQLInjectionTest
        Set-Location ..
    }
    "2" {
        Write-Host "`nRunning Brute Force Tests..." -ForegroundColor Cyan
        Set-Location security-tests
        mvn test -Dtest=BruteForceTest
        Set-Location ..
    }
    "3" {
        Write-Host "`nRunning SSRF Prevention Tests..." -ForegroundColor Cyan
        Set-Location security-tests
        mvn test -Dtest=SSRFTest
        Set-Location ..
    }
    "4" {
        Write-Host "`nOpening application in browser..." -ForegroundColor Cyan
        Start-Process "http://localhost:8080"
    }
    "5" {
        Write-Host "`nOpening H2 Database Console..." -ForegroundColor Cyan
        Write-Host "JDBC URL: jdbc:h2:file:./ecommerce-app/data/security-events" -ForegroundColor Yellow
        Write-Host "Username: sa" -ForegroundColor Yellow
        Write-Host "Password: (leave empty)" -ForegroundColor Yellow
        Start-Process "http://localhost:8080/h2-console"
    }
    "6" {
        Write-Host "`nRunning ALL Security Tests (this will take a few minutes)..." -ForegroundColor Cyan
        Set-Location security-tests
        mvn test
        Set-Location ..
    }
    "7" {
        Write-Host "`nExiting demo..." -ForegroundColor Cyan
    }
}

Wait-ForUser

# Cleanup
Write-Host "`nCLEANUP: Stopping application..." -ForegroundColor Yellow
Get-Process -Name "java" -ErrorAction SilentlyContinue | Where-Object {$_.Path -like "*maven*"} | Stop-Process -Force
Write-Host "✅ Demo complete!" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "KEY FEATURES DEMONSTRATED:" -ForegroundColor Cyan
Write-Host "✅ Spring Boot 3.5.0 (latest)" -ForegroundColor White
Write-Host "✅ 100% OWASP Top 10 2021 Coverage" -ForegroundColor White
Write-Host "✅ Enterprise SIEM Integration" -ForegroundColor White
Write-Host "✅ Multi-Channel Alerting" -ForegroundColor White
Write-Host "✅ Automated Threat Correlation" -ForegroundColor White
Write-Host "✅ Real-time Security Event Logging" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan

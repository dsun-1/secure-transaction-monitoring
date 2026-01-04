
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
$startedApp = $false

function Wait-ForApp {
    param(
        [string]$Url = "http://localhost:8080",
        [int]$Attempts = 40,
        [int]$DelaySeconds = 2
    )

    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 | Out-Null
            Write-Host "App is up at $Url"
            return $true
        } catch {
            Start-Sleep -Seconds $DelaySeconds
        }
    }

    return $false
}

Write-Host "Starting demo from: $repoRoot"

$appProcess = $null
Set-Location $repoRoot

try {
    if (Wait-ForApp) {
        Write-Host "Step 1: App already running; skipping startup"
    } else {
        Write-Host "Step 1: Start the Spring Boot app"
        $appProcess = Start-Process -FilePath "mvn" `
            -ArgumentList "-DskipTests", "spring-boot:run" `
            -WorkingDirectory (Join-Path $repoRoot "ecommerce-app") `
            -PassThru -NoNewWindow
        $startedApp = $true

        if (-not (Wait-ForApp)) {
            throw "App did not start in time."
        }
    }

    Write-Host "Step 2: Run security tests (headless)"
    & mvn -pl security-tests test -Dheadless=true -Dbrowser=chrome -DbaseUrl=http://localhost:8080

    Write-Host "Step 3: Run SIEM analysis"
    Push-Location (Join-Path $repoRoot "scripts/python")
    try {
        & python security_analyzer_h2.py
    } finally {
        Pop-Location
    }

    Write-Host "Step 4: Generate JIRA tickets (optional)"
    Push-Location (Join-Path $repoRoot "scripts/python")
    try {
        & python jira_ticket_generator.py siem_incident_report.json
    } finally {
        Pop-Location
    }

    Write-Host "Demo completed."
} finally {
    if ($startedApp -and $appProcess -and -not $appProcess.HasExited) {
        Write-Host "Stopping app..."
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
